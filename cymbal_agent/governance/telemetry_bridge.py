# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unified W3C Traceparent plane & standard OpenTelemetry OTLP dual-exporter.

Joins Gateway policy decisions, Dynamic Model Armor sanitization spans, ADK 2.0
graph nodes, MCP/A2A downstream hops, and nano-USD Wallet settlements into a single
W3C `trace_id` + `session_id` trace waterfall, writing directly to Google Cloud
Trace (`cloudtrace.googleapis.com`) and emitting OpenTelemetry `resourceSpans`
(`gen_ai.*` / Langfuse-compatible session & CMDB attributes) in `enterprise_hybrid`
mode.
"""

from __future__ import annotations

from collections import deque
import datetime
import os
import threading
import time
from typing import Any
import uuid

from google.cloud import trace_v2
from google.protobuf import wrappers_pb2
import httpx

from cymbal_agent.governance.gcp_auth import get_gcp_credentials


def _truncatable(text: str, limit: int = 256) -> trace_v2.TruncatableString:
    encoded = str(text)[:limit].encode("utf-8")
    return trace_v2.TruncatableString(value=encoded.decode("utf-8", errors="ignore"))


def build_otlp_resource_span_envelope(
    *,
    trace_id: str,
    span_id: str,
    session_id: str,
    span_name: str,
    stage: str,
    start_epoch: float,
    end_epoch: float,
    cmdb_app_id: str,
    architecture_mode: str,
    attributes: dict[str, str],
) -> dict[str, Any]:
    """Constructs an OpenTelemetry v1 `resourceSpans` payload compatible with OTLP/Langfuse."""
    start_ns = str(int(start_epoch * 1_000_000_000))
    end_ns = str(int(end_epoch * 1_000_000_000))
    otel_attrs = [
        {"key": "gen_ai.system", "value": {"stringValue": attributes.get("gen_ai.system", "gcp.vertex.agent")}},
        {"key": "session.id", "value": {"stringValue": session_id}},
        {"key": "langfuse.session.id", "value": {"stringValue": session_id}},
        {"key": "enterprise.cmdb.app_id", "value": {"stringValue": cmdb_app_id}},
        {"key": "enterprise.architecture_mode", "value": {"stringValue": architecture_mode}},
        {"key": "enterprise.governance.stage", "value": {"stringValue": stage}},
    ]
    for k, v in list(attributes.items())[:20]:
        if k not in {"gen_ai.system"}:
            otel_attrs.append({"key": k, "value": {"stringValue": str(v)}})

    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "cymbal-governance-workbench"}},
                        {"key": "enterprise.app_id", "value": {"stringValue": cmdb_app_id}},
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "cymbal.adk.otel.exporter", "version": "2.0.0"},
                        "spans": [
                            {
                                "traceId": trace_id,
                                "spanId": span_id,
                                "name": span_name,
                                "kind": 1,
                                "startTimeUnixNano": start_ns,
                                "endTimeUnixNano": end_ns,
                                "attributes": otel_attrs,
                            }
                        ],
                    }
                ],
            }
        ]
    }


class UnifiedTraceBridge:
    """Records unified `gen_ai.*` and governance spans across Cloud Trace & OTLP collectors."""

    def __init__(
        self,
        project_id: str | None = None,
        cloud_trace_enabled: bool | None = None,
        otlp_endpoint: str | None = None,
    ) -> None:
        self.project_id = (
            project_id or os.getenv("GOOGLE_CLOUD_PROJECT") or "cymbal-agent-platform"
        )
        if cloud_trace_enabled is None:
            flag = (
                os.getenv("CYMBAL_CLOUD_TRACE_LIVE")
                or os.getenv("SCAPE_CLOUD_TRACE_LIVE")
                or "true"
            )
            self.cloud_trace_enabled = flag.lower() in {"1", "true", "yes"}
        else:
            self.cloud_trace_enabled = cloud_trace_enabled
        self.otlp_endpoint = (
            otlp_endpoint if otlp_endpoint is not None else os.getenv("HYBRID_OTLP_ENDPOINT", "").strip()
        )
        self._lock = threading.Lock()
        self._traces: deque[dict[str, Any]] = deque(maxlen=100)
        self._otlp_envelopes: deque[dict[str, Any]] = deque(maxlen=50)
        self._trace_index: dict[str, dict[str, Any]] = {}
        self._client: trace_v2.TraceServiceClient | None = None

    def __getstate__(self) -> dict[str, Any]:
        state = dict(self.__dict__)
        state["_lock"] = None
        state["_client"] = None
        return state

    def __setstate__(self, state: dict[str, Any]) -> None:
        self.__dict__.update(state)
        self._lock = threading.Lock()
        self._client = None

    def _get_trace_client(self) -> trace_v2.TraceServiceClient:
        if self._client is None:
            creds, _ = get_gcp_credentials(self.project_id)
            self._client = trace_v2.TraceServiceClient(credentials=creds)
        return self._client

    def new_trace_id(self) -> str:
        return uuid.uuid4().hex

    def record_span(
        self,
        *,
        trace_id: str,
        session_id: str,
        span_name: str,
        stage: str,
        duration_ms: float,
        attributes: dict[str, Any] | None = None,
        architecture_mode: str = "enterprise_hybrid",
        cmdb_app_id: str = "SVC-CYMBAL-992",
    ) -> dict[str, Any]:
        span_id = uuid.uuid4().hex[:16]
        end_epoch = time.time()
        start_epoch = max(0.0, end_epoch - (max(duration_ms, 0.5) / 1000.0))
        attrs = dict(attributes or {})
        attrs.setdefault("gen_ai.system", "gcp.vertex.agent")
        attrs.setdefault("cymbal.session_id", session_id)
        attrs.setdefault("cymbal.architecture_mode", architecture_mode)
        attrs.setdefault("cymbal.cmdb_app_id", cmdb_app_id)
        if architecture_mode == "enterprise_hybrid":
            attrs["http.header.X-Trace-Session-Id"] = session_id
            attrs["http.header.X-Service-App-Id"] = cmdb_app_id
            attrs["otel.exporter.target"] = "langfuse_and_cop_otlp"

        str_attrs = {k: str(v) for k, v in attrs.items()}
        otlp_envelope = build_otlp_resource_span_envelope(
            trace_id=trace_id,
            span_id=span_id,
            session_id=session_id,
            span_name=span_name,
            stage=stage,
            start_epoch=start_epoch,
            end_epoch=end_epoch,
            cmdb_app_id=cmdb_app_id,
            architecture_mode=architecture_mode,
            attributes=str_attrs,
        )

        span_entry = {
            "trace_id": trace_id,
            "span_id": span_id,
            "w3c_traceparent": f"00-{trace_id}-{span_id}-01",
            "session_id": session_id,
            "span_name": span_name,
            "stage": stage,
            "duration_ms": round(duration_ms, 2),
            "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "attributes": str_attrs,
            "otlp_dual_exported": architecture_mode == "enterprise_hybrid",
        }

        with self._lock:
            trace_bundle = self._trace_index.get(trace_id)
            if trace_bundle is None:
                trace_bundle = {
                    "trace_id": trace_id,
                    "session_id": session_id,
                    "architecture_mode": architecture_mode,
                    "cmdb_app_id": cmdb_app_id,
                    "otlp_dual_export": architecture_mode == "enterprise_hybrid",
                    "created_at": span_entry["recorded_at"],
                    "spans": [],
                }
                self._trace_index[trace_id] = trace_bundle
                self._traces.appendleft(trace_bundle)
            trace_bundle["spans"].append(span_entry)
            if architecture_mode == "enterprise_hybrid":
                self._otlp_envelopes.appendleft(otlp_envelope)

        if (
            architecture_mode == "enterprise_hybrid"
            and self.otlp_endpoint
            and ".example" not in self.otlp_endpoint
        ):
            self._export_to_otlp_collector(
                otlp_envelope=otlp_envelope,
                session_id=session_id,
                cmdb_app_id=cmdb_app_id,
            )

        if self.cloud_trace_enabled:
            self._export_to_cloud_trace(
                trace_id=trace_id,
                span_id=span_id,
                display_name=span_name,
                start_epoch=start_epoch,
                end_epoch=end_epoch,
                attributes=str_attrs,
            )
        return span_entry

    def _export_to_otlp_collector(
        self,
        *,
        otlp_envelope: dict[str, Any],
        session_id: str,
        cmdb_app_id: str,
    ) -> None:
        try:
            httpx.post(
                self.otlp_endpoint,
                json=otlp_envelope,
                headers={
                    "Content-Type": "application/json",
                    "X-Trace-Session-Id": session_id,
                    "X-Service-App-Id": cmdb_app_id,
                },
                timeout=2.5,
            )
        except Exception:
            pass

    def _export_to_cloud_trace(
        self,
        *,
        trace_id: str,
        span_id: str,
        display_name: str,
        start_epoch: float,
        end_epoch: float,
        attributes: dict[str, str],
    ) -> None:
        try:
            start_dt = datetime.datetime.fromtimestamp(
                start_epoch, tz=datetime.timezone.utc
            )
            end_dt = datetime.datetime.fromtimestamp(
                end_epoch, tz=datetime.timezone.utc
            )

            attr_map = {
                k: trace_v2.AttributeValue(string_value=_truncatable(v, 256))
                for k, v in list(attributes.items())[:30]
            }

            span_pb = trace_v2.Span(
                name=f"projects/{self.project_id}/traces/{trace_id}/spans/{span_id}",
                span_id=span_id,
                display_name=_truncatable(display_name, 128),
                start_time=start_dt,
                end_time=end_dt,
                attributes=trace_v2.Span.Attributes(attribute_map=attr_map),
                same_process_as_parent_span=wrappers_pb2.BoolValue(value=True),
            )
            self._get_trace_client().batch_write_spans(
                request={
                    "name": f"projects/{self.project_id}",
                    "spans": [span_pb],
                },
                timeout=5.0,
            )
        except Exception:
            pass

    def get_trace(self, trace_id: str) -> dict[str, Any] | None:
        with self._lock:
            bundle = self._trace_index.get(trace_id)
            return dict(bundle) if bundle else None

    def list_recent_traces(self, limit: int = 15) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in list(self._traces)[:limit]]

    def list_recent_otlp_exports(self, limit: int = 10) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in list(self._otlp_envelopes)[:limit]]
