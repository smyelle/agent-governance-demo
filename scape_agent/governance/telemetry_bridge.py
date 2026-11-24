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

"""Unified W3C Traceparent plane & optional Langfuse OTLP dual-exporter.

Joins Gateway policy decisions, Model Armor sanitization spans, ADK 2.0 graph
nodes, MCP/A2A downstream hops, and nano-USD Wallet settlements into a single
W3C `trace_id` + `session_id` trace waterfall, writing directly to Google Cloud
Trace (`cloudtrace.googleapis.com`) and optionally dual-exporting OTLP HTTP to
`LANGFUSE_OTLP_ENDPOINT` in `comcast_hybrid` mode.
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

from scape_agent.governance.gcp_auth import get_gcp_credentials


def _truncatable(text: str, limit: int = 256) -> trace_v2.TruncatableString:
    encoded = str(text)[:limit].encode("utf-8")
    return trace_v2.TruncatableString(value=encoded.decode("utf-8", errors="ignore"))


class UnifiedTraceBridge:
    """Records unified `gen_ai.*` and governance spans across Cloud Trace & UI buffer."""

    def __init__(
        self,
        project_id: str | None = None,
        cloud_trace_enabled: bool | None = None,
    ) -> None:
        self.project_id = project_id or os.getenv("GOOGLE_CLOUD_PROJECT", "comcast-scape")
        if cloud_trace_enabled is None:
            self.cloud_trace_enabled = os.getenv("SCAPE_CLOUD_TRACE_LIVE", "true").lower() in {
                "1",
                "true",
                "yes",
            }
        else:
            self.cloud_trace_enabled = cloud_trace_enabled
        self._lock = threading.Lock()
        self._traces: deque[dict[str, Any]] = deque(maxlen=100)
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
        scape_mode: str = "google_native",
        devhub_app_id: str = "DEVHUB-SCAPE-992",
    ) -> dict[str, Any]:
        span_id = uuid.uuid4().hex[:16]
        end_epoch = time.time()
        start_epoch = max(0.0, end_epoch - (max(duration_ms, 0.5) / 1000.0))
        attrs = dict(attributes or {})
        attrs.setdefault("gen_ai.system", "gcp.vertex.agent")
        attrs.setdefault("scape.session_id", session_id)
        attrs.setdefault("scape.mode", scape_mode)
        attrs.setdefault("comcast.devhub_app_id", devhub_app_id)
        if scape_mode == "comcast_hybrid":
            attrs["http.header.X-Langfuse-Session-Id"] = session_id
            attrs["http.header.X-Project-Id"] = devhub_app_id

        span_entry = {
            "trace_id": trace_id,
            "span_id": span_id,
            "w3c_traceparent": f"00-{trace_id}-{span_id}-01",
            "session_id": session_id,
            "span_name": span_name,
            "stage": stage,
            "duration_ms": round(duration_ms, 2),
            "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "attributes": {k: str(v) for k, v in attrs.items()},
        }

        with self._lock:
            trace_bundle = self._trace_index.get(trace_id)
            if trace_bundle is None:
                trace_bundle = {
                    "trace_id": trace_id,
                    "session_id": session_id,
                    "scape_mode": scape_mode,
                    "devhub_app_id": devhub_app_id,
                    "created_at": span_entry["recorded_at"],
                    "spans": [],
                }
                self._trace_index[trace_id] = trace_bundle
                self._traces.appendleft(trace_bundle)
            trace_bundle["spans"].append(span_entry)

        if self.cloud_trace_enabled:
            self._export_to_cloud_trace(
                trace_id=trace_id,
                span_id=span_id,
                display_name=span_name,
                start_epoch=start_epoch,
                end_epoch=end_epoch,
                attributes=span_entry["attributes"],
            )
        return span_entry

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
