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

"""Cymbal Core Operations & Release MCP Server (/mcp StreamableHTTP).

Exposes read-only triage tools (`readOnlyHint=True`) and mutating/destructive
tools (`readOnlyHint=False`, `destructiveHint=True/False`) so Agent Gateway UAP
Policy V2 CEL rules enforce fine-grained per-tool access control beyond coarse
gateway-wide `mcp.use` scopes.
"""

from __future__ import annotations

import datetime
import json
import os
from typing import Any

from mcp.types import ToolAnnotations
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
import uvicorn

try:
    from mcp.server.mcpserver import MCPServer
    from mcp.server.transport_security import TransportSecuritySettings

    _MCP_V2 = True
except ImportError:  # pragma: no cover - fallback for mcp 1.x environments
    from mcp.server.fastmcp import FastMCP as MCPServer  # type: ignore[assignment]

    TransportSecuritySettings = None  # type: ignore[assignment]
    _MCP_V2 = False

mcp = MCPServer(
    "cymbal-ops-mcp-server",
)

INCIDENT_TELEMETRY_FIXTURES: dict[str, dict[str, Any]] = {
    "cymbal-release-api": {
        "incident_id": "INC-4092",
        "service_name": "cymbal-release-api",
        "component": "release-gateway-proxy",
        "baseline_p99_ms": 310,
        "current_p99_ms": 4820,
        "latency_samples_ms": [305, 318, 299, 312, 325, 4610, 4790, 4820, 4755, 4840],
        "error_rate_pct": 11.8,
        "valkey_stream": "usage:0",
        "valkey_memory_saturation_pct": 94.6,
        "celery_consumer_lag_messages": 184200,
        "active_release": "v2.14.3",
        "prior_healthy_release": "v2.14.2",
        "anomaly_started_minutes_ago": 18,
    },
    "billing-webhook-router": {
        "incident_id": "INC-4095",
        "service_name": "billing-webhook-router",
        "component": "checkout-settlement-dispatcher",
        "baseline_p99_ms": 240,
        "current_p99_ms": 5410,
        "latency_samples_ms": [235, 248, 239, 244, 251, 5120, 5340, 5410, 5385, 5450],
        "error_rate_pct": 14.2,
        "valkey_stream": "billing:retries",
        "valkey_memory_saturation_pct": 81.4,
        "celery_consumer_lag_messages": 62900,
        "active_release": "v3.8.1",
        "prior_healthy_release": "v3.8.0",
        "anomaly_started_minutes_ago": 24,
    },
    "edge-session-ingestor": {
        "incident_id": "INC-4099",
        "service_name": "edge-session-ingestor",
        "component": "telemetry-collector-edge",
        "baseline_p99_ms": 185,
        "current_p99_ms": 890,
        "latency_samples_ms": [180, 190, 184, 188, 192, 845, 870, 890, 865, 880],
        "error_rate_pct": 2.1,
        "valkey_stream": "edge:events",
        "valkey_memory_saturation_pct": 52.0,
        "celery_consumer_lag_messages": 4100,
        "active_release": "v1.9.4",
        "prior_healthy_release": "v1.9.3",
        "anomaly_started_minutes_ago": 12,
    },
}

CHANGE_CONTROL_FIXTURES: dict[str, dict[str, Any]] = {
    "cymbal-release-api": {
        "service_name": "cymbal-release-api",
        "recent_pr": "PR-8841: Increase streaming chunk buffer & synchronous Valkey usage:0 XADD flush",
        "deployed_version": "v2.14.3",
        "rollback_target_version": "v2.14.2",
        "release_ticket": "REL-4092",
        "change_freeze_active": False,
        "freeze_window_name": "None",
        "vp_exception_required": False,
    },
    "billing-webhook-router": {
        "service_name": "billing-webhook-router",
        "recent_pr": "PR-9104: Enable strict retry backoff multiplier on settlement webhook pool",
        "deployed_version": "v3.8.1",
        "rollback_target_version": "v3.8.0",
        "release_ticket": "REL-4095",
        "change_freeze_active": True,
        "freeze_window_name": "Cymbal Peak Holiday Billing Change Freeze",
        "vp_exception_required": True,
        "escalation_policy": "VP Core Operations Change-Freeze Override Required before any AG3 production rollback",
    },
    "edge-session-ingestor": {
        "service_name": "edge-session-ingestor",
        "recent_pr": "PR-7730: Minor log parser schema update (non-breaking)",
        "deployed_version": "v1.9.4",
        "rollback_target_version": "v1.9.3",
        "release_ticket": "REL-4099",
        "change_freeze_active": False,
        "freeze_window_name": "None",
        "vp_exception_required": False,
    },
}

CMDB_FIXTURES: dict[str, dict[str, Any]] = {
    "SVC-CYMBAL-992": {
        "app_id": "SVC-CYMBAL-992",
        "service_name": "cymbal-release-api",
        "owning_squad": "Cymbal Core Platform & Release SRE",
        "intake_id": "ATLAS-2026-0841",
        "risk_tier": "AG3",
        "upstream_dependencies": ["cymbal-idp-oidc", "valkey-usage-cluster"],
        "downstream_blast_radius": [
            "release-orchestrator",
            "canary-promotion-worker",
            "sre-triage-automation",
        ],
        "runbook_id": "RB-CYMBAL-204",
        "runbook_steps": [
            "1. Confirm p99 latency > 2,500ms and Valkey usage:0 saturation > 85%.",
            "2. Verify Cymbal release change-freeze calendar status in REL tracker.",
            "3. Obtain human SENTINEL AG3 approval before invoking Release Remediation A2A Agent.",
            "4. Execute canary rollback v2.14.3 -> v2.14.2 and trim consumer backlog.",
        ],
    },
    "SVC-CYMBAL-710": {
        "app_id": "SVC-CYMBAL-710",
        "service_name": "billing-webhook-router",
        "owning_squad": "Cymbal Commerce Settlement SRE",
        "intake_id": "ATLAS-2026-0915",
        "risk_tier": "AG3",
        "upstream_dependencies": ["payment-ledger-db", "valkey-billing-cluster"],
        "downstream_blast_radius": [
            "invoice-reconciliation-worker",
            "customer-receipt-notifier",
        ],
        "runbook_id": "RB-BILL-118",
        "runbook_steps": [
            "1. Inspect checkout-settlement-dispatcher p99 timeouts.",
            "2. CRITICAL: Check Cymbal Peak Change Freeze status; NEVER auto-rollback without VP Change-Freeze Exception.",
            "3. Route to SENTINEL AG3 human approval gate with freeze warning attached.",
        ],
    },
    "SVC-CYMBAL-305": {
        "app_id": "SVC-CYMBAL-305",
        "service_name": "edge-session-ingestor",
        "owning_squad": "Cymbal Observability Edge Ingestion Team",
        "intake_id": "ATLAS-2026-0512",
        "risk_tier": "AG1",
        "upstream_dependencies": ["regional-load-balancer"],
        "downstream_blast_radius": ["non-critical-session-archive"],
        "runbook_id": "RB-EDGE-042",
        "runbook_steps": [
            "1. Low-risk AG1 informational alert; scrub any pasted PII via Cloud SDP.",
            "2. Publish advisory triage summary without production rollback.",
        ],
    },
}

TICKET_ANNOTATIONS: list[dict[str, str]] = []


@mcp.tool(
    name="query_golden_signal_metrics",
    title="Query Service Golden-Signal Telemetry",
    description="Read-only query of golden-signal p99 latency, error rate, and stream saturation metrics.",
    annotations=ToolAnnotations(
        title="Query Golden Signal Metrics",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
def query_golden_signal_metrics(service_name: str, window_minutes: int = 30) -> str:
    """Returns realistic golden-signal telemetry for the requested Cymbal service."""
    if window_minutes == -503:
        raise RuntimeError("HTTP 503 Service Unavailable: Metrics telemetry backend timeout")
    key = service_name.strip().lower()
    payload = dict(
        INCIDENT_TELEMETRY_FIXTURES.get(key, INCIDENT_TELEMETRY_FIXTURES["cymbal-release-api"])
    )
    payload["window_minutes"] = window_minutes
    payload["queried_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return json.dumps(payload)


@mcp.tool(
    name="check_release_and_change_freeze",
    title="Check Release History & Enterprise Change Freeze",
    description="Read-only lookup of recent production deployments, PRs, and active change-freeze windows.",
    annotations=ToolAnnotations(
        title="Check Release and Change Freeze",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
def check_release_and_change_freeze(service_name: str) -> str:
    """Returns deployment history and active change-freeze status for a service."""
    key = service_name.strip().lower()
    payload = dict(
        CHANGE_CONTROL_FIXTURES.get(key, CHANGE_CONTROL_FIXTURES["cymbal-release-api"])
    )
    payload["checked_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return json.dumps(payload)


@mcp.tool(
    name="lookup_service_topology_and_runbook",
    title="Lookup ServiceAtlas CMDB, Blast Radius & OpsWiki Runbook",
    description="Read-only lookup of service ownership, dependency blast radius, SENTINEL risk tier, and runbook.",
    annotations=ToolAnnotations(
        title="Lookup ServiceAtlas CMDB and Runbook",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
def lookup_service_topology_and_runbook(app_id: str) -> str:
    """Returns CMDB ownership, blast radius, and standard remediation steps."""
    normalized = app_id.strip().upper()
    if normalized in CMDB_FIXTURES:
        payload = dict(CMDB_FIXTURES[normalized])
    elif "BILL" in normalized or "710" in normalized or "4095" in normalized:
        payload = dict(CMDB_FIXTURES["SVC-CYMBAL-710"])
    elif "EDGE" in normalized or "305" in normalized or "4099" in normalized:
        payload = dict(CMDB_FIXTURES["SVC-CYMBAL-305"])
    else:
        payload = dict(CMDB_FIXTURES["SVC-CYMBAL-992"])
    return json.dumps(payload)


@mcp.tool(
    name="annotate_incident_ticket",
    title="Append Structured Triage Evidence to Incident Ticket",
    description="Non-destructive mutating tool that appends correlated triage findings to an incident ticket.",
    annotations=ToolAnnotations(
        title="Annotate Incident Ticket",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=False,
    ),
)
def annotate_incident_ticket(incident_id: str, note: str) -> str:
    """Appends structured triage evidence to an active incident ticket."""
    entry = {
        "incident_id": incident_id.strip(),
        "note": note.strip()[:2000],
        "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "RECORDED",
    }
    TICKET_ANNOTATIONS.append(entry)
    return json.dumps(entry)


@mcp.tool(
    name="purge_production_valkey_stream",
    title="Purge Production Valkey Stream (Destructive)",
    description="Destructive administrative operation that drops all unconsumed Valkey stream messages.",
    annotations=ToolAnnotations(
        title="Purge Production Valkey Stream",
        readOnlyHint=False,
        destructiveHint=True,
        idempotentHint=False,
        openWorldHint=False,
    ),
)
def purge_production_valkey_stream(stream_key: str) -> str:
    """Destructive tool blocked at Agent Gateway / UAP Policy V2 CEL."""
    return json.dumps(
        {
            "stream_key": stream_key,
            "status": "PURGED_IF_UNGOVERNED",
        }
    )


TOOL_SPEC_MANIFEST: dict[str, Any] = {
    "serverName": "cymbal-ops-mcp-server",
    "protocol": "MCP-StreamableHTTP",
    "tools": [
        {
            "name": "query_golden_signal_metrics",
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "check_release_and_change_freeze",
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "lookup_service_topology_and_runbook",
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "annotate_incident_ticket",
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False},
        },
        {
            "name": "purge_production_valkey_stream",
            "annotations": {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False},
        },
    ],
}


async def healthz(_request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "cymbal-ops-mcp-server"})


async def tools_metadata(_request: Request) -> JSONResponse:
    return JSONResponse(TOOL_SPEC_MANIFEST)


def build_asgi_app() -> Starlette:
    if _MCP_V2 and TransportSecuritySettings is not None:
        mcp_subapp = mcp.streamable_http_app(
            streamable_http_path="/mcp",
            stateless_http=True,
            transport_security=TransportSecuritySettings(
                enable_dns_rebinding_protection=False
            ),
        )
    else:  # pragma: no cover
        mcp_subapp = mcp.streamable_http_app()

    return Starlette(
        routes=[
            Route("/healthz", endpoint=healthz, methods=["GET"]),
            Route("/tools-metadata", endpoint=tools_metadata, methods=["GET"]),
            Mount("/", app=mcp_subapp),
        ],
        lifespan=getattr(mcp_subapp.router, "lifespan_context", None),
    )


app = build_asgi_app()


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8081"))
    bind_host = os.getenv("BIND_HOST", "127.0.0.1")
    uvicorn.run(app, host=bind_host, port=port)
