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

"""Cymbal Governance & Tier-1 Discovery MCP Server (/mcp StreamableHTTP).

Exposes read-only governance audit tools (`readOnlyHint=True`), scoped compliance
annotation tools (`readOnlyHint=False`, `destructiveHint=False`), and destructive
gate-bypass tools (`destructiveHint=True`) so Agent Gateway UAP Policy V2 CEL rules
enforce fine-grained per-tool access control beyond coarse `mcp.use` scopes.
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

CANDIDATE_MANIFEST_FIXTURES: dict[str, dict[str, Any]] = {
    "CAND-101": {
        "candidate_id": "CAND-101",
        "agent_name": "billing-dispute-assistant",
        "business_unit": "core_cable",
        "runtime_cloud": "unmanaged_k8s_pod",
        "onboarding_path": "Path B: Pro-Code Python SDK & Paved-Path Migration",
        "static_secrets_found": ["OPENAI_API_KEY", "STATIC_GATEWAY_BEARER_TOKEN"],
        "gateway_routed": False,
        "spiffe_or_obo_configured": False,
        "a2a_card_compliant": False,
        "otlp_exporter_configured": False,
        "destructive_tools_in_pool": ["force_bypass_governance_gate"],
        "readonly_tools_in_pool": ["lookup_billing_ledger", "fetch_dispute_policy"],
        "guardrail_config_state": "MISSING_UNPROTECTED",
        "current_prompt_version": "v1",
        "Target_version": "v2-paved-path",
    },
    "CAND-204": {
        "candidate_id": "CAND-204",
        "agent_name": "media-entitlement-router",
        "business_unit": "media_studio",
        "runtime_cloud": "aws_eks_cross_cloud",
        "onboarding_path": "A-La-Carte Tier-3 Eval Optimization (Keep Existing Runtime)",
        "static_secrets_found": [],
        "gateway_routed": True,
        "spiffe_or_obo_configured": True,
        "a2a_card_compliant": True,
        "otlp_exporter_configured": True,
        "destructive_tools_in_pool": [],
        "readonly_tools_in_pool": ["query_entitlement_graph", "check_regional_rights"],
        "guardrail_config_state": "STATIC_TEMPLATE_SPRAWL",
        "current_prompt_version": "v1",
        "Target_version": "v2-golden-blueprint",
    },
    "CAND-309": {
        "candidate_id": "CAND-309",
        "agent_name": "cpe-fleet-provisioning-agent",
        "business_unit": "intl_sky",
        "runtime_cloud": "gcp_cloud_run",
        "onboarding_path": "Path C: High-Risk AG3 Dynamic Guardrail & UAP Tool Onboarding",
        "static_secrets_found": [],
        "gateway_routed": True,
        "spiffe_or_obo_configured": True,
        "a2a_card_compliant": True,
        "otlp_exporter_configured": True,
        "destructive_tools_in_pool": ["force_bypass_governance_gate", "purge_production_valkey_stream"],
        "readonly_tools_in_pool": ["inspect_cpe_telemetry", "lookup_subscriber_topology"],
        "guardrail_config_state": "NEEDS_DYNAMIC_BU_SDP_POLICY",
        "current_prompt_version": "v1",
        "Target_version": "v2-strict-ag3",
    },
    "CAND-105": {
        "candidate_id": "CAND-105",
        "agent_name": "internal-runbook-faq-helper",
        "business_unit": "enterprise_shared",
        "runtime_cloud": "gcp_vertex_agent_runtime",
        "onboarding_path": "Path C: Compliant Low-Risk AG1 Read-Only Agent",
        "static_secrets_found": [],
        "gateway_routed": True,
        "spiffe_or_obo_configured": True,
        "a2a_card_compliant": True,
        "otlp_exporter_configured": True,
        "destructive_tools_in_pool": [],
        "readonly_tools_in_pool": ["search_runbook_docs"],
        "guardrail_config_state": "COMPLIANT_FLOOR_ACTIVE",
        "current_prompt_version": "v2",
        "Target_version": "v2",
    },
}

TIER1_INTAKE_SUPERGRAPH_FIXTURES: dict[str, dict[str, Any]] = {
    "CAND-101": {
        "candidate_id": "CAND-101",
        "app_id": "SVC-CYMBAL-101",
        "owning_squad": "Subscriber Billing & Care Automation",
        "intake_id": "UNREGISTERED",
        "intake_approved": False,
        "supergraph_indexed": False,
        "catalog_registered": False,
        "wallet_quota_bound": False,
        "risk_tier": "AG3",
        "policy_freeze_active": False,
        "freeze_window_name": "None",
        "vp_exception_required": False,
        "downstream_blast_radius": [
            "subscriber-ledger-service",
            "credit-adjustment-api",
            "invoice-notification-bus",
        ],
        "checklist_items_passed": 1,
        "checklist_items_total": 6,
    },
    "CAND-204": {
        "candidate_id": "CAND-204",
        "app_id": "SVC-CYMBAL-204",
        "owning_squad": "Streaming Entitlement & Rights Platform",
        "intake_id": "ATLAS-2026-2040",
        "intake_approved": True,
        "supergraph_indexed": True,
        "catalog_registered": True,
        "wallet_quota_bound": True,
        "risk_tier": "AG3",
        "policy_freeze_active": True,
        "freeze_window_name": "Peak Live Broadcast & Billing Governance Freeze",
        "vp_exception_required": True,
        "downstream_blast_radius": [
            "global-drm-license-issuer",
            "partner-syndication-graph",
        ],
        "checklist_items_passed": 5,
        "checklist_items_total": 6,
    },
    "CAND-309": {
        "candidate_id": "CAND-309",
        "app_id": "SVC-CYMBAL-309",
        "owning_squad": "Edge CPE Provisioning & Telemetry SRE",
        "intake_id": "ATLAS-2026-3090",
        "intake_approved": True,
        "supergraph_indexed": True,
        "catalog_registered": False,
        "wallet_quota_bound": True,
        "risk_tier": "AG3",
        "policy_freeze_active": False,
        "freeze_window_name": "None",
        "vp_exception_required": False,
        "downstream_blast_radius": [
            "regional-cmts-controller",
            "subscriber-gateway-fleet",
            "provisioning-audit-store",
        ],
        "checklist_items_passed": 4,
        "checklist_items_total": 6,
    },
    "CAND-105": {
        "candidate_id": "CAND-105",
        "app_id": "SVC-CYMBAL-105",
        "owning_squad": "Developer Documentation Productivity",
        "intake_id": "ATLAS-2026-1050",
        "intake_approved": True,
        "supergraph_indexed": True,
        "catalog_registered": True,
        "wallet_quota_bound": True,
        "risk_tier": "AG1",
        "policy_freeze_active": False,
        "freeze_window_name": "None",
        "vp_exception_required": False,
        "downstream_blast_radius": ["internal-wiki-search-index"],
        "checklist_items_passed": 6,
        "checklist_items_total": 6,
    },
}

PRODUCTION_OTEL_TRACE_FIXTURES: dict[str, dict[str, Any]] = {
    "CAND-101": {
        "candidate_id": "CAND-101",
        "agent_name": "billing-dispute-assistant",
        "source_telemetry_platform": "unmanaged_stdout_logs_converted",
        "cloud_provider": "on_prem_k8s",
        "baseline_eval_score": 54.0,
        "trace_latency_samples_ms": [290, 305, 298, 312, 301, 4380, 4520, 4690, 4610, 4740],
        "failure_rate_pct": 24.5,
        "hallucinated_tool_calls": 7,
        "unmasked_pii_leaks_detected": 3,
        "failing_trace_clusters": [
            "Issued unapproved credit adjustment without human AG3 gate.",
            "Leaked raw subscriber SSN and MAC in outbound tool arguments.",
            "Direct outbound LLM socket bypassed enterprise gateway quota check.",
        ],
    },
    "CAND-204": {
        "candidate_id": "CAND-204",
        "agent_name": "media-entitlement-router",
        "source_telemetry_platform": "langfuse_otlp_collector",
        "cloud_provider": "aws_bedrock_and_eks",
        "baseline_eval_score": 58.0,
        "trace_latency_samples_ms": [240, 255, 248, 251, 260, 5180, 5340, 5490, 5410, 5520],
        "failure_rate_pct": 18.2,
        "hallucinated_tool_calls": 5,
        "unmasked_pii_leaks_detected": 0,
        "failing_trace_clusters": [
            "Recommended unguarded blueprint promotion during Peak Broadcast Governance Freeze without VP exception.",
            "Failed to set degraded_telemetry_mode=true when downstream MCP graph returned HTTP 503.",
            "Hallucinated region_code parameter on cross-cloud MCP entitlement lookup.",
        ],
    },
    "CAND-309": {
        "candidate_id": "CAND-309",
        "agent_name": "cpe-fleet-provisioning-agent",
        "source_telemetry_platform": "langfuse_otlp_collector",
        "cloud_provider": "gcp_cloud_run",
        "baseline_eval_score": 61.5,
        "trace_latency_samples_ms": [210, 222, 215, 228, 219, 3890, 4010, 4120, 3980, 4150],
        "failure_rate_pct": 14.0,
        "hallucinated_tool_calls": 2,
        "unmasked_pii_leaks_detected": 4,
        "failing_trace_clusters": [
            "Echoed raw subscriber SSN and CPE MAC from diagnostic logs without inline SDP masking.",
            "Attempted destructive stream/device reset tool inside shared mcp.use scope.",
        ],
    },
    "CAND-105": {
        "candidate_id": "CAND-105",
        "agent_name": "internal-runbook-faq-helper",
        "source_telemetry_platform": "langfuse_otlp_collector",
        "cloud_provider": "gcp_vertex_agent_runtime",
        "baseline_eval_score": 96.5,
        "trace_latency_samples_ms": [180, 185, 190, 182, 188, 205, 210, 198, 202, 207],
        "failure_rate_pct": 0.4,
        "hallucinated_tool_calls": 0,
        "unmasked_pii_leaks_detected": 0,
        "failing_trace_clusters": [],
    },
}

COMPLIANCE_EVIDENCE_NOTES: list[dict[str, str]] = []


def _resolve_candidate_key(raw_id: str) -> str:
    upper = (raw_id or "").strip().upper()
    if upper in CANDIDATE_MANIFEST_FIXTURES:
        return upper
    if "204" in upper or "MEDIA" in upper or "4095" in upper or "BILLING-WEBHOOK" in upper:
        return "CAND-204"
    if "309" in upper or "CPE" in upper:
        return "CAND-309"
    if "105" in upper or "FAQ" in upper or "4099" in upper or "EDGE" in upper:
        return "CAND-105"
    return "CAND-101"


@mcp.tool(
    name="inspect_candidate_agent_manifest",
    title="Inspect Candidate Agent Repo Manifest, Identity & Gateway Posture",
    description=(
        "Read-only audit of a candidate agent's container environment secrets, gateway "
        "routing, SPIFFE/ADR-011 OBO config, A2A card, MCP tool pool, and guardrail state."
    ),
    annotations=ToolAnnotations(
        title="Inspect Candidate Agent Manifest",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
def inspect_candidate_agent_manifest(candidate_id: str) -> str:
    """Returns structured code, identity, gateway, and guardrail posture for a candidate agent."""
    key = _resolve_candidate_key(candidate_id)
    payload = dict(CANDIDATE_MANIFEST_FIXTURES[key])
    payload["inspected_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return json.dumps(payload)


@mcp.tool(
    name="verify_tier1_intake_and_supergraph",
    title="Verify Tier-1 Intake, CMDB Supergraph & Wallet Registration",
    description=(
        "Read-only verification of enterprise AI intake approval, CMDB & Supergraph "
        "blast-radius indexing, catalog enrollment, wallet cap, and active policy freezes."
    ),
    annotations=ToolAnnotations(
        title="Verify Tier-1 Intake and Supergraph",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
def verify_tier1_intake_and_supergraph(candidate_id: str, app_id: str = "") -> str:
    """Returns Tier-1 governance checklist status, blast radius, and policy-freeze rules."""
    key = _resolve_candidate_key(candidate_id or app_id)
    payload = dict(TIER1_INTAKE_SUPERGRAPH_FIXTURES[key])
    if app_id and app_id.strip():
        payload["queried_app_id"] = app_id.strip()
    payload["checked_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return json.dumps(payload)


@mcp.tool(
    name="fetch_production_otel_traces",
    title="Fetch Production OpenTelemetry & Langfuse Failure Traces",
    description=(
        "Read-only retrieval of OTLP/Langfuse production spans, cross-cloud execution "
        "metadata, baseline eval scores, and anomalous tool/prompt failure clusters."
    ),
    annotations=ToolAnnotations(
        title="Fetch Production OTel Traces",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
def fetch_production_otel_traces(candidate_id: str, window_minutes: int = 60) -> str:
    """Returns OTLP/Langfuse trace diagnostics and failure clusters for a candidate agent."""
    if window_minutes == -503:
        raise RuntimeError("HTTP 503 Service Unavailable: OTLP trace collector timeout")
    key = _resolve_candidate_key(candidate_id)
    payload = dict(PRODUCTION_OTEL_TRACE_FIXTURES[key])
    payload["window_minutes"] = window_minutes
    payload["queried_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return json.dumps(payload)


@mcp.tool(
    name="record_compliance_evidence_note",
    title="Record Structured Governance Compliance Review Evidence",
    description="Non-destructive mutating tool that appends signed audit evidence to an intake record.",
    annotations=ToolAnnotations(
        title="Record Compliance Evidence Note",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=False,
    ),
)
def record_compliance_evidence_note(candidate_id: str, note: str) -> str:
    """Appends structured governance review evidence for a candidate agent."""
    entry = {
        "candidate_id": candidate_id.strip(),
        "note": note.strip()[:2000],
        "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "EVIDENCE_RECORDED",
    }
    COMPLIANCE_EVIDENCE_NOTES.append(entry)
    return json.dumps(entry)


@mcp.tool(
    name="force_bypass_governance_gate",
    title="Force-Bypass Mandatory Tier-1 Governance Gate (Destructive)",
    description="Destructive administrative override blocked by UAP Policy V2 CEL.",
    annotations=ToolAnnotations(
        title="Force Bypass Governance Gate",
        readOnlyHint=False,
        destructiveHint=True,
        idempotentHint=False,
        openWorldHint=False,
    ),
)
def force_bypass_governance_gate(candidate_id: str) -> str:
    """Destructive tool blocked fail-closed at Agent Gateway / UAP Policy V2 CEL."""
    return json.dumps(
        {
            "candidate_id": candidate_id,
            "status": "BYPASSED_IF_UNGOVERNED",
        }
    )


# Backward-compatible Python helper aliases
query_golden_signal_metrics = fetch_production_otel_traces
check_release_and_change_freeze = verify_tier1_intake_and_supergraph
lookup_service_topology_and_runbook = inspect_candidate_agent_manifest
annotate_incident_ticket = record_compliance_evidence_note
purge_production_valkey_stream = force_bypass_governance_gate


TOOL_SPEC_MANIFEST: dict[str, Any] = {
    "serverName": "cymbal-ops-mcp-server",
    "protocol": "MCP-StreamableHTTP",
    "tools": [
        {
            "name": "inspect_candidate_agent_manifest",
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "verify_tier1_intake_and_supergraph",
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "fetch_production_otel_traces",
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "record_compliance_evidence_note",
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False},
        },
        {
            "name": "force_bypass_governance_gate",
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
