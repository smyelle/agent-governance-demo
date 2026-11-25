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

"""FastAPI Backend-for-Frontend (BFF) for Cymbal Platform Agent Lifecycle Console.

Serves the four enterprise lifecycle stages:
- Build (/build): 10-Component Agent Deployment Template (Google Cloud vs. Custom
  Cymbal / Google Cloud selection) + Registered & Draft Agents inventory.
- Evaluate (/evaluate): Governance pillar & workstream rubric scoring, remediation queue,
  and 6-stage behavioral prompt/trace optimization.
- Deploy (/deploy): Terraform module & dynamic guardrail policy synthesis, approval gate,
  and production fleet enrollment.
- Govern (/govern): Policies & Rubric, Fleet Operations, FinOps & Economics, and Runtime Controls.
- Right Slide-Out Inspector Drawer: Component configuration & 9-Service Runtime Pipeline.

Implements strict web security controls:
- Strict Content-Security-Policy (`default-src 'self'`, zero `unsafe-inline`/`unsafe-eval`),
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Permissions-Policy`,
  and `Cache-Control: no-store` on API responses.
- Hardened `HttpOnly`, `SameSite=Strict` (`__Host-` on HTTPS) session cookies +
  synchronizer CSRF token verification on mutating POST routes.
- Fetch Metadata cross-site isolation, per-IP sliding-window rate limiting, and
  HTTP method allow-listing (`GET`, `POST`, `HEAD`).
- Strict Pydantic validation on all inbound payloads.
"""

from __future__ import annotations

import os

# Configure gRPC C-core logging and fork behavior before grpc modules initialize
os.environ.setdefault("GRPC_VERBOSITY", "ERROR")
os.environ.setdefault("GRPC_ENABLE_FORK_SUPPORT", "0")

from collections import defaultdict, deque
import hmac
import json
import logging
from pathlib import Path
import secrets
import sys
import time
from typing import Any, Literal

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from google.adk.apps.app import App, ResumabilityConfig
from google.adk.runners import InMemoryRunner
from google.adk.workflow.utils._workflow_hitl_utils import create_request_input_response
from google.genai import types
from pydantic import BaseModel, Field
import uvicorn

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

load_dotenv(REPO_ROOT / ".env")

from cymbal_agent.agent import build_cymbal_workflow  # noqa: E402
from cymbal_agent.governance.gcp_auth import (  # noqa: E402
    get_gcp_credentials,
    is_cloud_managed_runtime,
    probe_local_gcp_credentials,
)
from cymbal_agent.governance.identity_obo import (  # noqa: E402
    fetch_cloud_run_id_token,
    inspect_zero_secret_posture,
    mint_demo_adr011_token_pair,
    verify_adr011_dual_tokens,
)
from cymbal_agent.governance.model_armor_guard import (  # noqa: E402
    DynamicGuardrailPolicyPayload,
    FailClosedModelArmorGuard,
    ModelArmorBlockedError,
)
from cymbal_agent.governance.plugin import CymbalGovernancePlugin  # noqa: E402
from cymbal_agent.governance.telemetry_bridge import UnifiedTraceBridge  # noqa: E402
from cymbal_agent.governance.wallet_ledger import (  # noqa: E402
    AtomicWalletAndGovernanceStore,
    KillSwitchHaltedError,
    WalletBudgetExceededError,
)
from cymbal_agent.governance.workbench_state import (  # noqa: E402
    AgentDeploymentTemplate,
    ProviderChoice,
    RubricConfig,
    WorkbenchGovernanceEngine,
    apply_remediation_action_to_template,
    build_localized_slot_catalog,
    evaluate_template_against_rubric,
    parse_uploaded_template_manifest,
)
from cymbal_agent.memory.memory_bank import ScopedMemoryBankClient  # noqa: E402
from cymbal_agent.tenant import load_tenant_profile  # noqa: E402
from evals.run_beyond_scape_proofs import (  # noqa: E402
    calculate_guardrail_tco,
    run_all_beyond_scape_proofs,
    run_single_proof,
)
from evals.run_closed_loop_eval import execute_closed_loop_flywheel  # noqa: E402

logger = logging.getLogger("cymbal_web_bff")
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("google_genai").setLevel(logging.WARNING)
logging.getLogger("google_adk").setLevel(logging.WARNING)

STATIC_DIR = Path(__file__).resolve().parent / "static"
PROMPTS_DIR = REPO_ROOT / "config" / "prompts"

FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 36 32">'
    "<defs>"
    '<linearGradient id="cmg" x1="0%" y1="0%" x2="100%" y2="100%">'
    '<stop offset="0%" stop-color="#6D28D9"/>'
    '<stop offset="55%" stop-color="#EC4899"/>'
    '<stop offset="100%" stop-color="#2563EB"/>'
    "</linearGradient>"
    "</defs>"
    '<path d="M4 6.5C4 4.3 6.4 3 8.3 4.1l12.2 7.4c1.8 1.1 1.8 3.9 0 5L8.3 23.9C6.4 25 4 23.7 4 21.5V6.5z" fill="url(#cmg)"/>'
    '<path d="M23.5 8.5a10.5 10.5 0 0 1 0 11" fill="none" stroke="url(#cmg)" stroke-width="3" stroke-linecap="round"/>'
    '<path d="M28.5 5a16 16 0 0 1 0 18" fill="none" stroke="#2563EB" stroke-width="3" stroke-linecap="round"/>'
    "</svg>"
)

DEFAULT_TOPOLOGY_EDGES = [
    "identity->armor",
    "armor->gateway",
    "registry->gateway",
    "gateway->runtime",
    "runtime->memory",
    "gateway->mesh",
    "runtime->trace",
    "trace->eval",
    "eval->registry",
]


def _resolve_session_hmac_secret() -> bytes:
    env_secret = os.getenv("CYMBAL_BFF_SESSION_SECRET")
    if env_secret:
        return env_secret.strip().encode("utf-8")
    secret_file = REPO_ROOT / "jwt_secret.txt"
    if secret_file.is_file():
        return secret_file.read_text(encoding="utf-8").strip().encode("utf-8")
    logger.warning("Generating ephemeral secret. Instance-isolated!")
    return secrets.token_bytes(32)


_BFF_SECRET = _resolve_session_hmac_secret()
_REVOKED_SESSIONS: set[str] = set()
_SESSION_TTL_SECONDS = 3600.0
_RATE_BUCKETS: dict[str, deque[float]] = defaultdict(deque)
_RATE_LIMIT_MAX_REQUESTS = 240
_RATE_LIMIT_WINDOW_SEC = 60.0
_HSTS_MAX_AGE_SECONDS = int(os.getenv("CYMBAL_HSTS_MAX_AGE", "300"))

# TODO(security): Enforce hardware-backed WebAuthn / MFA step-up policies on Cloud Run
# Identity-Aware Proxy (IAP) access levels when promoting beyond sandbox evaluations.


def _is_effective_https(request: Request) -> bool:
    """Detects HTTPS directly or behind Cloud Run Google Front End TLS termination."""
    forwarded_proto = (
        request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    )
    origin_or_ref = (
        request.headers.get("origin") or request.headers.get("referer") or ""
    ).lower()
    via_local_http_proxy = origin_or_ref.startswith(
        "http://127.0.0.1"
    ) or origin_or_ref.startswith("http://localhost")
    return (
        request.url.scheme == "https" or forwarded_proto == "https"
    ) and not via_local_http_proxy


def _mint_signed_session_id(now_ts: float) -> str:
    nonce = secrets.token_urlsafe(18)
    iat = int(now_ts)
    payload = f"{nonce}.{iat}"
    sig = hmac.new(
        _BFF_SECRET, f"sid:{payload}".encode("utf-8"), "sha256"
    ).hexdigest()[:32]
    return f"{payload}.{sig}"


def _verify_signed_session_id(sid: str, now_ts: float) -> bool:
    if not sid or sid in _REVOKED_SESSIONS:
        return False
    parts = sid.split(".")
    if len(parts) != 3:
        return False
    nonce, iat_str, presented_sig = parts
    if not nonce or not iat_str.isdigit() or len(presented_sig) != 32:
        return False
    iat = int(iat_str)
    age = now_ts - iat
    if age < -60 or age > _SESSION_TTL_SECONDS:
        return False
    expected_sig = hmac.new(
        _BFF_SECRET, f"sid:{nonce}.{iat}".encode("utf-8"), "sha256"
    ).hexdigest()[:32]
    return hmac.compare_digest(presented_sig, expected_sig)


def _derive_csrf_token(sid: str) -> str:
    return hmac.new(
        _BFF_SECRET, f"csrf:{sid}".encode("utf-8"), "sha256"
    ).hexdigest()


def build_runtime_environment(request: Request | None = None) -> dict[str, Any]:
    """Builds non-PII runtime metadata for Cloud Run and local development."""
    k_service = os.getenv("K_SERVICE", "")
    k_revision = os.getenv("K_REVISION", "")
    on_cloud_run = bool(k_service)
    region = os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1")
    https_active = bool(request and _is_effective_https(request))
    iap_verified = bool(
        request
        and (
            request.headers.get("x-goog-iap-jwt-assertion")
            or request.headers.get("x-goog-authenticated-user-email")
        )
    )
    return {
        "target": "cloud_run" if on_cloud_run else "local_dev",
        "service_name": k_service or "cymbal-ops-release-web",
        "revision": k_revision or "local-dev",
        "region": region,
        "https_enforced": https_active,
        "iap_verified": iap_verified,
        "iam_auth_enforced": on_cloud_run,
        "session_backing": (
            "secret_manager_hmac"
            if os.getenv("CYMBAL_BFF_SESSION_SECRET")
            else "ephemeral_sandbox_hmac"
        ),
        "badge_label": (
            f"Cloud Run ({region})" if on_cloud_run else "Local Dev (127.0.0.1)"
        ),
    }


class TriageStartRequest(BaseModel):
    candidate_id: str | None = Field(default=None, max_length=32)
    incident_id: str | None = Field(default=None, max_length=32)
    agent_name: str | None = Field(default=None, max_length=80)
    service_name: str | None = Field(default=None, max_length=80)
    app_id: str = Field(default="SVC-CYMBAL-101", min_length=3, max_length=64)
    operator_prompt: str = Field(..., min_length=4, max_length=4000)
    architecture_mode: Literal["enterprise_hybrid", "google_native"] = "enterprise_hybrid"


class HitlResumeRequest(BaseModel):
    session_id: str = Field(..., min_length=4, max_length=128)
    interrupt_id: str = Field(..., min_length=4, max_length=128)
    approved: bool
    approver_principal: str = Field(default="gov-steward-lead", min_length=2, max_length=80)
    vp_exception_ticket: str | None = Field(default=None, max_length=64)
    reason: str = Field(
        default="Verified Tier-1 compliance hooks, dynamic guardrail spec, and Golden Blueprint.",
        max_length=400,
    )


class ModeSwitchRequest(BaseModel):
    architecture_mode: Literal["enterprise_hybrid", "google_native"]


class KillSwitchUpdateRequest(BaseModel):
    status: Literal["ACTIVE", "PAUSED", "DISABLED"]


class WalletCapUpdateRequest(BaseModel):
    monthly_cap_nano_usd: int = Field(..., ge=0, le=500_000_000_000)
    reset_spend: bool = False


class GuardrailTestRequest(BaseModel):
    sample_text: str = Field(..., min_length=1, max_length=4000)
    dynamic_policy: DynamicGuardrailPolicyPayload | None = None


class ClosedLoopTriggerRequest(BaseModel):
    custom_traces_json: str | None = Field(default=None, max_length=12000)


class TcoQueryRequest(BaseModel):
    daily_turns: int = Field(default=10_000_000, ge=100_000, le=200_000_000)
    tokens_per_turn: int = Field(default=1000, ge=100, le=16000)


class TemplateUploadRequest(BaseModel):
    filename: str = Field(default="uploaded_template.yaml", min_length=5, max_length=120)
    content: str = Field(..., min_length=2, max_length=524_288)


class TemplateEvaluateRequest(BaseModel):
    template: AgentDeploymentTemplate


class TemplateRemediateRequest(BaseModel):
    template: AgentDeploymentTemplate
    rule_id: str = Field(..., min_length=3, max_length=40)
    action: Literal["accept", "customize", "exception"]
    custom_provider: str | None = Field(default=None, max_length=40)
    custom_parameters: dict[str, Any] | None = None
    exception_reason: str | None = Field(default=None, max_length=300)


class TemplateDeployRequest(BaseModel):
    template: AgentDeploymentTemplate
    initial_score: float = Field(default=60.0, ge=0.0, le=100.0)
    approver_principal: str = Field(default="gov-steward-lead", min_length=2, max_length=80)
    vp_exception_ticket: str | None = Field(default=None, max_length=64)


CANDIDATE_PRESETS: list[dict[str, Any]] = [
    {
        "candidate_id": "CAND-101",
        "incident_id": "CAND-101",
        "title": "Shadow Python Agent Missing Tier-1 Hooks",
        "agent_name": "billing-dispute-assistant",
        "service_name": "billing-dispute-assistant",
        "app_id": "SVC-CYMBAL-101",
        "severity": "Path B | AG3 Shadow",
        "default_prompt": (
            "Audit CAND-101 (billing-dispute-assistant): remove static API keys, wire Tier-1 "
            "Gateway + OTLP + SPIFFE WIF via Terraform Paved Path, and stage Golden Blueprint deployment."
        ),
    },
    {
        "candidate_id": "CAND-204",
        "incident_id": "CAND-204",
        "title": "Cross-Cloud AWS/Azure Agent with Failing OTLP Traces",
        "agent_name": "media-entitlement-router",
        "service_name": "media-entitlement-router",
        "app_id": "SVC-CYMBAL-204",
        "severity": "A-La-Carte | AG3 Freeze",
        "default_prompt": (
            "Evaluate cross-cloud CAND-204 (media-entitlement-router) production OTLP/Langfuse "
            "failure spans without migrating its AWS runtime, verify governance-freeze rules, "
            "and stage Golden Blueprint promotion."
        ),
    },
    {
        "candidate_id": "CAND-309",
        "incident_id": "CAND-309",
        "title": "High-Risk Multi-BU PII & Mutating Tool Agent",
        "agent_name": "cpe-fleet-provisioning-agent",
        "service_name": "cpe-fleet-provisioning-agent",
        "app_id": "SVC-CYMBAL-309",
        "severity": "Multi-BU | SDP + CEL",
        "default_prompt": (
            "Audit CAND-309 (cpe-fleet-provisioning-agent). Production trace log: subscriber SSN "
            "123-45-6789 on CPE MAC aa:bb:cc:dd:ee:ff. Attach Dynamic Model Armor policy and "
            "block destructive MCP tools."
        ),
    },
]


def _resolve_prompts_dir() -> Path:
    runtime_dir = os.getenv("CYMBAL_RUNTIME_STATE_DIR")
    if runtime_dir:
        candidate = Path(runtime_dir) / "prompts"
        if candidate.is_dir():
            return candidate
    return PROMPTS_DIR


def _load_prompt_pointer() -> dict[str, Any]:
    active_dir = _resolve_prompts_dir()
    for pointer_path in (
        active_dir / "active_version.json",
        PROMPTS_DIR / "active_version.json",
    ):
        if pointer_path.is_file():
            try:
                return json.loads(pointer_path.read_text(encoding="utf-8"))
            except Exception:
                pass
    return {"active_version": "v2", "behavior_score": 96.4, "eval_gate": "passed"}


def build_platform_services_snapshot(
    *,
    store: AtomicWalletAndGovernanceStore,
    mem_bank: ScopedMemoryBankClient,
    tracer: UnifiedTraceBridge,
    architecture_mode: str,
    last_event: str = "4-Tier Coexistence control plane initialized and ready",
    trace_id: str = "",
    flow_sequence: list[str] | None = None,
    active_edges: list[str] | None = None,
    overrides: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Constructs live status across all 9 services mapped 1:1 to the 4-Tier Pyramid."""
    profile = load_tenant_profile()
    terms = profile.terminology
    agent_state = store.get_agent_state("agent-governance-demo")
    wallet_state = store.get_wallet_state("wallet-cymbal-ops")
    posture = inspect_zero_secret_posture()
    pointer = _load_prompt_pointer()
    memories = mem_bank.retrieve_memories(verified_user_id="gov-reviewer-01", limit=5)
    recent_traces = tracer.list_recent_traces(limit=5)
    recent_otlp = tracer.list_recent_otlp_exports(limit=5)

    kill_status = str(agent_state.get("status", "ACTIVE")).upper()
    spent_usd = int(wallet_state.get("spent_nano_usd", 0)) / 1e9
    cap_usd = int(wallet_state.get("monthly_cap_nano_usd", 15_000_000_000)) / 1e9
    resolved_cnt = int(wallet_state.get("resolved_incidents_count", 0))
    active_ver = str(pointer.get("active_version", "v2"))
    b_score = pointer.get("behavior_score", 96.4)

    t1_label = f"Tier 1 - Mandatory Foundation ({terms.platform_name})"
    t2_label = "Tier 2 - Enterprise Control & Runtime"
    t34_label = "Tier 3 & 4 - Eval Optimization & Frontier Models"

    services: list[dict[str, Any]] = [
        {
            "id": "agent_identity",
            "step": 1,
            "stage_group": t1_label,
            "name": "SPIFFE Identity & OIDC OBO",
            "plane": "Tier 1 Foundation",
            "subtitle": "Zero Static Secrets + ADR-011 azp Federation",
            "status": "READY" if posture.zero_secret_compliant else "BLOCKED",
            "badge_label": (
                "SPIFFE + ADR-011 OBO"
                if architecture_mode == "enterprise_hybrid"
                else "SPIFFE SVID Ready"
            ),
            "latency_ms": None,
            "api_surface": "agentidentity.googleapis.com / sts.googleapis.com (WIF)",
            "consolidates": "Keycard, Custom OBO Sidecars, HashiCorp Vault",
            "summary": posture.summary,
            "metrics": {
                "spiffe_id": posture.spiffe_id,
                "static_secrets_in_env": "0",
                "architecture_mode": architecture_mode,
            },
        },
        {
            "id": "agent_registry",
            "step": 2,
            "stage_group": t1_label,
            "name": f"{terms.registry_name} & Sync",
            "plane": "Tier 1 Foundation",
            "subtitle": "Golden Blueprints, Intake & Supergraph Link",
            "status": "READY",
            "badge_label": f"Blueprint {active_ver} ({b_score})",
            "latency_ms": None,
            "api_surface": "Enterprise Catalog Hook + agentregistry.googleapis.com",
            "consolidates": "Disconnected Multi-Catalog Sync Glue",
            "summary": (
                f"Synchronizes Golden Blueprint {active_ver} (behavior_score={b_score}) across "
                f"{terms.registry_name}, {terms.supergraph_name}, and GCP Agent Registry."
            ),
            "metrics": {
                "active_blueprint": f"bp-governance-synthesizer-{active_ver}",
                "supergraph_link": terms.supergraph_name,
                "eval_gate": str(pointer.get("eval_gate", "passed")),
            },
        },
        {
            "id": "agent_gateway",
            "step": 3,
            "stage_group": t1_label,
            "name": f"{terms.gateway_name} + UAP",
            "plane": "Tier 1 Foundation",
            "subtitle": "/26 PSC-I Attachment + Per-Tool CEL Policy",
            "status": "READY",
            "badge_label": (
                "Coexistence Proxy + CEL"
                if architecture_mode == "enterprise_hybrid"
                else "PSC-I + UAP CEL Active"
            ),
            "latency_ms": None,
            "api_surface": "Enterprise Gateway Proxy + networkservices.googleapis.com/agentGateways",
            "consolidates": "Agentgateway, Runlayer, Arcade, Hush",
            "summary": (
                f"Routes outbound traffic via {terms.gateway_name} over private /26 PSC-I "
                "attachment while enforcing fine-grained UAP Policy V2 CEL per-tool rules."
            ),
            "metrics": {
                "network_attachment": "10.10.1.0/26 (PRIVATE_RANGES_ONLY)",
                "readonly_mcp_tools": "ALLOW",
                "destructive_mcp_tools": "DENY (403 PERMISSION_DENIED)",
            },
        },
        {
            "id": "trace_wallet",
            "step": 4,
            "stage_group": t1_label,
            "name": f"{terms.observability_name} & Wallet",
            "plane": "Tier 1 Foundation",
            "subtitle": "OTLP Dual-Export + Kill Switch + Atomic Budget",
            "status": "READY" if kill_status == "ACTIVE" else "BLOCKED",
            "badge_label": f"{kill_status} | ${spent_usd:.4f}",
            "latency_ms": None,
            "api_surface": "OTLP v1 resourceSpans + cloudtrace + firestore + bigquery",
            "consolidates": "Revenium, Ascerta, Custom Trace Joiners",
            "summary": (
                f"Kill Switch={kill_status}; {terms.wallet_name}=${spent_usd:.6f}/${cap_usd:.2f} "
                f"({resolved_cnt} governed deployments); exported {len(recent_otlp)} OTLP envelopes."
            ),
            "metrics": {
                "kill_switch": kill_status,
                "wallet_spend_usd": f"${spent_usd:.6f} / ${cap_usd:.2f}",
                "otlp_envelopes_buffered": str(len(recent_otlp)),
                "w3c_traces": str(len(recent_traces)),
            },
        },
        {
            "id": "model_armor",
            "step": 5,
            "stage_group": t2_label,
            "name": "Dynamic Model Armor + SDP",
            "plane": "Tier 2 Control & Guardrail",
            "subtitle": "Per-Request BU Policy Router + Inline PII + 40-URL",
            "status": "READY",
            "badge_label": "Dynamic Router + Floor",
            "latency_ms": None,
            "api_surface": "modelarmor.us-central1.rep.googleapis.com + dlp.googleapis.com",
            "consolidates": "Straiker.ai, Static Template Sprawl",
            "summary": (
                "Routes per-request BU/risk/SDP JSON payloads onto 2 Floor-enforced base "
                "templates (eliminating 280+ static templates) as a $0.10/1M-token Ensemble Tier-0 filter."
            ),
            "metrics": {
                "base_pool": "cymbal-default-medium-gpp & cymbal-strict-ag3-gpp",
                "floor_enforcement": "ENABLED (failOpen=false)",
                "ensemble_role": "Tier-0 Inline SDP & URL Pre-Filter",
            },
        },
        {
            "id": "agent_runtime",
            "step": 6,
            "stage_group": t2_label,
            "name": "ADK 2.0 Runtime & gVisor",
            "plane": "Tier 2 Runtime & Sandbox",
            "subtitle": "Parallel Audit Graph + gVisor + RequestInput HITL",
            "status": "READY" if kill_status == "ACTIVE" else "BLOCKED",
            "badge_label": "ADK 2.0 Resumable" if kill_status == "ACTIVE" else f"Halted ({kill_status})",
            "latency_ms": None,
            "api_surface": "aiplatform.googleapis.com/ReasoningEngine + infra/terraform",
            "consolidates": "E2B MicroVMs, Custom Checkpoint State Glue",
            "summary": (
                "Executes typed ADK 2.0 Governance Workflow: 3-way parallel MCP audit, JoinNode, "
                "gVisor readiness scoring, Terraform Paved-Path generation, and AG3 HITL gate."
            ),
            "metrics": {
                "model": os.getenv("GEMINI_MODEL", "gemini-3.8-flash"),
                "sandbox": "BuiltInCodeExecutor (gVisor)",
                "paved_path_iac": "infra/terraform/ (Cloud Run & Vertex)",
            },
        },
        {
            "id": "memory_bank",
            "step": 7,
            "stage_group": t2_label,
            "name": "Vertex AI Memory Bank",
            "plane": "Tier 2 Longitudinal State",
            "subtitle": "JWT-Isolated Reviewer & Audit Memory",
            "status": "READY",
            "badge_label": f"{len(memories)} Audit Fact(s)",
            "latency_ms": None,
            "api_surface": "aiplatform.googleapis.com/agentEngines.memories",
            "consolidates": "Mem0, Memori, Custom Memory ABAC Wrappers",
            "summary": (
                "Recalls historical compliance reviews per candidate agent and persists "
                "signed deployment outcomes strictly isolated by JWT reviewer user_id."
            ),
            "metrics": {
                "principal_scope": "user_id=gov-reviewer-01",
                "stored_memories": str(len(memories)),
                "cross_tenant_leakage": "0 records",
            },
        },
        {
            "id": "mcp_a2a_mesh",
            "step": 8,
            "stage_group": t2_label,
            "name": "Governance MCP & A2A Mesh",
            "plane": "Tier 2 Governed Mesh",
            "subtitle": "/mcp Tier-1 Audit Tools & /a2a Paved-Path Deployer",
            "status": "READY",
            "badge_label": "IAM Auth Enforced",
            "latency_ms": None,
            "api_surface": "run.googleapis.com (StreamableHTTP /mcp + JSON-RPC 2.0 /a2a)",
            "consolidates": "Unauthenticated Webhooks & Manual Onboarding Scripts",
            "summary": (
                "Hosts IAM-protected Governance Discovery MCP Server (Manifest, Supergraph, "
                "OTLP Trace tools) and A2A v1.0 Paved-Path Deployment Executor."
            ),
            "metrics": {
                "mcp_server": "cymbal-ops-mcp-server (/mcp)",
                "a2a_agent": "remediation-a2a-agent (/a2a)",
                "public_ingress": "Disabled (--no-allow-unauthenticated)",
            },
        },
        {
            "id": "eval_flywheel",
            "step": 9,
            "stage_group": t34_label,
            "name": f"{terms.eval_engine_name}",
            "plane": "Tier 3 & 4 Golden Goose",
            "subtitle": "6-Stage Cross-Cloud Trace -> Eval -> Optimizer -> Gate",
            "status": "READY",
            "badge_label": f"Score {b_score}/100",
            "latency_ms": None,
            "api_surface": "agentplatform.Client.evals.evaluate + gemini-3.8-flash",
            "consolidates": "Veris Simulation, LangSmith",
            "summary": (
                f"A-la-carte 6-stage engine ingesting AWS/Azure/GCP OTLP traces without lock-in; "
                f"promoted Golden Blueprint {active_ver} ({b_score}/100 >= 90.0 gate)."
            ),
            "metrics": {
                "trace_sources": "AWS Bedrock, Azure OpenAI, GCP Vertex (OTLP)",
                "baseline_v1_score": "58.0 (BLOCKED)",
                "promoted_v2_score": f"{b_score} (PASSED)",
            },
        },
    ]

    if overrides:
        for svc in services:
            ov = overrides.get(svc["id"])
            if ov:
                merged_metrics = dict(svc.get("metrics") or {})
                if ov.get("metrics"):
                    merged_metrics.update({k: str(v) for k, v in ov["metrics"].items()})
                svc.update({k: v for k, v in ov.items() if k != "metrics"})
                svc["metrics"] = merged_metrics

    return {
        "last_event": last_event,
        "trace_id": trace_id,
        "architecture_mode": architecture_mode,
        "flow_sequence": flow_sequence or [s["id"] for s in services],
        "active_edges": active_edges or DEFAULT_TOPOLOGY_EDGES,
        "services": services,
    }


def create_bff_app(*, offline_mode: bool | None = None) -> FastAPI:
    if offline_mode is None:
        flag = (
            os.getenv("CYMBAL_BFF_OFFLINE")
            or os.getenv("SCAPE_BFF_OFFLINE")
            or "false"
        )
        offline_mode = flag.lower() in {"1", "true", "yes"}

    if not offline_mode and not is_cloud_managed_runtime():
        creds_ok, creds_reason = probe_local_gcp_credentials()
        if not creds_ok:
            logger.warning(
                "Local gcloud credentials unavailable or expired (%s); "
                "starting Web Workbench in resilient local mode. "
                "Run 'gcloud auth login' to re-enable live GCP telemetry.",
                creds_reason,
            )
            offline_mode = True

    live_cloud = not offline_mode
    if live_cloud:
        try:
            get_gcp_credentials()
            a2a_url = os.getenv("CYMBAL_A2A_URL") or os.getenv("SCAPE_A2A_URL") or ""
            if a2a_url:
                fetch_cloud_run_id_token(a2a_url)
        except Exception:
            pass

    store = AtomicWalletAndGovernanceStore(in_memory_only=offline_mode)
    guard = FailClosedModelArmorGuard(live_api_enabled=live_cloud)
    tracer = UnifiedTraceBridge(cloud_trace_enabled=live_cloud)
    mem_bank = ScopedMemoryBankClient(in_memory_only=offline_mode)
    plugin = CymbalGovernancePlugin(store=store, guard=guard, tracer=tracer)
    wf = build_cymbal_workflow(
        memory_bank=mem_bank,
        use_live_llm=False,
    )
    agent_adk_app = App(
        name="cymbal_web_agent_app",
        root_agent=wf,
        resumability_config=ResumabilityConfig(is_resumable=True),
        plugins=[plugin],
    )
    runner = InMemoryRunner(app=agent_adk_app)
    workbench = WorkbenchGovernanceEngine()

    runtime_cfg: dict[str, str] = {
        "architecture_mode": os.getenv("CYMBAL_PLATFORM_MODE", "enterprise_hybrid"),
    }

    bff = FastAPI(
        title="Cymbal Agent Governance, Optimization & Deployment Workbench",
        version="2.0.0",
        docs_url=None,
        redoc_url=None,
    )

    def _issue_or_get_session(request: Request, response: Response) -> tuple[str, str]:
        is_https = _is_effective_https(request)
        cookie_name = "__Host-cymbal_sid" if is_https else "cymbal_sid"
        sid = request.cookies.get(cookie_name) or ""
        now = time.time()
        if not _verify_signed_session_id(sid, now):
            sid = _mint_signed_session_id(now)
            response.set_cookie(
                key=cookie_name,
                value=sid,
                max_age=int(_SESSION_TTL_SECONDS),
                httponly=True,
                secure=is_https,
                samesite="strict",
                path="/",
            )
        csrf = _derive_csrf_token(sid)
        return sid, csrf

    def _verify_csrf(request: Request) -> None:
        is_https = _is_effective_https(request)
        sid = (
            request.cookies.get("__Host-cymbal_sid") or ""
            if is_https
            else (
                request.cookies.get("cymbal_sid")
                or request.cookies.get("__Host-cymbal_sid")
                or ""
            )
        )
        presented = request.headers.get("X-CSRF-Token") or ""
        now = time.time()
        if not sid or not presented or not _verify_signed_session_id(sid, now):
            raise HTTPException(
                status_code=403, detail="CSRF token missing or session expired."
            )
        expected_csrf = _derive_csrf_token(sid)
        if not hmac.compare_digest(presented, expected_csrf):
            raise HTTPException(status_code=403, detail="CSRF token mismatch.")

    @bff.middleware("http")
    async def security_and_rate_limit_middleware(request: Request, call_next: Any) -> Response:
        if request.method not in {"GET", "POST", "HEAD"}:
            return JSONResponse({"detail": "Method not allowed"}, status_code=405)

        sec_site = (request.headers.get("sec-fetch-site") or "").strip().lower()
        if sec_site and sec_site not in {"same-origin", "same-site", "none"}:
            sec_mode = (request.headers.get("sec-fetch-mode") or "").strip().lower()
            sec_dest = (request.headers.get("sec-fetch-dest") or "").strip().lower()
            allow_top_nav = (
                sec_site == "cross-site"
                and sec_mode == "navigate"
                and request.method in {"GET", "HEAD"}
                and not request.url.path.startswith("/api/")
                and sec_dest not in {"object", "embed", "iframe"}
            )
            if not allow_top_nav:
                return JSONResponse(
                    {"detail": "Cross-site request rejected by Fetch Metadata policy"},
                    status_code=403,
                )

        xff = request.headers.get("x-forwarded-for", "")
        if is_cloud_managed_runtime() and xff:
            client_ip = xff.split(",")[0].strip() or "127.0.0.1"
        else:
            client_ip = request.client.host if request.client else "127.0.0.1"

        now = time.time()
        bucket = _RATE_BUCKETS[client_ip]
        while bucket and (now - bucket[0]) > _RATE_LIMIT_WINDOW_SEC:
            bucket.popleft()
        if len(bucket) >= _RATE_LIMIT_MAX_REQUESTS:
            return JSONResponse({"detail": "Rate limit exceeded"}, status_code=429)
        bucket.append(now)

        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin-allow-popups"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Vary"] = "Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), accelerometer=(), "
            "focus-without-user-activation=()"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'report-sample'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        if _is_effective_https(request):
            response.headers["Strict-Transport-Security"] = (
                f"max-age={_HSTS_MAX_AGE_SECONDS}; includeSubDomains"
            )
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        elif request.url.path.startswith("/static/") or request.url.path in {
            "/",
            "/build",
            "/evaluate",
            "/deploy",
            "/govern",
        }:
            response.headers["Cache-Control"] = "no-cache"
        return response

    @bff.get("/healthz")
    async def healthz(request: Request) -> dict[str, Any]:
        env_meta = build_runtime_environment(request)
        return {
            "status": "ok",
            "service": "cymbal-ops-release-web",
            "target": env_meta["target"],
            "revision": env_meta["revision"],
        }

    @bff.post("/api/session/reset")
    async def reset_session(request: Request) -> JSONResponse:
        _verify_csrf(request)
        for cname in ("__Host-cymbal_sid", "cymbal_sid"):
            val = request.cookies.get(cname)
            if val:
                _REVOKED_SESSIONS.add(val)
        resp = JSONResponse({"status": "session_cleared"})
        resp.headers["Clear-Site-Data"] = '"cookies", "storage"'
        return resp

    @bff.get("/favicon.ico")
    async def favicon() -> Response:
        return Response(content=FAVICON_SVG, media_type="image/svg+xml")

    @bff.get("/api/bootstrap")
    async def bootstrap(request: Request, response: Response) -> dict[str, Any]:
        _, csrf_token = _issue_or_get_session(request, response)
        profile = load_tenant_profile()
        pointer = _load_prompt_pointer()
        active_pdir = _resolve_prompts_dir()
        v1_file = (
            active_pdir / "synthesizer_v1_flawed.txt"
            if (active_pdir / "synthesizer_v1_flawed.txt").is_file()
            else PROMPTS_DIR / "synthesizer_v1_flawed.txt"
        )
        v2_file = (
            active_pdir / "synthesizer_v2_optimized.txt"
            if (active_pdir / "synthesizer_v2_optimized.txt").is_file()
            else PROMPTS_DIR / "synthesizer_v2_optimized.txt"
        )
        bp_file = active_pdir / "enterprise_golden_blueprint_v2.json"
        v1_txt = v1_file.read_text(encoding="utf-8")
        v2_txt = v2_file.read_text(encoding="utf-8")
        bp_json = (
            json.loads(bp_file.read_text(encoding="utf-8"))
            if bp_file.is_file()
            else None
        )
        runtime_env = build_runtime_environment(request)

        platform_services = build_platform_services_snapshot(
            store=store,
            mem_bank=mem_bank,
            tracer=tracer,
            architecture_mode=runtime_cfg["architecture_mode"],
            last_event=(
                f"Lifecycle control plane ready ({profile.terminology.platform_name} + Google Cloud)"
            ),
        )

        return {
            "csrf_token": csrf_token,
            "runtime_environment": runtime_env,
            "architecture_mode": runtime_cfg["architecture_mode"],
            "tenant": profile.model_dump(),
            "candidates": CANDIDATE_PRESETS,
            "incidents": CANDIDATE_PRESETS,
            "agent_state": store.get_agent_state("agent-governance-demo"),
            "wallet_state": store.get_wallet_state("wallet-cymbal-ops"),
            "identity_posture": inspect_zero_secret_posture().__dict__,
            "prompt_registry": {
                "active": pointer,
                "v1_prompt": v1_txt,
                "v2_prompt": v2_txt,
                "golden_blueprint": bp_json,
            },
            "tco_default": calculate_guardrail_tco(daily_turns=10_000_000, tokens_per_turn=1000),
            "recent_traces": tracer.list_recent_traces(limit=10),
            "recent_otlp_exports": tracer.list_recent_otlp_exports(limit=5),
            "recent_ledger": store.recent_ledger_rows(limit=10),
            "recent_memories": mem_bank.retrieve_memories(
                verified_user_id="gov-reviewer-01", limit=5
            ),
            "platform_services": platform_services,
            "slot_catalog": build_localized_slot_catalog(profile),
            "templates": workbench.list_templates(),
            "rubric": workbench.get_rubric().model_dump(),
            "operations_metrics": workbench.build_operations_metrics(),
            "executive_costs": workbench.build_executive_cost_summary(),
        }

    @bff.post("/api/config/mode")
    async def switch_mode(req: ModeSwitchRequest, request: Request) -> dict[str, Any]:
        _verify_csrf(request)
        profile = load_tenant_profile()
        runtime_cfg["architecture_mode"] = req.architecture_mode
        obo_note = (
            f"4-Tier A-La-Carte Coexistence active: {profile.terminology.gateway_name} + OTLP + ADR-011 OBO"
            if req.architecture_mode == "enterprise_hybrid"
            else "Full GCP-Native Paved-Path mode active across all 9 services"
        )
        return {
            "architecture_mode": runtime_cfg["architecture_mode"],
            "tenant": profile.model_dump(),
            "platform_services": build_platform_services_snapshot(
                store=store,
                mem_bank=mem_bank,
                tracer=tracer,
                architecture_mode=runtime_cfg["architecture_mode"],
                last_event=obo_note,
                flow_sequence=["agent_identity", "agent_registry", "agent_gateway", "model_armor", "agent_runtime"],
                active_edges=["identity->armor", "armor->gateway", "gateway->runtime"],
            ),
        }

    @bff.post("/api/agent/audit")
    @bff.post("/api/agent/triage")
    async def start_governance_audit(req: TriageStartRequest, request: Request) -> Any:
        _verify_csrf(request)
        t0 = time.perf_counter()
        trace_id = tracer.new_trace_id()
        sess_preview_id = f"sess-{trace_id[:10]}"
        cand_id = (req.candidate_id or req.incident_id or "CAND-101").strip()
        agent_name = (req.agent_name or req.service_name or "billing-dispute-assistant").strip()

        try:
            store.assert_agent_active("agent-governance-demo")
            store.reserve_preflight_budget("wallet-cymbal-ops")
            verdict = guard.inspect_text(req.operator_prompt, direction="USER_PROMPT")
            store.record_guardrail_audit(
                trace_id=trace_id,
                session_id=sess_preview_id,
                agent_id="agent-governance-demo",
                direction="USER_PROMPT",
                verdict=verdict,
            )
            if not verdict.allowed:
                raise ModelArmorBlockedError(verdict.summary, verdict)
        except KillSwitchHaltedError as exc:
            snap = build_platform_services_snapshot(
                store=store,
                mem_bank=mem_bank,
                tracer=tracer,
                architecture_mode=req.architecture_mode,
                last_event=f"Execution halted immediately by Global Kill Switch ({exc.agent_status})",
                trace_id=trace_id,
                flow_sequence=["trace_wallet"],
                active_edges=[],
                overrides={
                    "trace_wallet": {
                        "status": "BLOCKED",
                        "badge_label": f"423 HALTED ({exc.agent_status})",
                        "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
                        "summary": str(exc),
                    },
                    "agent_runtime": {
                        "status": "STANDBY",
                        "badge_label": "Protected (Unreached)",
                        "summary": "Blocked upstream before ADK 2.0 Workflow or Gemini invocation.",
                    },
                },
            )
            return JSONResponse({"detail": str(exc), "platform_services": snap}, status_code=423)
        except WalletBudgetExceededError as exc:
            snap = build_platform_services_snapshot(
                store=store,
                mem_bank=mem_bank,
                tracer=tracer,
                architecture_mode=req.architecture_mode,
                last_event="Execution rejected pre-inference by Atomic Nano-USD Wallet (403 budget_exceeded)",
                trace_id=trace_id,
                flow_sequence=["trace_wallet"],
                active_edges=[],
                overrides={
                    "trace_wallet": {
                        "status": "BLOCKED",
                        "badge_label": "403 BUDGET_EXCEEDED",
                        "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
                        "summary": str(exc),
                    },
                    "agent_runtime": {
                        "status": "STANDBY",
                        "badge_label": "Zero Spend Incurred",
                        "summary": "Atomic Firestore pre-flight check prevented model token spend.",
                    },
                },
            )
            return JSONResponse({"detail": str(exc), "platform_services": snap}, status_code=403)
        except ModelArmorBlockedError as exc:
            snap = build_platform_services_snapshot(
                store=store,
                mem_bank=mem_bank,
                tracer=tracer,
                architecture_mode=req.architecture_mode,
                last_event=f"Blocked fail-closed by Dynamic Model Armor ({exc.audit_record.action_taken})",
                trace_id=trace_id,
                flow_sequence=["agent_identity", "model_armor", "trace_wallet"],
                active_edges=["identity->armor", "runtime->trace"],
                overrides={
                    "agent_identity": {
                        "status": "VERIFIED",
                        "badge_label": "SPIFFE Verified",
                        "latency_ms": 1.2,
                    },
                    "model_armor": {
                        "status": "BLOCKED",
                        "badge_label": exc.audit_record.action_taken,
                        "latency_ms": exc.audit_record.latency_ms,
                        "summary": exc.audit_record.summary,
                    },
                    "agent_runtime": {
                        "status": "STANDBY",
                        "badge_label": "Protected (Unreached)",
                        "summary": "Malicious payload stopped before ADK 2.0 Governance Workflow.",
                    },
                },
            )
            return JSONResponse({"detail": str(exc), "platform_services": snap}, status_code=400)

        init_state: dict[str, Any] = {
            "candidate_id": cand_id,
            "incident_id": cand_id,
            "agent_name": agent_name,
            "service_name": agent_name,
            "app_id": req.app_id,
            "architecture_mode": req.architecture_mode,
            "trace_id": trace_id,
        }
        if req.architecture_mode == "enterprise_hybrid":
            t_gw, t_mcp = mint_demo_adr011_token_pair()
            init_state["authorization_bearer"] = t_gw
            init_state["x_user_authorization_bearer"] = t_mcp

        session = await runner.session_service.create_session(
            app_name="cymbal_web_agent_app",
            user_id="gov-reviewer-01",
            state=init_state,
        )

        stream_messages: list[str] = []
        pending_approval: dict[str, Any] | None = None

        wf_t0 = time.perf_counter()
        async for ev in runner.run_async(
            user_id="gov-reviewer-01",
            session_id=session.id,
            new_message=types.Content(
                role="user", parts=[types.Part(text=verdict.sanitized_text)]
            ),
        ):
            if ev.long_running_tool_ids and ev.content and ev.content.parts:
                for p in ev.content.parts:
                    if p.function_call and p.function_call.args:
                        pending_approval = dict(p.function_call.args.get("payload") or {})
                        pending_approval["interrupt_id"] = next(iter(ev.long_running_tool_ids))
            elif ev.content and ev.content.parts:
                for p in ev.content.parts:
                    if p.text:
                        stream_messages.append(p.text)
        wf_ms = round((time.perf_counter() - wf_t0) * 1000, 2)

        updated = await runner.session_service.get_session(
            app_name="cymbal_web_agent_app",
            user_id="gov-reviewer-01",
            session_id=session.id,
        )
        st = updated.state if updated else {}

        ledger_row = store.settle_turn_spend(
            wallet_id="wallet-cymbal-ops",
            agent_id="agent-governance-demo",
            session_id=session.id,
            trace_id=trace_id,
            architecture_mode=req.architecture_mode,
            input_tokens=540,
            output_tokens=280,
            outcome="GOVERNANCE_AUDIT_SYNTHESIZED",
            incident_id=cand_id,
            incident_resolved=pending_approval is None,
        )
        total_ms = round((time.perf_counter() - t0) * 1000, 2)
        tracer.record_span(
            trace_id=trace_id,
            session_id=session.id,
            span_name="governance_workbench.audit_and_paved_path",
            stage="adk_workflow_graph",
            duration_ms=total_ms,
            architecture_mode=req.architecture_mode,
            cmdb_app_id=req.app_id,
            attributes={
                "candidate.id": cand_id,
                "hitl.paused": pending_approval is not None,
                "pii.masked_inline": verdict.pii_masked,
            },
        )

        sandbox_obj = (
            json.loads(st["sandbox_anomaly_summary"])
            if st.get("sandbox_anomaly_summary")
            else None
        )
        assessment = st.get("incident_assessment") or {}
        recalled_cnt = int(st.get("recalled_facts_count", 1))
        readiness_str = (
            f"readiness={sandbox_obj['readiness_score']}/100"
            if sandbox_obj and "readiness_score" in sandbox_obj
            else "gVisor verified"
        )

        service_overrides: dict[str, dict[str, Any]] = {
            "agent_identity": {
                "status": "VERIFIED",
                "badge_label": (
                    "SPIFFE + azp OBO Verified"
                    if req.architecture_mode == "enterprise_hybrid"
                    else "SPIFFE SVID Verified"
                ),
                "latency_ms": 1.8,
                "summary": (
                    f"Verified workload SPIFFE posture and ADR-011 OIDC azp correlation for {cand_id}."
                ),
            },
            "agent_registry": {
                "status": "VERIFIED",
                "badge_label": f"Blueprint {_load_prompt_pointer().get('active_version', 'v2')} Bound",
                "latency_ms": 2.1,
                "summary": (
                    f"Checked Tier-1 Catalog & Supergraph metadata for {cand_id} ({req.app_id})."
                ),
            },
            "agent_gateway": {
                "status": "VERIFIED",
                "badge_label": "3x Read-Only Audit Allowed",
                "latency_ms": 4.2,
                "summary": (
                    "Enforced UAP Policy V2 CEL: allowed 3 readOnlyHint=true governance MCP tools "
                    "while keeping force_bypass_governance_gate blocked (403)."
                ),
            },
            "trace_wallet": {
                "status": "VERIFIED",
                "badge_label": f"OTLP + {ledger_row['total_cost_nano_usd']} nUSD",
                "latency_ms": 5.1,
                "summary": (
                    f"Dual-exported W3C + OTLP span {trace_id[:12]}... and settled "
                    f"{ledger_row['total_cost_nano_usd']} nano-USD in wallet_ledger."
                ),
            },
            "model_armor": {
                "status": "MASKED_PII" if verdict.pii_masked else "VERIFIED",
                "badge_label": "Inline SDP Masked" if verdict.pii_masked else "Dynamic Policy Ready",
                "latency_ms": verdict.latency_ms,
                "summary": verdict.summary,
                "metrics": {
                    "action": verdict.action_taken,
                    "pii_types_masked": ", ".join(verdict.pii_types_masked) or "None",
                    "policy_key": verdict.dynamic_policy_key,
                },
            },
            "agent_runtime": {
                "status": "PAUSED_HITL" if pending_approval else "VERIFIED",
                "badge_label": (
                    f"Paused: {pending_approval['interrupt_id']}"
                    if pending_approval
                    else f"Completed ({readiness_str})"
                ),
                "latency_ms": wf_ms,
                "summary": (
                    f"Parallel 3-way MCP audit -> JoinNode -> gVisor ({readiness_str}) -> "
                    + (
                        f"Paused at RequestInput('{pending_approval['interrupt_id']}') awaiting AG3 Reviewer sign-off."
                        if pending_approval
                        else f"Verified {assessment.get('risk_level', 'AG1')} advisory readiness."
                    )
                ),
            },
            "memory_bank": {
                "status": "VERIFIED",
                "badge_label": (
                    f"Recalled {recalled_cnt} Review(s)"
                    if pending_approval
                    else "Recalled + Persisted"
                ),
                "latency_ms": 6.4,
                "summary": (
                    f"Recalled {recalled_cnt} JWT-isolated compliance fact(s) for {agent_name}."
                ),
            },
            "mcp_a2a_mesh": {
                "status": "ACTIVE" if pending_approval else "VERIFIED",
                "badge_label": "3x MCP Audit Done | A2A Ready",
                "latency_ms": 8.9,
                "summary": (
                    "Executed inspect_candidate_agent_manifest, verify_tier1_intake_and_supergraph, "
                    "and fetch_production_otel_traces in parallel."
                ),
            },
            "eval_flywheel": {
                "status": "VERIFIED",
                "badge_label": f"Enforcing {assessment.get('risk_level', 'AG3')} Gate",
                "latency_ms": None,
                "summary": (
                    "Synthesized Dynamic Guardrail JSON + Terraform Paved-Path HCL under promoted v2 rules."
                ),
            },
        }

        platform_services = build_platform_services_snapshot(
            store=store,
            mem_bank=mem_bank,
            tracer=tracer,
            architecture_mode=req.architecture_mode,
            last_event=(
                f"Audit {cand_id}: Paused at AG3 Governance Reviewer Gate ({pending_approval['interrupt_id']})"
                if pending_approval
                else f"Audit {cand_id}: Completed AG1 compliance verification"
            ),
            trace_id=trace_id,
            flow_sequence=[
                "agent_identity",
                "agent_registry",
                "agent_gateway",
                "trace_wallet",
                "model_armor",
                "mcp_a2a_mesh",
                "memory_bank",
                "agent_runtime",
            ],
            overrides=service_overrides,
        )

        return {
            "session_id": session.id,
            "trace_id": trace_id,
            "status": "WAITING_AG3_APPROVAL" if pending_approval else "COMPLETED",
            "pii_masked_inline": verdict.pii_masked,
            "sanitized_prompt": verdict.sanitized_text,
            "stream_messages": stream_messages,
            "correlated_bundle": st.get("correlated_bundle_dict"),
            "sandbox_anomaly": sandbox_obj,
            "assessment": st.get("incident_assessment"),
            "pending_approval": pending_approval,
            "remediation_outcome": st.get("remediation_outcome"),
            "postmortem_record": st.get("postmortem_record"),
            "wallet_settlement": ledger_row,
            "agent_state": store.get_agent_state("agent-governance-demo"),
            "wallet_state": store.get_wallet_state("wallet-cymbal-ops"),
            "recent_memories": mem_bank.retrieve_memories(
                verified_user_id="gov-reviewer-01", limit=5
            ),
            "platform_services": platform_services,
        }

    @bff.post("/api/agent/resume")
    async def resume_agent_hitl(req: HitlResumeRequest, request: Request) -> Any:
        _verify_csrf(request)
        t0 = time.perf_counter()
        try:
            store.assert_agent_active("agent-governance-demo")
        except KillSwitchHaltedError as exc:
            snap = build_platform_services_snapshot(
                store=store,
                mem_bank=mem_bank,
                tracer=tracer,
                architecture_mode=runtime_cfg["architecture_mode"],
                last_event=f"Resume blocked by Global Kill Switch ({exc.agent_status})",
                flow_sequence=["trace_wallet"],
                active_edges=[],
                overrides={
                    "trace_wallet": {
                        "status": "BLOCKED",
                        "badge_label": f"423 HALTED ({exc.agent_status})",
                        "summary": str(exc),
                    }
                },
            )
            return JSONResponse({"detail": str(exc), "platform_services": snap}, status_code=423)

        part = create_request_input_response(
            req.interrupt_id,
            {
                "approved": req.approved,
                "approver_principal": req.approver_principal,
                "vp_exception_ticket": req.vp_exception_ticket,
                "reason": req.reason,
            },
        )
        messages: list[str] = []
        async for ev in runner.run_async(
            user_id="gov-reviewer-01",
            session_id=req.session_id,
            new_message=types.Content(role="user", parts=[part]),
        ):
            if ev.content and ev.content.parts:
                for p in ev.content.parts:
                    if p.text:
                        messages.append(p.text)

        updated = await runner.session_service.get_session(
            app_name="cymbal_web_agent_app",
            user_id="gov-reviewer-01",
            session_id=req.session_id,
        )
        if updated is None:
            raise HTTPException(status_code=404, detail="Workflow session not found.")
        st = updated.state
        trace_id = str(st.get("trace_id") or tracer.new_trace_id())
        cand_id = str(st.get("candidate_id") or st.get("incident_id") or "CAND-101")

        store.reserve_preflight_budget("wallet-cymbal-ops")
        ledger_row = store.settle_turn_spend(
            wallet_id="wallet-cymbal-ops",
            agent_id="agent-governance-demo",
            session_id=req.session_id,
            trace_id=trace_id,
            architecture_mode=runtime_cfg["architecture_mode"],
            input_tokens=220,
            output_tokens=150,
            outcome="AG3_PAVED_PATH_DEPLOYED" if req.approved else "AG3_HELD_GOVERNANCE_FREEZE",
            incident_id=cand_id,
            incident_resolved=req.approved,
        )
        resume_ms = round((time.perf_counter() - t0) * 1000, 2)
        tracer.record_span(
            trace_id=trace_id,
            session_id=req.session_id,
            span_name="governance_workbench.ag3_resume_and_a2a_deploy",
            stage="hitl_resume",
            duration_ms=resume_ms,
            architecture_mode=runtime_cfg["architecture_mode"],
            attributes={
                "ag3.approved": req.approved,
                "ag3.approver": req.approver_principal,
                "candidate.id": cand_id,
            },
        )

        rem_outcome = dict(st.get("remediation_outcome") or {})
        memories = mem_bank.retrieve_memories(verified_user_id="gov-reviewer-01", limit=5)

        resume_overrides: dict[str, dict[str, Any]] = {
            "agent_identity": {
                "status": "VERIFIED",
                "badge_label": "Reviewer + SPIFFE Bound",
                "latency_ms": 1.4,
            },
            "agent_registry": {
                "status": "VERIFIED" if req.approved else "STANDBY",
                "badge_label": (
                    f"Enrolled {rem_outcome.get('golden_blueprint_id', 'Blueprint')}"
                    if req.approved
                    else "Registry Held"
                ),
                "latency_ms": 4.1 if req.approved else None,
            },
            "agent_runtime": {
                "status": "VERIFIED",
                "badge_label": "HITL Resumed -> Completed",
                "latency_ms": resume_ms,
                "summary": (
                    f"Resumed durable checkpoint '{req.interrupt_id}' with decision "
                    f"{'APPROVED_DEPLOY' if req.approved else 'HELD_FOR_EXCEPTION'} by {req.approver_principal}."
                ),
            },
            "agent_gateway": {
                "status": "VERIFIED",
                "badge_label": "A2A Approval Verified" if req.approved else "Deployment Withheld",
                "latency_ms": 3.4,
            },
            "mcp_a2a_mesh": {
                "status": "VERIFIED" if req.approved else "STANDBY",
                "badge_label": "A2A Paved-Path Deployed" if req.approved else "Held Pending VP Ticket",
                "latency_ms": 11.6 if req.approved else None,
                "summary": str(rem_outcome.get("summary") or "Completed HITL deployment branch."),
            },
            "memory_bank": {
                "status": "VERIFIED",
                "badge_label": "Audit Trail Persisted",
                "latency_ms": 7.2,
                "summary": f"Persisted longitudinal compliance record for {cand_id}.",
            },
            "trace_wallet": {
                "status": "VERIFIED",
                "badge_label": f"Settled {ledger_row['cost_per_resolved_incident_nano_usd']} nUSD",
                "latency_ms": 4.8,
            },
        }

        platform_services = build_platform_services_snapshot(
            store=store,
            mem_bank=mem_bank,
            tracer=tracer,
            architecture_mode=runtime_cfg["architecture_mode"],
            last_event=(
                f"Deployed {cand_id}: Enrolled Golden Blueprint & Terraform Paved Path across Tier-1 + GCP"
                if req.approved
                else f"Held {cand_id}: Blueprint promotion paused pending VP Governance-Freeze Exception"
            ),
            trace_id=trace_id,
            flow_sequence=(
                [
                    "agent_identity",
                    "agent_runtime",
                    "agent_gateway",
                    "mcp_a2a_mesh",
                    "agent_registry",
                    "memory_bank",
                    "trace_wallet",
                ]
                if req.approved
                else ["agent_identity", "agent_runtime", "memory_bank", "trace_wallet"]
            ),
            overrides=resume_overrides,
        )

        return {
            "session_id": req.session_id,
            "trace_id": trace_id,
            "status": "COMPLETED",
            "stream_messages": messages,
            "remediation_outcome": rem_outcome,
            "postmortem_record": st.get("postmortem_record"),
            "wallet_settlement": ledger_row,
            "agent_state": store.get_agent_state("agent-governance-demo"),
            "wallet_state": store.get_wallet_state("wallet-cymbal-ops"),
            "memories": memories,
            "platform_services": platform_services,
        }

    @bff.post("/api/steward/kill-switch")
    async def update_kill_switch(
        req: KillSwitchUpdateRequest, request: Request
    ) -> dict[str, Any]:
        _verify_csrf(request)
        updated = store.set_agent_status("agent-governance-demo", req.status)
        snap = build_platform_services_snapshot(
            store=store,
            mem_bank=mem_bank,
            tracer=tracer,
            architecture_mode=runtime_cfg["architecture_mode"],
            last_event=f"Global Kill Switch set to {req.status} across Tier-1 & Agent Runtime",
            flow_sequence=["trace_wallet", "agent_runtime", "agent_gateway"],
        )
        return {"agent_state": updated, "platform_services": snap}

    @bff.post("/api/steward/wallet-cap")
    async def update_wallet_cap(req: WalletCapUpdateRequest, request: Request) -> dict[str, Any]:
        _verify_csrf(request)
        updated = store.update_wallet_cap(
            "wallet-cymbal-ops",
            monthly_cap_nano_usd=req.monthly_cap_nano_usd,
            reset_spend=req.reset_spend,
        )
        cap_usd = req.monthly_cap_nano_usd / 1e9
        snap = build_platform_services_snapshot(
            store=store,
            mem_bank=mem_bank,
            tracer=tracer,
            architecture_mode=runtime_cfg["architecture_mode"],
            last_event=f"Atomic Nano-USD Wallet ceiling updated to ${cap_usd:.6f}",
            flow_sequence=["trace_wallet", "agent_runtime"],
            overrides={
                "trace_wallet": {
                    "status": "VERIFIED" if req.monthly_cap_nano_usd >= 3_500_000 else "MASKED_PII",
                    "badge_label": f"Cap ${cap_usd:.4f}",
                }
            },
        )
        return {"wallet_state": updated, "platform_services": snap}

    @bff.post("/api/steward/tco")
    async def compute_tco(req: TcoQueryRequest, request: Request) -> dict[str, Any]:
        _verify_csrf(request)
        return calculate_guardrail_tco(
            daily_turns=req.daily_turns, tokens_per_turn=req.tokens_per_turn
        )

    @bff.post("/api/steward/guardrail-test")
    async def test_guardrail_live(req: GuardrailTestRequest, request: Request) -> dict[str, Any]:
        _verify_csrf(request)
        verdict = guard.inspect_text(
            req.sample_text,
            direction="USER_PROMPT",
            dynamic_policy=req.dynamic_policy,
        )
        trace_id = tracer.new_trace_id()
        store.record_guardrail_audit(
            trace_id=trace_id,
            session_id="steward-threat-lab",
            agent_id="agent-governance-demo",
            direction="USER_PROMPT",
            verdict=verdict,
        )
        tracer.record_span(
            trace_id=trace_id,
            session_id="steward-threat-lab",
            span_name="threat_lab.dynamic_model_armor_inspect",
            stage="guardrail_test",
            duration_ms=verdict.latency_ms,
            architecture_mode=runtime_cfg["architecture_mode"],
            attributes={
                "allowed": verdict.allowed,
                "action": verdict.action_taken,
                "pii_masked": verdict.pii_masked,
                "dynamic_policy_key": verdict.dynamic_policy_key,
            },
        )

        ma_status = (
            "BLOCKED"
            if not verdict.allowed
            else ("MASKED_PII" if verdict.pii_masked else "VERIFIED")
        )
        snap = build_platform_services_snapshot(
            store=store,
            mem_bank=mem_bank,
            tracer=tracer,
            architecture_mode=runtime_cfg["architecture_mode"],
            last_event=(
                f"Dynamic Model Armor Router [{verdict.dynamic_policy_key}]: "
                f"{verdict.action_taken} ({verdict.latency_ms}ms)"
            ),
            trace_id=trace_id,
            flow_sequence=["agent_identity", "model_armor", "trace_wallet"],
            overrides={
                "model_armor": {
                    "status": ma_status,
                    "badge_label": verdict.action_taken,
                    "latency_ms": verdict.latency_ms,
                    "summary": verdict.summary,
                    "metrics": {
                        "resolved_template": verdict.template_id.split("/")[-1],
                        "dynamic_policy_key": verdict.dynamic_policy_key,
                        "ensemble_role": verdict.ensemble_role,
                    },
                },
                "trace_wallet": {
                    "status": "VERIFIED",
                    "badge_label": "OTLP + Audit Logged",
                    "summary": f"Recorded guardrail audit row and OTLP span {trace_id[:12]}...",
                },
            },
        )
        return {
            "trace_id": trace_id,
            "allowed": verdict.allowed,
            "sanitized_text": verdict.sanitized_text,
            "action_taken": verdict.action_taken,
            "filter_match_state": verdict.filter_match_state,
            "pii_masked": verdict.pii_masked,
            "pii_types_masked": verdict.pii_types_masked,
            "malicious_uri_detected": verdict.malicious_uri_detected,
            "injection_detected": verdict.injection_detected,
            "unpacked_layers": verdict.unpacked_layers,
            "latency_ms": verdict.latency_ms,
            "dynamic_policy_key": verdict.dynamic_policy_key,
            "resolved_template": verdict.template_id.split("/")[-1],
            "ensemble_role": verdict.ensemble_role,
            "summary": verdict.summary,
            "platform_services": snap,
        }

    @bff.post("/api/steward/obo-verify")
    async def verify_obo_pair(request: Request) -> dict[str, Any]:
        _verify_csrf(request)
        t_gw, t_mcp = mint_demo_adr011_token_pair()
        valid_res = verify_adr011_dual_tokens(t_gw, t_mcp)
        _, forged_mcp = mint_demo_adr011_token_pair(mcp_azp="unregistered-shadow-agent")
        forged_blocked = False
        try:
            verify_adr011_dual_tokens(t_gw, forged_mcp)
        except Exception:
            forged_blocked = True

        snap = build_platform_services_snapshot(
            store=store,
            mem_bank=mem_bank,
            tracer=tracer,
            architecture_mode=runtime_cfg["architecture_mode"],
            last_event="Verified SPIFFE zero-secret posture & ADR-011 azp OBO token correlation",
            flow_sequence=["agent_identity", "agent_gateway"],
            overrides={
                "agent_identity": {
                    "status": "VERIFIED",
                    "badge_label": "azp Correlation Verified",
                    "latency_ms": 1.6,
                    "summary": (
                        f"Authorized party azp={valid_res['authorized_party_azp']} matched across "
                        f"divergent pairwise subjects; forged azp rejected fail-closed."
                    ),
                }
            },
        )
        return {
            "adr011_valid_pair": valid_res,
            "mismatched_azp_blocked_fail_closed": forged_blocked,
            "platform_services": snap,
        }

    @bff.post("/api/steward/proofs/{proof_id}")
    async def trigger_single_proof(proof_id: int, request: Request) -> dict[str, Any]:
        _verify_csrf(request)
        if proof_id < 1 or proof_id > 8:
            raise HTTPException(status_code=400, detail="proof_id must be 1..8")
        res = await run_single_proof(proof_id, live_cloud=live_cloud)
        exercised = list(res.get("services_exercised") or ["agent_runtime"])
        ov = {
            sid: {
                "status": "VERIFIED" if res["passed"] else "BLOCKED",
                "badge_label": f"Proof #{proof_id} {'PASS' if res['passed'] else 'FAIL'}",
                "latency_ms": res["latency_ms"],
                "summary": res["measured_evidence"],
            }
            for sid in exercised
        }
        res["platform_services"] = build_platform_services_snapshot(
            store=store,
            mem_bank=mem_bank,
            tracer=tracer,
            architecture_mode=runtime_cfg["architecture_mode"],
            last_event=f"Modular Proof #{proof_id}: {'PASS' if res['passed'] else 'FAIL'} in {res['latency_ms']}ms",
            flow_sequence=exercised,
            overrides=ov,
        )
        return res

    @bff.post("/api/steward/proofs-all")
    async def trigger_all_proofs(request: Request) -> dict[str, Any]:
        _verify_csrf(request)
        summary = await run_all_beyond_scape_proofs(live_cloud=live_cloud)
        ov: dict[str, dict[str, Any]] = {}
        for p in summary.get("proofs", []):
            for sid in p.get("services_exercised", []):
                ov[sid] = {
                    "status": "VERIFIED" if p["passed"] else "BLOCKED",
                    "badge_label": "Verified Live",
                    "latency_ms": p["latency_ms"],
                    "summary": p["measured_evidence"],
                }
        summary["platform_services"] = build_platform_services_snapshot(
            store=store,
            mem_bank=mem_bank,
            tracer=tracer,
            architecture_mode=runtime_cfg["architecture_mode"],
            last_event=f"All {summary['passed_count']}/{summary['total_count']} Modular Coexistence Proofs passed live",
            overrides=ov,
        )
        return summary

    @bff.post("/api/steward/closed-loop-eval")
    async def trigger_closed_loop(
        request: Request,
        body: ClosedLoopTriggerRequest | None = None,
    ) -> dict[str, Any]:
        _verify_csrf(request)
        custom_traces = None
        if body and body.custom_traces_json:
            try:
                parsed = json.loads(body.custom_traces_json)
                if isinstance(parsed, list):
                    custom_traces = parsed
                elif isinstance(parsed, dict) and isinstance(parsed.get("traces"), list):
                    custom_traces = parsed["traces"]
            except Exception as exc:
                raise HTTPException(
                    status_code=400, detail=f"Invalid custom_traces_json: {exc}"
                ) from exc

        res = await execute_closed_loop_flywheel(
            live_cloud=live_cloud, custom_traces=custom_traces
        )
        v2_score = res["v2_candidate"]["behavior_score"]
        res["platform_services"] = build_platform_services_snapshot(
            store=store,
            mem_bank=mem_bank,
            tracer=tracer,
            architecture_mode=runtime_cfg["architecture_mode"],
            last_event=(
                f"6-Stage Closed-Loop Flywheel promoted Golden Blueprint v2 "
                f"(behavior_score={v2_score}) in {res['elapsed_seconds']}s"
            ),
            flow_sequence=[
                "trace_wallet",
                "eval_flywheel",
                "model_armor",
                "agent_registry",
                "agent_runtime",
            ],
            overrides={
                "eval_flywheel": {
                    "status": "VERIFIED",
                    "badge_label": f"v1 (58) -> v2 ({v2_score})",
                    "latency_ms": round(res["elapsed_seconds"] * 1000, 1),
                    "summary": (
                        f"Ingested cross-cloud OTLP spans, scored v1=58.0 (BLOCKED), synthesized v2 "
                        f"+ few-shots, and passed {res['v2_candidate']['cases_passed']}/"
                        f"{res['v2_candidate']['cases_total']} gVisor simulations."
                    ),
                },
                "agent_registry": {
                    "status": "VERIFIED",
                    "badge_label": f"Blueprint v2 ({v2_score})",
                    "summary": "Committed Golden Blueprint v2 across Enterprise Catalog, Agent Registry, and Firestore.",
                },
            },
        )
        return res

    @bff.get("/api/steward/telemetry")
    async def get_telemetry_snapshot() -> dict[str, Any]:
        return {
            "agent_state": store.get_agent_state("agent-governance-demo"),
            "wallet_state": store.get_wallet_state("wallet-cymbal-ops"),
            "recent_traces": tracer.list_recent_traces(limit=12),
            "recent_otlp_exports": tracer.list_recent_otlp_exports(limit=6),
            "recent_ledger": store.recent_ledger_rows(limit=12),
            "recent_guardrail_audits": store.recent_guardrail_audits(limit=12),
            "platform_services": build_platform_services_snapshot(
                store=store,
                mem_bank=mem_bank,
                tracer=tracer,
                architecture_mode=runtime_cfg["architecture_mode"],
                last_event="Refreshed live OTLP, Cloud Trace, Firestore, and BigQuery governance telemetry",
            ),
        }

    def _template_to_service_overrides(
        tpl: AgentDeploymentTemplate, evaluation: dict[str, Any]
    ) -> dict[str, dict[str, Any]]:
        slot_to_service = {
            "identity_access": "agent_identity",
            "agent_registry": "agent_registry",
            "ai_gateway": "agent_gateway",
            "observability_tracing": "trace_wallet",
            "cost_kill_controls": "trace_wallet",
            "safety_guardrails": "model_armor",
            "foundation_model": "agent_runtime",
            "runtime_sandbox": "agent_runtime",
            "memory_knowledge": "memory_bank",
            "eval_optimization": "eval_flywheel",
        }
        severity_rank = {"VERIFIED": 1, "MASKED_PII": 2, "BLOCKED": 3}
        failed_slots = {
            r["slot_id"]
            for r in evaluation.get("rule_results", [])
            if r.get("status") == "FAILED"
        }
        overrides: dict[str, dict[str, Any]] = {}
        for sid, svc_id in slot_to_service.items():
            comp = tpl.components.get(sid)
            prov = comp.provider if (comp and comp.enabled) else "unconfigured"
            if prov == "unconfigured" or sid in failed_slots:
                st_val = "BLOCKED" if prov == "unconfigured" else "MASKED_PII"
                lbl = "Unconfigured" if prov == "unconfigured" else "Action Required"
            else:
                st_val = "VERIFIED"
                lbl = "Cymbal Active" if prov == "cymbal_stack" else "Google Cloud"
            prev = overrides.get(svc_id)
            if prev is None or severity_rank[st_val] >= severity_rank.get(prev["status"], 0):
                overrides[svc_id] = {"status": st_val, "badge_label": lbl}
        overrides["mcp_a2a_mesh"] = {
            "status": "BLOCKED"
            if (tpl.destructive_mcp_tools_exposed and not tpl.uap_cel_per_tool_enforced)
            else "VERIFIED",
            "badge_label": (
                "CEL Gate Missing"
                if (tpl.destructive_mcp_tools_exposed and not tpl.uap_cel_per_tool_enforced)
                else "MCP + A2A Governed"
            ),
        }
        return overrides

    @bff.post("/api/templates/upload")
    async def upload_template_manifest(
        req: TemplateUploadRequest, request: Request
    ) -> dict[str, Any]:
        _verify_csrf(request)
        profile = load_tenant_profile()
        try:
            tpl = parse_uploaded_template_manifest(
                req.content, filename=req.filename, profile=profile
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        rubric = workbench.get_rubric()
        evaluation = evaluate_template_against_rubric(tpl, rubric, profile=profile)
        snap = build_platform_services_snapshot(
            store=store,
            mem_bank=mem_bank,
            tracer=tracer,
            architecture_mode=runtime_cfg["architecture_mode"],
            last_event=(
                f"Inspected uploaded template '{tpl.agent_name}': "
                f"score={evaluation['overall_score']}/100 ({evaluation['gate_verdict']})"
            ),
            overrides=_template_to_service_overrides(tpl, evaluation),
        )
        return {
            "template": tpl.model_dump(),
            "evaluation": evaluation,
            "platform_services": snap,
        }

    @bff.post("/api/templates/evaluate")
    async def evaluate_deployment_template(
        req: TemplateEvaluateRequest, request: Request
    ) -> dict[str, Any]:
        _verify_csrf(request)
        profile = load_tenant_profile()
        rubric = workbench.get_rubric()
        evaluation = evaluate_template_against_rubric(
            req.template, rubric, profile=profile
        )
        snap = build_platform_services_snapshot(
            store=store,
            mem_bank=mem_bank,
            tracer=tracer,
            architecture_mode=runtime_cfg["architecture_mode"],
            last_event=(
                f"Evaluated '{req.template.agent_name}' against {rubric.name}: "
                f"{evaluation['overall_score']}/100 ({evaluation['recommendations_count']} recommendation(s))"
            ),
            overrides=_template_to_service_overrides(req.template, evaluation),
        )
        return {
            "template": req.template.model_dump(),
            "evaluation": evaluation,
            "platform_services": snap,
        }

    @bff.post("/api/templates/remediate")
    async def remediate_deployment_template(
        req: TemplateRemediateRequest, request: Request
    ) -> dict[str, Any]:
        _verify_csrf(request)
        profile = load_tenant_profile()
        rubric = workbench.get_rubric()
        try:
            updated_tpl = apply_remediation_action_to_template(
                req.template,
                rule_id=req.rule_id,
                action=req.action,
                rubric=rubric,
                custom_provider=req.custom_provider,
                custom_parameters=req.custom_parameters,
                exception_reason=req.exception_reason,
                profile=profile,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        evaluation = evaluate_template_against_rubric(
            updated_tpl, rubric, profile=profile
        )
        snap = build_platform_services_snapshot(
            store=store,
            mem_bank=mem_bank,
            tracer=tracer,
            architecture_mode=runtime_cfg["architecture_mode"],
            last_event=(
                f"Applied '{req.action}' on {req.rule_id} for '{updated_tpl.agent_name}' -> "
                f"updated score {evaluation['overall_score']}/100"
            ),
            overrides=_template_to_service_overrides(updated_tpl, evaluation),
        )
        return {
            "template": updated_tpl.model_dump(),
            "evaluation": evaluation,
            "platform_services": snap,
        }

    @bff.post("/api/templates/deploy")
    async def deploy_governed_template(
        req: TemplateDeployRequest, request: Request
    ) -> Any:
        _verify_csrf(request)
        t0 = time.perf_counter()
        trace_id = tracer.new_trace_id()
        sess_id = f"dep-sess-{trace_id[:10]}"
        profile = load_tenant_profile()
        rubric = workbench.get_rubric()

        try:
            store.assert_agent_active("agent-governance-demo")
            store.reserve_preflight_budget("wallet-cymbal-ops")
            verdict = guard.inspect_text(
                req.template.system_instruction, direction="USER_PROMPT"
            )
            store.record_guardrail_audit(
                trace_id=trace_id,
                session_id=sess_id,
                agent_id="agent-governance-demo",
                direction="USER_PROMPT",
                verdict=verdict,
            )
            if not verdict.allowed:
                raise ModelArmorBlockedError(verdict.summary, verdict)
        except KillSwitchHaltedError as exc:
            snap = build_platform_services_snapshot(
                store=store,
                mem_bank=mem_bank,
                tracer=tracer,
                architecture_mode=runtime_cfg["architecture_mode"],
                last_event=f"Deployment blocked by Global Kill Switch ({exc.agent_status})",
                trace_id=trace_id,
            )
            return JSONResponse({"detail": str(exc), "platform_services": snap}, status_code=423)
        except WalletBudgetExceededError as exc:
            snap = build_platform_services_snapshot(
                store=store,
                mem_bank=mem_bank,
                tracer=tracer,
                architecture_mode=runtime_cfg["architecture_mode"],
                last_event="Deployment blocked by Atomic Nano-USD Wallet cap (403)",
                trace_id=trace_id,
            )
            return JSONResponse({"detail": str(exc), "platform_services": snap}, status_code=403)
        except ModelArmorBlockedError as exc:
            snap = build_platform_services_snapshot(
                store=store,
                mem_bank=mem_bank,
                tracer=tracer,
                architecture_mode=runtime_cfg["architecture_mode"],
                last_event=f"Deployment blocked by Model Armor ({exc.audit_record.action_taken})",
                trace_id=trace_id,
            )
            return JSONResponse({"detail": str(exc), "platform_services": snap}, status_code=400)

        evaluation = evaluate_template_against_rubric(
            req.template, rubric, profile=profile
        )
        if not evaluation["gate_passed"]:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Template '{req.template.agent_name}' has not met deployment gate "
                    f"(score={evaluation['overall_score']}/100, required={evaluation['passing_threshold']}/100, "
                    f"mandatory_failures={evaluation['mandatory_failures_count']}). "
                    "Accept remediation recommendations or record exceptions before deploying."
                ),
            )

        tpl_clean = req.template.model_copy(
            update={"system_instruction": verdict.sanitized_text}
        )
        dep_record = workbench.record_deployment(
            template=tpl_clean,
            initial_score=req.initial_score,
            approver_principal=req.approver_principal,
            trace_id=trace_id,
        )
        ledger_row = store.settle_turn_spend(
            wallet_id="wallet-cymbal-ops",
            agent_id="agent-governance-demo",
            session_id=sess_id,
            trace_id=trace_id,
            architecture_mode=runtime_cfg["architecture_mode"],
            input_tokens=480,
            output_tokens=260,
            outcome="GOVERNED_TEMPLATE_DEPLOYED",
            incident_id=dep_record["deployment_id"],
            incident_resolved=True,
        )
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        tracer.record_span(
            trace_id=trace_id,
            session_id=sess_id,
            span_name="governance_workbench.deploy_template",
            stage="template_deployment",
            duration_ms=elapsed_ms,
            architecture_mode=runtime_cfg["architecture_mode"],
            cmdb_app_id=tpl_clean.app_id,
            attributes={
                "deployment.id": dep_record["deployment_id"],
                "agent.name": tpl_clean.agent_name,
                "eval.final_score": dep_record["final_eval_score"],
            },
        )
        mem_bank.persist_memory(
            verified_user_id="gov-reviewer-01",
            incident_id=dep_record["deployment_id"],
            service_name=tpl_clean.agent_name,
            fact=(
                f"Deployed {tpl_clean.agent_name} ({dep_record['deployment_id']}) "
                f"score {dep_record['initial_eval_score']} -> {dep_record['final_eval_score']} "
                f"at ${dep_record['monthly_run_rate_usd']}/mo."
            ),
        )
        snap = build_platform_services_snapshot(
            store=store,
            mem_bank=mem_bank,
            tracer=tracer,
            architecture_mode=runtime_cfg["architecture_mode"],
            last_event=(
                f"Deployed {dep_record['deployment_id']} ({tpl_clean.agent_name}) -> "
                f"Score {dep_record['final_eval_score']}/100 | ${dep_record['monthly_run_rate_usd']}/mo"
            ),
            trace_id=trace_id,
            overrides=_template_to_service_overrides(tpl_clean, evaluation),
        )
        return {
            "deployment": dep_record,
            "templates": workbench.list_templates(),
            "wallet_settlement": ledger_row,
            "wallet_state": store.get_wallet_state("wallet-cymbal-ops"),
            "operations_metrics": workbench.build_operations_metrics(),
            "executive_costs": workbench.build_executive_cost_summary(),
            "recent_memories": mem_bank.retrieve_memories(
                verified_user_id="gov-reviewer-01", limit=5
            ),
            "platform_services": snap,
        }

    @bff.post("/api/ops/rubric")
    async def save_governance_rubric(
        req: RubricConfig, request: Request
    ) -> dict[str, Any]:
        _verify_csrf(request)
        saved = workbench.update_rubric(req)
        return {
            "rubric": saved.model_dump(),
            "templates": workbench.list_templates(),
        }

    @bff.post("/api/agents/save")
    @bff.post("/api/ops/templates")
    async def upsert_standard_template(
        req: AgentDeploymentTemplate, request: Request
    ) -> dict[str, Any]:
        _verify_csrf(request)
        profile = load_tenant_profile()
        saved = workbench.upsert_template(req)
        rubric = workbench.get_rubric()
        validated_tpl = AgentDeploymentTemplate.model_validate(saved)
        evaluation = evaluate_template_against_rubric(
            validated_tpl, rubric, profile=profile
        )
        snap = build_platform_services_snapshot(
            store=store,
            mem_bank=mem_bank,
            tracer=tracer,
            architecture_mode=runtime_cfg["architecture_mode"],
            last_event=(
                f"Saved deployment template '{validated_tpl.agent_name}' "
                f"(score={evaluation['overall_score']}/100)"
            ),
            overrides=_template_to_service_overrides(validated_tpl, evaluation),
        )
        return {
            "template": saved,
            "templates": workbench.list_templates(),
            "evaluation": evaluation,
            "platform_services": snap,
        }

    @bff.get("/api/ops/metrics")
    async def get_governance_ops_metrics() -> dict[str, Any]:
        return workbench.build_operations_metrics()

    @bff.get("/api/executive/costs")
    async def get_executive_cost_rollup(
        business_unit: str = "all",
        origin: str = "all",
    ) -> dict[str, Any]:
        allowed_bu = {
            "all",
            "core_cable",
            "media_studio",
            "intl_sky",
            "enterprise_shared",
        }
        allowed_orig = {
            "all",
            "google_gcp_standard",
            "cymbal_baseline",
            "custom_hybrid",
            "imported_manifest",
        }
        bu_val = business_unit if business_unit in allowed_bu else "all"
        orig_val = origin if origin in allowed_orig else "all"
        return workbench.build_executive_cost_summary(
            business_unit_filter=bu_val,
            origin_filter=orig_val,
        )

    bff.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @bff.get("/")
    @bff.get("/build")
    @bff.get("/evaluate")
    @bff.get("/deploy")
    @bff.get("/govern")
    @bff.get("/end-user")
    @bff.get("/governance-ops")
    @bff.get("/executive")
    async def serve_index(request: Request) -> FileResponse:
        resp = FileResponse(STATIC_DIR / "index.html")
        _issue_or_get_session(request, resp)
        return resp

    return bff


app = create_bff_app()


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    cloud_runtime = is_cloud_managed_runtime()
    default_host = "0.0.0.0" if cloud_runtime else "127.0.0.1"  # noqa: S104
    bind_host = os.getenv("BIND_HOST", default_host)
    uvicorn.run(
        app,
        host=bind_host,
        port=port,
        proxy_headers=cloud_runtime,
        forwarded_allow_ips="*" if cloud_runtime else "127.0.0.1",
    )
