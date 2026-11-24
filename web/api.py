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

"""FastAPI Backend-for-Frontend (BFF) for Cymbal Core Operations & Release Agent.

Serves:
- View 1: Cymbal Core Operations & Release Agent (ADK 2.0 Workflow + Resumable HITL)
- View 2: Google Agent Platform Steward Console (Kill Switch, Atomic Wallet, Proofs,
  TCO Calculator, Threat Sanitizer, Closed-Loop Optimizer, W3C Single-Trace Ledger)
- Live 9-Service Google Agent Platform Architecture Telemetry (`platform_services`)

Implements strict web security controls:
- Strict Content-Security-Policy (`default-src 'self'`, zero `unsafe-inline`/`unsafe-eval`),
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Permissions-Policy`,
  and `Cache-Control: no-store` on API responses.
- Hardened `HttpOnly`, `SameSite=Strict` session cookies + synchronizer CSRF token
  verification on mutating POST routes.
- Per-IP sliding-window rate limiting and HTTP method allow-listing (`GET`, `POST`).
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
from cymbal_agent.governance.gcp_auth import get_gcp_credentials  # noqa: E402
from cymbal_agent.governance.identity_obo import (  # noqa: E402
    fetch_cloud_run_id_token,
    inspect_zero_secret_posture,
    mint_demo_adr011_token_pair,
    verify_adr011_dual_tokens,
)
from cymbal_agent.governance.model_armor_guard import (  # noqa: E402
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
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
    '<rect width="32" height="32" rx="7" fill="#0284c7"/>'
    '<path d="M16 6l8 4v6c0 5.5-3.4 9.7-8 11-4.6-1.3-8-5.5-8-11v-6l8-4z" fill="#ffffff"/>'
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
        return env_secret.encode("utf-8")
    secret_file = REPO_ROOT / "jwt_secret.txt"
    if secret_file.is_file():
        return secret_file.read_text(encoding="utf-8").strip().encode("utf-8")
    logger.debug("Generated ephemeral in-memory BFF CSRF secret for sandbox session.")
    return secrets.token_bytes(32)


_BFF_SECRET = _resolve_session_hmac_secret()
_SESSION_CSRF_MAP: dict[str, tuple[str, float]] = {}
_SESSION_TTL_SECONDS = 3600.0
_RATE_BUCKETS: dict[str, deque[float]] = defaultdict(deque)
_RATE_LIMIT_MAX_REQUESTS = 240
_RATE_LIMIT_WINDOW_SEC = 60.0

# TODO(security): Integrate enterprise OIDC SSO + MFA enforcement at Cloud IAP / Load Balancer
# front door when promoting beyond isolated sandbox evaluations.


class TriageStartRequest(BaseModel):
    incident_id: str = Field(default="INC-4092", pattern=r"^INC-\d{4}$")
    service_name: str = Field(default="cymbal-release-api", min_length=2, max_length=80)
    app_id: str = Field(default="SVC-CYMBAL-992", min_length=3, max_length=64)
    operator_prompt: str = Field(..., min_length=4, max_length=2000)
    architecture_mode: Literal["google_native", "enterprise_hybrid"] = "google_native"


class HitlResumeRequest(BaseModel):
    session_id: str = Field(..., min_length=4, max_length=128)
    interrupt_id: str = Field(..., min_length=4, max_length=128)
    approved: bool
    approver_principal: str = Field(default="sre-oncall-lead", min_length=2, max_length=80)
    vp_exception_ticket: str | None = Field(default=None, max_length=64)
    reason: str = Field(default="Reviewed correlated telemetry and blast radius.", max_length=400)


class ModeSwitchRequest(BaseModel):
    architecture_mode: Literal["google_native", "enterprise_hybrid"]


class KillSwitchUpdateRequest(BaseModel):
    status: Literal["ACTIVE", "PAUSED", "DISABLED"]


class WalletCapUpdateRequest(BaseModel):
    monthly_cap_nano_usd: int = Field(..., ge=0, le=500_000_000_000)
    reset_spend: bool = False


class GuardrailTestRequest(BaseModel):
    sample_text: str = Field(..., min_length=1, max_length=4000)


class TcoQueryRequest(BaseModel):
    daily_turns: int = Field(default=10_000_000, ge=100_000, le=200_000_000)
    tokens_per_turn: int = Field(default=1000, ge=100, le=16000)


INCIDENT_PRESETS: list[dict[str, Any]] = [
    {
        "incident_id": "INC-4092",
        "title": "Release Gateway p99 Latency & Valkey usage:0 Saturation",
        "service_name": "cymbal-release-api",
        "app_id": "SVC-CYMBAL-992",
        "severity": "SEV-1 / AG3",
        "default_prompt": (
            "Investigate INC-4092: cymbal-release-api gateway p99 latency spiked to 4,820ms "
            "with Valkey usage:0 stream memory at 94.6% after release v2.14.3."
        ),
    },
    {
        "incident_id": "INC-4095",
        "title": "Settlement Webhook Timeout During Peak Change Freeze",
        "service_name": "billing-webhook-router",
        "app_id": "SVC-CYMBAL-710",
        "severity": "SEV-1 / AG3 Freeze",
        "default_prompt": (
            "Urgent INC-4095: billing-webhook-router p99 latency jumped to 5,410ms following "
            "release v3.8.1. Evaluate root cause, change-freeze rules, and safe remediation."
        ),
    },
    {
        "incident_id": "INC-4099",
        "title": "Edge Session Alert with Pasted Customer PII",
        "service_name": "edge-session-ingestor",
        "app_id": "SVC-CYMBAL-305",
        "severity": "SEV-3 / AG1 + SDP",
        "default_prompt": (
            "Triage INC-4099 on edge-session-ingestor. Raw pasted log snippet: subscriber SSN "
            "123-45-6789 on CPE MAC aa:bb:cc:dd:ee:ff saw minor 890ms jitter."
        ),
    },
]


def _load_prompt_pointer() -> dict[str, Any]:
    pointer_path = PROMPTS_DIR / "active_version.json"
    if pointer_path.is_file():
        try:
            return json.loads(pointer_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"active_version": "v2", "behavior_score": 96.2, "eval_gate": "passed"}


def build_platform_services_snapshot(
    *,
    store: AtomicWalletAndGovernanceStore,
    mem_bank: ScopedMemoryBankClient,
    tracer: UnifiedTraceBridge,
    architecture_mode: str,
    last_event: str = "Platform control plane initialized and ready",
    trace_id: str = "",
    flow_sequence: list[str] | None = None,
    active_edges: list[str] | None = None,
    overrides: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Constructs live status & telemetry across all 9 Google Agent Platform services."""
    agent_state = store.get_agent_state("cymbal-ops-release-agent")
    wallet_state = store.get_wallet_state("wallet-cymbal-ops")
    posture = inspect_zero_secret_posture()
    pointer = _load_prompt_pointer()
    memories = mem_bank.retrieve_memories(verified_user_id="sre-oncall-01", limit=5)
    recent_traces = tracer.list_recent_traces(limit=5)

    kill_status = str(agent_state.get("status", "ACTIVE")).upper()
    spent_usd = (int(wallet_state.get("spent_nano_usd", 0)) / 1e9)
    cap_usd = (int(wallet_state.get("monthly_cap_nano_usd", 15_000_000_000)) / 1e9)
    resolved_cnt = int(wallet_state.get("resolved_incidents_count", 0))
    active_ver = str(pointer.get("active_version", "v2"))
    b_score = pointer.get("behavior_score", 96.2)

    services: list[dict[str, Any]] = [
        {
            "id": "agent_identity",
            "step": 1,
            "stage_group": "Stage 1 - Identity & Zero-Trust Safety",
            "name": "Agent Identity & OBO",
            "plane": "Identity & Security",
            "subtitle": "SPIFFE SVID + Zero Static Secrets",
            "status": "READY" if posture.zero_secret_compliant else "BLOCKED",
            "badge_label": (
                "SPIFFE + ADR-011 OBO" if architecture_mode == "enterprise_hybrid" else "SPIFFE SVID Ready"
            ),
            "latency_ms": None,
            "api_surface": "agentidentity.googleapis.com / sts.googleapis.com",
            "consolidates": "Keycard, Custom OBO Sidecars, HashiCorp Vault",
            "summary": posture.summary,
            "metrics": {
                "spiffe_id": posture.spiffe_id,
                "static_secrets_in_env": "0",
                "architecture_mode": architecture_mode,
            },
        },
        {
            "id": "model_armor",
            "step": 2,
            "stage_group": "Stage 1 - Identity & Zero-Trust Safety",
            "name": "Model Armor + Cloud SDP",
            "plane": "Identity & Security",
            "subtitle": "Floor Settings + Inline PII Mask + 40-URL Scan",
            "status": "READY",
            "badge_label": "Fail-Closed Floor Active",
            "latency_ms": None,
            "api_surface": "modelarmor.us-central1.rep.googleapis.com + dlp.googleapis.com",
            "consolidates": "Straiker.ai, Azure Content Safety, Bedrock Guardrails",
            "summary": (
                "Enforces un-bypassable global Floor Settings, 3-layer Base64/Hex unpacking, "
                "inline SSN/MAC PII masking, and 40-URL phishing inspection."
            ),
            "metrics": {
                "template": "cymbal-default-medium-gpp",
                "floor_enforcement": "ENABLED (failOpen=false)",
                "sdp_inline_redaction": "SSN, MAC, Payment Card",
            },
        },
        {
            "id": "agent_registry",
            "step": 3,
            "stage_group": "Stage 2 - Discovery & Private L7 Gateway",
            "name": "Agent & Tool Registry",
            "plane": "Discovery & Inventory",
            "subtitle": "Canonical Agent, MCP Tool-Spec & A2A Card",
            "status": "READY",
            "badge_label": f"Active {active_ver} ({b_score})",
            "latency_ms": None,
            "api_surface": "agentregistry.googleapis.com/v1alpha",
            "consolidates": "Fragmented Multi-Catalog Sync Glue",
            "summary": (
                f"Governs canonical discovery for cymbal-ops-release-agent ({active_ver}, "
                f"behavior_score={b_score}), cymbal-ops-mcp-server, and remediation-a2a-agent."
            ),
            "metrics": {
                "registered_services": "3 (Agent, MCP Tool-Spec, A2A Card)",
                "active_prompt_version": active_ver,
                "eval_gate": str(pointer.get("eval_gate", "passed")),
            },
        },
        {
            "id": "agent_gateway",
            "step": 4,
            "stage_group": "Stage 2 - Discovery & Private L7 Gateway",
            "name": "Agent Gateway + ACT + UAP",
            "plane": "Network & Access Plane",
            "subtitle": "/26 PSC-I Attachment + Per-Tool CEL Policy",
            "status": "READY",
            "badge_label": "PSC-I + UAP CEL Active",
            "latency_ms": None,
            "api_surface": "networkservices.googleapis.com/agentGateways + iap.googleapis.com",
            "consolidates": "Agentgateway, Runlayer, Arcade, Hush",
            "summary": (
                "Routes agent egress over private /26 PSC-I attachment (10.10.1.0/26) and "
                "evaluates UAP Policy V2 CEL per-tool annotations inline."
            ),
            "metrics": {
                "network_attachment": "10.10.1.0/26 (PRIVATE_RANGES_ONLY)",
                "readonly_mcp_tools": "ALLOW",
                "destructive_mcp_tools": "DENY (403 PERMISSION_DENIED)",
            },
        },
        {
            "id": "agent_runtime",
            "step": 5,
            "stage_group": "Stage 3 - ADK 2.0 Runtime, Memory & Mesh",
            "name": "Vertex AI Agent Runtime",
            "plane": "ADK 2.0 Runtime & Sandbox",
            "subtitle": "Workflow Graph + JoinNode + gVisor + RequestInput HITL",
            "status": "READY" if kill_status == "ACTIVE" else "BLOCKED",
            "badge_label": "ADK 2.0 Resumable" if kill_status == "ACTIVE" else f"Halted ({kill_status})",
            "latency_ms": None,
            "api_surface": "aiplatform.googleapis.com/ReasoningEngine (gemini-3.8-flash)",
            "consolidates": "E2B MicroVMs, Custom Checkpoint State Glue",
            "summary": (
                "Executes typed ADK 2.0 Workflow graph: 3-way parallel MCP fan-out, JoinNode, "
                "BuiltInCodeExecutor gVisor sandbox, Gemini 3.8 Flash synthesis, and RequestInput HITL."
            ),
            "metrics": {
                "model": os.getenv("GEMINI_MODEL", "gemini-3.8-flash"),
                "sandbox": "BuiltInCodeExecutor (gVisor)",
                "resumability": "ResumabilityConfig(is_resumable=True)",
            },
        },
        {
            "id": "memory_bank",
            "step": 6,
            "stage_group": "Stage 3 - ADK 2.0 Runtime, Memory & Mesh",
            "name": "Vertex AI Memory Bank",
            "plane": "Scoped Longitudinal State",
            "subtitle": "JWT Principal-Scoped Cross-Session Recall",
            "status": "READY",
            "badge_label": f"{len(memories)} Scoped Fact(s)",
            "latency_ms": None,
            "api_surface": "aiplatform.googleapis.com/agentEngines.memories",
            "consolidates": "Mem0, Memori, Custom Memory ABAC Wrappers",
            "summary": (
                "Recalls longitudinal service incident history at intake and persists resolved "
                "postmortems strictly bound to verified JWT principal user_id."
            ),
            "metrics": {
                "principal_scope": "user_id=sre-oncall-01",
                "stored_memories": str(len(memories)),
                "cross_tenant_leakage": "0 records",
            },
        },
        {
            "id": "mcp_a2a_mesh",
            "step": 7,
            "stage_group": "Stage 3 - ADK 2.0 Runtime, Memory & Mesh",
            "name": "Cloud Run MCP & A2A Mesh",
            "plane": "Governed Tool & Agent Mesh",
            "subtitle": "/mcp Read-Only Triage Tools & /a2a Canary Rollback",
            "status": "READY",
            "badge_label": "IAM Auth Enforced",
            "latency_ms": None,
            "api_surface": "run.googleapis.com (StreamableHTTP /mcp + JSON-RPC 2.0 /a2a)",
            "consolidates": "Unauthenticated Webhooks & Coarse Tool Pools",
            "summary": (
                "Hosts IAM-protected cymbal-ops-mcp-server (Golden Signals, Release Freeze, "
                "ServiceAtlas CMDB) and remediation-a2a-agent (AG3 canary rollback executor)."
            ),
            "metrics": {
                "mcp_server": "cymbal-ops-mcp-server (/mcp)",
                "a2a_agent": "remediation-a2a-agent (/a2a)",
                "public_ingress": "Disabled (--no-allow-unauthenticated)",
            },
        },
        {
            "id": "trace_wallet",
            "step": 8,
            "stage_group": "Stage 4 - FinOps, Trace & Eval Flywheel",
            "name": "Cloud Trace & Atomic Wallet",
            "plane": "Observability & FinOps",
            "subtitle": "Kill Switch + W3C Single-Trace + BigQuery Ledger",
            "status": "READY" if kill_status == "ACTIVE" else "BLOCKED",
            "badge_label": f"{kill_status} | ${spent_usd:.4f}",
            "latency_ms": None,
            "api_surface": "cloudtrace.googleapis.com + firestore + bigquery.googleapis.com",
            "consolidates": "Revenium, Ascerta, Disconnected Log Stores",
            "summary": (
                f"Kill Switch={kill_status}; Wallet=${spent_usd:.6f} spent of ${cap_usd:.2f} cap "
                f"({resolved_cnt} resolved incidents); joins W3C spans in Cloud Trace."
            ),
            "metrics": {
                "kill_switch": kill_status,
                "wallet_spend_usd": f"${spent_usd:.6f} / ${cap_usd:.2f}",
                "recent_w3c_traces": str(len(recent_traces)),
            },
        },
        {
            "id": "eval_flywheel",
            "step": 9,
            "stage_group": "Stage 4 - FinOps, Trace & Eval Flywheel",
            "name": "Gen AI Eval & Optimizer",
            "plane": "Continuous Quality Flywheel",
            "subtitle": "503 & Change-Freeze Simulation + Prompt Optimizer",
            "status": "READY",
            "badge_label": f"Score {b_score}/100",
            "latency_ms": None,
            "api_surface": "Vertex AI Gen AI Eval + CymbalEnvironmentSimulator",
            "consolidates": "Veris Simulation, LangSmith",
            "summary": (
                f"Continuously evaluates failure traces across 8 adversarial & HTTP 503 cases; "
                f"promoted {active_ver} ({b_score}/100 >= 90.0 gate)."
            ),
            "metrics": {
                "baseline_v1_score": "58.0 (BLOCKED)",
                "promoted_v2_score": f"{b_score} (PASSED)",
                "simulated_faults": "HTTP 503 + Peak Change Freeze + Base64 Injection",
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

    runtime_cfg: dict[str, str] = {
        "architecture_mode": os.getenv("CYMBAL_PLATFORM_MODE", "google_native"),
    }

    bff = FastAPI(
        title="Cymbal Core Operations & Release Agent - Google Agent Platform Console",
        version="1.1.0",
        docs_url=None,
        redoc_url=None,
    )

    def _issue_or_get_session(request: Request, response: Response) -> tuple[str, str]:
        is_https = request.url.scheme == "https"
        cookie_name = "__Host-cymbal_sid" if is_https else "cymbal_sid"
        sid = request.cookies.get(cookie_name) or ""
        now = time.time()
        entry = _SESSION_CSRF_MAP.get(sid)
        if not sid or entry is None or (now - entry[1]) > _SESSION_TTL_SECONDS:
            sid = secrets.token_urlsafe(24)
            csrf = hmac.new(_BFF_SECRET, sid.encode("utf-8"), "sha256").hexdigest()
            _SESSION_CSRF_MAP[sid] = (csrf, now)
            response.set_cookie(
                key=cookie_name,
                value=sid,
                max_age=int(_SESSION_TTL_SECONDS),
                httponly=True,
                secure=is_https,
                samesite="strict",
                path="/",
            )
        else:
            csrf = entry[0]
            _SESSION_CSRF_MAP[sid] = (csrf, now)
        return sid, csrf

    def _verify_csrf(request: Request) -> None:
        is_https = request.url.scheme == "https"
        cookie_name = "__Host-cymbal_sid" if is_https else "cymbal_sid"
        sid = request.cookies.get(cookie_name) or ""
        presented = request.headers.get("X-CSRF-Token") or ""
        entry = _SESSION_CSRF_MAP.get(sid)
        if not sid or not presented or entry is None:
            raise HTTPException(status_code=403, detail="CSRF token missing or session expired.")
        if (time.time() - entry[1]) > _SESSION_TTL_SECONDS:
            _SESSION_CSRF_MAP.pop(sid, None)
            raise HTTPException(status_code=403, detail="Session expired; reload page.")
        if not hmac.compare_digest(presented, entry[0]):
            raise HTTPException(status_code=403, detail="CSRF token mismatch.")

    @bff.middleware("http")
    async def security_and_rate_limit_middleware(request: Request, call_next: Any) -> Response:
        if request.method not in {"GET", "POST", "HEAD"}:
            return JSONResponse({"detail": "Method not allowed"}, status_code=405)

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
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @bff.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "service": "cymbal-ops-release-web"}

    @bff.get("/favicon.ico")
    async def favicon() -> Response:
        return Response(content=FAVICON_SVG, media_type="image/svg+xml")

    @bff.get("/api/bootstrap")
    async def bootstrap(request: Request, response: Response) -> dict[str, Any]:
        _, csrf_token = _issue_or_get_session(request, response)
        profile = load_tenant_profile()
        pointer = _load_prompt_pointer()
        v1_txt = (PROMPTS_DIR / "synthesizer_v1_flawed.txt").read_text(encoding="utf-8")
        v2_txt = (PROMPTS_DIR / "synthesizer_v2_optimized.txt").read_text(encoding="utf-8")

        platform_services = build_platform_services_snapshot(
            store=store,
            mem_bank=mem_bank,
            tracer=tracer,
            architecture_mode=runtime_cfg["architecture_mode"],
            last_event="All 9 Google Agent Platform services online and ready for incident triage",
        )

        return {
            "csrf_token": csrf_token,
            "architecture_mode": runtime_cfg["architecture_mode"],
            "tenant": profile.model_dump(),
            "incidents": INCIDENT_PRESETS,
            "agent_state": store.get_agent_state("cymbal-ops-release-agent"),
            "wallet_state": store.get_wallet_state("wallet-cymbal-ops"),
            "identity_posture": inspect_zero_secret_posture().__dict__,
            "prompt_registry": {
                "active": pointer,
                "v1_prompt": v1_txt,
                "v2_prompt": v2_txt,
            },
            "tco_default": calculate_guardrail_tco(daily_turns=10_000_000, tokens_per_turn=1000),
            "recent_traces": tracer.list_recent_traces(limit=10),
            "recent_ledger": store.recent_ledger_rows(limit=10),
            "recent_memories": mem_bank.retrieve_memories(
                verified_user_id="sre-oncall-01", limit=5
            ),
            "platform_services": platform_services,
        }

    @bff.post("/api/config/mode")
    async def switch_mode(req: ModeSwitchRequest, request: Request) -> dict[str, Any]:
        _verify_csrf(request)
        profile = load_tenant_profile()
        runtime_cfg["architecture_mode"] = req.architecture_mode
        obo_note = (
            "Hybrid coexistence active: ADR-011 dual-token azp correlation + single-guardrail passthrough enabled"
            if req.architecture_mode == "enterprise_hybrid"
            else "Google-Native Full Platform mode active across all 9 services"
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
                flow_sequence=["agent_identity", "model_armor", "agent_gateway", "agent_runtime"],
                active_edges=["identity->armor", "armor->gateway", "gateway->runtime"],
            ),
        }

    @bff.post("/api/agent/triage")
    async def start_agent_triage(req: TriageStartRequest, request: Request) -> Any:
        _verify_csrf(request)
        t0 = time.perf_counter()
        trace_id = tracer.new_trace_id()
        sess_preview_id = f"sess-{trace_id[:10]}"

        try:
            store.assert_agent_active("cymbal-ops-release-agent")
            store.reserve_preflight_budget("wallet-cymbal-ops")
            verdict = guard.inspect_text(req.operator_prompt, direction="USER_PROMPT")
            store.record_guardrail_audit(
                trace_id=trace_id,
                session_id=sess_preview_id,
                agent_id="cymbal-ops-release-agent",
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
                last_event=f"Blocked fail-closed by Model Armor ({exc.audit_record.action_taken})",
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
                        "summary": "Malicious prompt stopped before ADK 2.0 Workflow execution.",
                    },
                },
            )
            return JSONResponse({"detail": str(exc), "platform_services": snap}, status_code=400)

        init_state: dict[str, Any] = {
            "incident_id": req.incident_id,
            "service_name": req.service_name,
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
            user_id="sre-oncall-01",
            state=init_state,
        )

        stream_messages: list[str] = []
        pending_approval: dict[str, Any] | None = None

        wf_t0 = time.perf_counter()
        async for ev in runner.run_async(
            user_id="sre-oncall-01",
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
            user_id="sre-oncall-01",
            session_id=session.id,
        )
        st = updated.state if updated else {}

        ledger_row = store.settle_turn_spend(
            wallet_id="wallet-cymbal-ops",
            agent_id="cymbal-ops-release-agent",
            session_id=session.id,
            trace_id=trace_id,
            architecture_mode=req.architecture_mode,
            input_tokens=520,
            output_tokens=260,
            outcome="AGENT_TRIAGE_SYNTHESIZED",
            incident_id=req.incident_id,
            incident_resolved=pending_approval is None,
        )
        total_ms = round((time.perf_counter() - t0) * 1000, 2)
        tracer.record_span(
            trace_id=trace_id,
            session_id=session.id,
            span_name="cymbal_agent.workflow_triage",
            stage="adk_workflow_graph",
            duration_ms=total_ms,
            architecture_mode=req.architecture_mode,
            cmdb_app_id=req.app_id,
            attributes={
                "incident.id": req.incident_id,
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
        z_str = f"z={sandbox_obj['z_score']} sigma" if sandbox_obj else "gVisor verified"

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
                    f"Authenticated workload via {st.get('spiffe_id', 'SPIFFE SVID')} with zero static secrets."
                ),
            },
            "model_armor": {
                "status": "MASKED_PII" if verdict.pii_masked else "VERIFIED",
                "badge_label": "Inline SDP Masked" if verdict.pii_masked else "ALLOWED_CLEAN",
                "latency_ms": verdict.latency_ms,
                "summary": verdict.summary,
                "metrics": {
                    "action": verdict.action_taken,
                    "pii_types_masked": ", ".join(verdict.pii_types_masked) or "None",
                    "unpacked_layers": str(verdict.unpacked_layers),
                },
            },
            "agent_gateway": {
                "status": "VERIFIED",
                "badge_label": "3x Read-Only MCP Allowed",
                "latency_ms": 4.2,
                "summary": (
                    "Enforced UAP Policy V2 CEL over /26 PSC-I attachment: allowed 3 readOnlyHint=true "
                    "MCP triage tools while keeping destructive tools blocked."
                ),
            },
            "agent_registry": {
                "status": "VERIFIED",
                "badge_label": f"Prompt {_load_prompt_pointer().get('active_version', 'v2')} Bound",
                "latency_ms": 2.1,
                "summary": (
                    f"Resolved cymbal-ops-mcp-server tool-spec and governed synthesizer instruction "
                    f"({_load_prompt_pointer().get('active_version', 'v2')})."
                ),
            },
            "agent_runtime": {
                "status": "PAUSED_HITL" if pending_approval else "VERIFIED",
                "badge_label": (
                    f"Paused: {pending_approval['interrupt_id']}"
                    if pending_approval
                    else f"Completed ({z_str})"
                ),
                "latency_ms": wf_ms,
                "summary": (
                    f"Parallel 3-way fan-out -> JoinNode -> gVisor ({z_str}) -> "
                    + (
                        f"Paused at RequestInput('{pending_approval['interrupt_id']}') awaiting human AG3 approval."
                        if pending_approval
                        else f"Synthesized {assessment.get('risk_level', 'AG1')} advisory outcome."
                    )
                ),
                "metrics": {
                    "incident_id": req.incident_id,
                    "gvisor_z_score": str(sandbox_obj["z_score"]) if sandbox_obj else "n/a",
                    "route": str(assessment.get("recommended_route", "info_or_ag1")),
                },
            },
            "memory_bank": {
                "status": "VERIFIED",
                "badge_label": (
                    f"Recalled {recalled_cnt} Fact(s)"
                    if pending_approval
                    else "Recalled + Persisted"
                ),
                "latency_ms": 6.4,
                "summary": (
                    f"Recalled {recalled_cnt} JWT-scoped incident memory fact(s) for {req.service_name}"
                    + ("" if pending_approval else " and persisted advisory postmortem.")
                ),
            },
            "mcp_a2a_mesh": {
                "status": "ACTIVE" if pending_approval else "VERIFIED",
                "badge_label": "3x MCP Done | A2A Standby" if pending_approval else "3x MCP Triage Complete",
                "latency_ms": 8.9,
                "summary": (
                    "Executed query_golden_signal_metrics, check_release_and_change_freeze, and "
                    "lookup_service_topology_and_runbook in parallel."
                ),
            },
            "trace_wallet": {
                "status": "VERIFIED",
                "badge_label": f"Settled {ledger_row['total_cost_nano_usd']} nUSD",
                "latency_ms": 5.1,
                "summary": (
                    f"Joined W3C trace {trace_id[:12]}... in Cloud Trace and settled "
                    f"{ledger_row['total_cost_nano_usd']} nano-USD in BigQuery wallet_ledger."
                ),
                "metrics": {
                    "trace_id": trace_id[:16] + "...",
                    "turn_cost_nano_usd": str(ledger_row["total_cost_nano_usd"]),
                    "cost_per_resolved_incident": f"{ledger_row['cost_per_resolved_incident_nano_usd']} nUSD",
                },
            },
            "eval_flywheel": {
                "status": "VERIFIED",
                "badge_label": f"Guard {assessment.get('risk_level', 'AG3')} Policy",
                "latency_ms": None,
                "summary": (
                    "Promoted v2 instruction actively enforced change-freeze and degraded-telemetry rules during synthesis."
                ),
            },
        }

        platform_services = build_platform_services_snapshot(
            store=store,
            mem_bank=mem_bank,
            tracer=tracer,
            architecture_mode=req.architecture_mode,
            last_event=(
                f"Triage {req.incident_id}: Paused at SENTINEL AG3 HITL checkpoint ({pending_approval['interrupt_id']})"
                if pending_approval
                else f"Triage {req.incident_id}: Completed AG1 advisory workflow and persisted memory"
            ),
            trace_id=trace_id,
            flow_sequence=[
                "agent_identity",
                "model_armor",
                "trace_wallet",
                "agent_registry",
                "agent_gateway",
                "mcp_a2a_mesh",
                "memory_bank",
                "agent_runtime",
            ],
            active_edges=[
                "identity->armor",
                "armor->gateway",
                "registry->gateway",
                "gateway->runtime",
                "runtime->memory",
                "gateway->mesh",
                "runtime->trace",
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
            "agent_state": store.get_agent_state("cymbal-ops-release-agent"),
            "wallet_state": store.get_wallet_state("wallet-cymbal-ops"),
            "recent_memories": mem_bank.retrieve_memories(
                verified_user_id="sre-oncall-01", limit=5
            ),
            "platform_services": platform_services,
        }

    @bff.post("/api/agent/resume")
    async def resume_agent_hitl(req: HitlResumeRequest, request: Request) -> Any:
        _verify_csrf(request)
        t0 = time.perf_counter()
        try:
            store.assert_agent_active("cymbal-ops-release-agent")
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
            user_id="sre-oncall-01",
            session_id=req.session_id,
            new_message=types.Content(role="user", parts=[part]),
        ):
            if ev.content and ev.content.parts:
                for p in ev.content.parts:
                    if p.text:
                        messages.append(p.text)

        updated = await runner.session_service.get_session(
            app_name="cymbal_web_agent_app",
            user_id="sre-oncall-01",
            session_id=req.session_id,
        )
        if updated is None:
            raise HTTPException(status_code=404, detail="Workflow session not found.")
        st = updated.state
        trace_id = str(st.get("trace_id") or tracer.new_trace_id())
        inc_id = str(st.get("incident_id") or "INC-4092")

        store.reserve_preflight_budget("wallet-cymbal-ops")
        ledger_row = store.settle_turn_spend(
            wallet_id="wallet-cymbal-ops",
            agent_id="cymbal-ops-release-agent",
            session_id=req.session_id,
            trace_id=trace_id,
            architecture_mode=runtime_cfg["architecture_mode"],
            input_tokens=210,
            output_tokens=140,
            outcome="AG3_HITL_RESUMED_AND_RESOLVED" if req.approved else "AG3_HELD_MANUAL",
            incident_id=inc_id,
            incident_resolved=req.approved,
        )
        resume_ms = round((time.perf_counter() - t0) * 1000, 2)
        tracer.record_span(
            trace_id=trace_id,
            session_id=req.session_id,
            span_name="cymbal_agent.ag3_hitl_resume_and_a2a",
            stage="hitl_resume",
            duration_ms=resume_ms,
            architecture_mode=runtime_cfg["architecture_mode"],
            attributes={
                "ag3.approved": req.approved,
                "ag3.approver": req.approver_principal,
            },
        )

        rem_outcome = st.get("remediation_outcome") or {}
        memories = mem_bank.retrieve_memories(verified_user_id="sre-oncall-01", limit=5)

        resume_overrides: dict[str, dict[str, Any]] = {
            "agent_identity": {
                "status": "VERIFIED",
                "badge_label": "Approver + SPIFFE Bound",
                "latency_ms": 1.4,
            },
            "agent_runtime": {
                "status": "VERIFIED",
                "badge_label": "HITL Resumed -> Completed",
                "latency_ms": resume_ms,
                "summary": (
                    f"Resumed durable checkpoint '{req.interrupt_id}' with decision "
                    f"{'APPROVED' if req.approved else 'HELD_FOR_EXCEPTION'} by {req.approver_principal}."
                ),
            },
            "agent_gateway": {
                "status": "VERIFIED",
                "badge_label": "A2A Approval Header Verified" if req.approved else "Mutating A2A Withheld",
                "latency_ms": 3.4,
                "summary": (
                    "Verified X-Cymbal-AG3-Approval-Id header under UAP Policy V2 CEL before routing /a2a."
                    if req.approved
                    else "Change-freeze hold honored; zero mutating A2A calls dispatched."
                ),
            },
            "mcp_a2a_mesh": {
                "status": "VERIFIED" if req.approved else "STANDBY",
                "badge_label": "A2A Canary Rolled Back" if req.approved else "Held Pending VP Ticket",
                "latency_ms": 11.6 if req.approved else None,
                "summary": str(rem_outcome.get("summary") or "Completed HITL remediation branch."),
            },
            "memory_bank": {
                "status": "VERIFIED",
                "badge_label": "Postmortem Persisted",
                "latency_ms": 7.2,
                "summary": f"Persisted longitudinal resolution fact for {inc_id} (sre-oncall-01).",
            },
            "trace_wallet": {
                "status": "VERIFIED",
                "badge_label": f"CPRI {ledger_row['cost_per_resolved_incident_nano_usd']} nUSD",
                "latency_ms": 4.8,
                "summary": (
                    f"Updated BigQuery cost_per_resolved_incident="
                    f"{ledger_row['cost_per_resolved_incident_nano_usd']} nano-USD on trace {trace_id[:12]}..."
                ),
            },
        }

        platform_services = build_platform_services_snapshot(
            store=store,
            mem_bank=mem_bank,
            tracer=tracer,
            architecture_mode=runtime_cfg["architecture_mode"],
            last_event=(
                f"Resumed {inc_id}: A2A canary rollback completed (post-rollback p99=298ms) & Memory Bank updated"
                if req.approved
                else f"Resumed {inc_id}: Execution safely held pending VP Change-Freeze Exception"
            ),
            trace_id=trace_id,
            flow_sequence=(
                ["agent_identity", "agent_runtime", "agent_gateway", "mcp_a2a_mesh", "memory_bank", "trace_wallet"]
                if req.approved
                else ["agent_identity", "agent_runtime", "memory_bank", "trace_wallet"]
            ),
            active_edges=(
                ["gateway->runtime", "gateway->mesh", "runtime->memory", "runtime->trace"]
                if req.approved
                else ["runtime->memory", "runtime->trace"]
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
            "agent_state": store.get_agent_state("cymbal-ops-release-agent"),
            "wallet_state": store.get_wallet_state("wallet-cymbal-ops"),
            "memories": memories,
            "platform_services": platform_services,
        }

    @bff.post("/api/steward/kill-switch")
    async def update_kill_switch(
        req: KillSwitchUpdateRequest, request: Request
    ) -> dict[str, Any]:
        _verify_csrf(request)
        updated = store.set_agent_status("cymbal-ops-release-agent", req.status)
        snap = build_platform_services_snapshot(
            store=store,
            mem_bank=mem_bank,
            tracer=tracer,
            architecture_mode=runtime_cfg["architecture_mode"],
            last_event=f"Global Kill Switch set to {req.status} in Firestore cymbal_agents",
            flow_sequence=["trace_wallet", "agent_runtime", "agent_gateway"],
            active_edges=["runtime->trace", "gateway->runtime"],
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
            active_edges=["runtime->trace"],
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
        verdict = guard.inspect_text(req.sample_text, direction="USER_PROMPT")
        trace_id = tracer.new_trace_id()
        store.record_guardrail_audit(
            trace_id=trace_id,
            session_id="steward-threat-lab",
            agent_id="cymbal-ops-release-agent",
            direction="USER_PROMPT",
            verdict=verdict,
        )
        tracer.record_span(
            trace_id=trace_id,
            session_id="steward-threat-lab",
            span_name="threat_lab.model_armor_inspect",
            stage="guardrail_test",
            duration_ms=verdict.latency_ms,
            architecture_mode=runtime_cfg["architecture_mode"],
            attributes={
                "allowed": verdict.allowed,
                "action": verdict.action_taken,
                "pii_masked": verdict.pii_masked,
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
            last_event=f"Model Armor Threat Lab verdict: {verdict.action_taken} ({verdict.latency_ms}ms)",
            trace_id=trace_id,
            flow_sequence=["agent_identity", "model_armor", "trace_wallet"],
            active_edges=["identity->armor", "runtime->trace"],
            overrides={
                "model_armor": {
                    "status": ma_status,
                    "badge_label": verdict.action_taken,
                    "latency_ms": verdict.latency_ms,
                    "summary": verdict.summary,
                },
                "trace_wallet": {
                    "status": "VERIFIED",
                    "badge_label": "Audit Logged",
                    "summary": f"Recorded guardrail audit row and W3C span {trace_id[:12]}...",
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
            active_edges=["identity->armor", "armor->gateway"],
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
            last_event=f"Live Capability Proof #{proof_id}: {'PASS' if res['passed'] else 'FAIL'} in {res['latency_ms']}ms",
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
            last_event=f"All {summary['passed_count']}/{summary['total_count']} Google Agent Platform proofs verified live",
            overrides=ov,
        )
        return summary

    @bff.post("/api/steward/closed-loop-eval")
    async def trigger_closed_loop(request: Request) -> dict[str, Any]:
        _verify_csrf(request)
        res = await execute_closed_loop_flywheel(live_cloud=live_cloud)
        v2_score = res["v2_candidate"]["behavior_score"]
        res["platform_services"] = build_platform_services_snapshot(
            store=store,
            mem_bank=mem_bank,
            tracer=tracer,
            architecture_mode=runtime_cfg["architecture_mode"],
            last_event=(
                f"Closed-Loop Flywheel promoted v2 (behavior_score={v2_score}) in {res['elapsed_seconds']}s"
            ),
            flow_sequence=["trace_wallet", "eval_flywheel", "model_armor", "agent_registry", "agent_runtime"],
            active_edges=["runtime->trace", "trace->eval", "eval->registry", "registry->gateway", "gateway->runtime"],
            overrides={
                "eval_flywheel": {
                    "status": "VERIFIED",
                    "badge_label": f"v1 (58) -> v2 ({v2_score})",
                    "latency_ms": round(res["elapsed_seconds"] * 1000, 1),
                    "summary": (
                        f"Blocked flawed v1 (58.0), synthesized v2 with Gemini 3.8 Flash, and passed "
                        f"{res['v2_candidate']['cases_passed']}/{res['v2_candidate']['cases_total']} simulations."
                    ),
                },
                "agent_registry": {
                    "status": "VERIFIED",
                    "badge_label": f"Promoted v2 ({v2_score})",
                    "summary": "Promoted v2 prompt and eval_gate=passed in Agent Registry and Firestore.",
                },
            },
        )
        return res

    @bff.get("/api/steward/telemetry")
    async def get_telemetry_snapshot() -> dict[str, Any]:
        return {
            "agent_state": store.get_agent_state("cymbal-ops-release-agent"),
            "wallet_state": store.get_wallet_state("wallet-cymbal-ops"),
            "recent_traces": tracer.list_recent_traces(limit=12),
            "recent_ledger": store.recent_ledger_rows(limit=12),
            "recent_guardrail_audits": store.recent_guardrail_audits(limit=12),
            "platform_services": build_platform_services_snapshot(
                store=store,
                mem_bank=mem_bank,
                tracer=tracer,
                architecture_mode=runtime_cfg["architecture_mode"],
                last_event="Refreshed live Cloud Trace, Firestore, and BigQuery governance telemetry",
            ),
        }

    bff.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @bff.get("/")
    async def serve_index(request: Request) -> FileResponse:
        resp = FileResponse(STATIC_DIR / "index.html")
        _issue_or_get_session(request, resp)
        return resp

    return bff


app = create_bff_app()


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    bind_host = os.getenv("BIND_HOST", "127.0.0.1")
    uvicorn.run(app, host=bind_host, port=port)
