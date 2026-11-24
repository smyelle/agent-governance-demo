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

"""FastAPI Backend-for-Frontend (BFF) serving Copilot & Steward Console views.

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

from evals.run_beyond_scape_proofs import (  # noqa: E402
    calculate_guardrail_tco,
    run_all_beyond_scape_proofs,
    run_single_proof,
)
from evals.run_closed_loop_eval import execute_closed_loop_flywheel  # noqa: E402
from scape_agent.agent import build_scape_workflow  # noqa: E402
from scape_agent.governance.gcp_auth import get_gcp_credentials  # noqa: E402
from scape_agent.governance.identity_obo import (  # noqa: E402
    fetch_cloud_run_id_token,
    inspect_zero_secret_posture,
    mint_demo_adr011_token_pair,
    verify_adr011_dual_tokens,
)
from scape_agent.governance.model_armor_guard import (  # noqa: E402
    FailClosedModelArmorGuard,
    ModelArmorBlockedError,
)
from scape_agent.governance.plugin import ScapeGovernancePlugin  # noqa: E402
from scape_agent.governance.telemetry_bridge import UnifiedTraceBridge  # noqa: E402
from scape_agent.governance.wallet_ledger import (  # noqa: E402
    AtomicWalletAndGovernanceStore,
    KillSwitchHaltedError,
    WalletBudgetExceededError,
)
from scape_agent.memory.memory_bank import ScopedMemoryBankClient  # noqa: E402
from scape_agent.tenant import list_available_profiles, load_tenant_profile  # noqa: E402

logger = logging.getLogger("scape_web_bff")
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("google_genai").setLevel(logging.WARNING)
logging.getLogger("google_adk").setLevel(logging.WARNING)

STATIC_DIR = Path(__file__).resolve().parent / "static"
PROMPTS_DIR = REPO_ROOT / "config" / "prompts"

FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
    '<rect width="32" height="32" rx="7" fill="#2563eb"/>'
    '<path d="M16 6l8 4v6c0 5.5-3.4 9.7-8 11-4.6-1.3-8-5.5-8-11v-6l8-4z" fill="#ffffff"/>'
    "</svg>"
)


def _resolve_session_hmac_secret() -> bytes:
    env_secret = os.getenv("SCAPE_BFF_SESSION_SECRET")
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
_RATE_LIMIT_MAX_REQUESTS = 180
_RATE_LIMIT_WINDOW_SEC = 60.0

# TODO(security): Integrate enterprise OIDC SSO + MFA enforcement at Cloud IAP / Load Balancer
# front door when promoting beyond isolated sandbox evaluations.


class TriageStartRequest(BaseModel):
    incident_id: str = Field(default="INC-4092", pattern=r"^INC-\d{4}$")
    service_name: str = Field(default="flow-intel-api", min_length=2, max_length=80)
    app_id: str = Field(default="DEVHUB-SCAPE-992", min_length=3, max_length=64)
    operator_prompt: str = Field(..., min_length=4, max_length=2000)
    scape_mode: Literal["google_native", "comcast_hybrid"] = "google_native"
    tenant_profile: str = Field(default="comcast_devx", min_length=2, max_length=64)


class HitlResumeRequest(BaseModel):
    session_id: str = Field(..., min_length=4, max_length=128)
    interrupt_id: str = Field(..., min_length=4, max_length=128)
    approved: bool
    approver_principal: str = Field(default="sre-oncall-lead", min_length=2, max_length=80)
    vp_exception_ticket: str | None = Field(default=None, max_length=64)
    reason: str = Field(default="Reviewed correlated telemetry and blast radius.", max_length=400)


class ModeSwitchRequest(BaseModel):
    scape_mode: Literal["google_native", "comcast_hybrid"]
    tenant_profile: str = Field(default="comcast_devx", min_length=2, max_length=64)


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
        "title": "Bifrost ModelGW p99 Latency & Valkey usage:0 Saturation",
        "service_name": "flow-intel-api",
        "app_id": "DEVHUB-SCAPE-992",
        "severity": "SEV-1 / AG3",
        "default_prompt": (
            "Investigate INC-4092: flow-intel-api Bifrost modelgw p99 latency spiked to 4,820ms "
            "with Valkey usage:0 stream memory at 94.6% after release v2.14.3."
        ),
    },
    {
        "incident_id": "INC-4095",
        "title": "Settlement Webhook Timeout During Enterprise Change Freeze",
        "service_name": "billing-webhook-router",
        "app_id": "DEVHUB-BILL-710",
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
        "app_id": "DEVHUB-EDGE-305",
        "severity": "SEV-3 / AG1 + SDP",
        "default_prompt": (
            "Triage INC-4099 on edge-session-ingestor. Raw pasted log snippet: subscriber SSN "
            "123-45-6789 on CPE MAC aa:bb:cc:dd:ee:ff saw minor 890ms jitter."
        ),
    },
]


def create_bff_app(*, offline_mode: bool | None = None) -> FastAPI:
    if offline_mode is None:
        offline_mode = os.getenv("SCAPE_BFF_OFFLINE", "false").lower() in {"1", "true", "yes"}

    live_cloud = not offline_mode
    if live_cloud:
        # Pre-warm CLI OAuth & OIDC tokens once before any gRPC channel opens so
        # request handlers never fork child subprocesses while gRPC pollsets exist.
        try:
            get_gcp_credentials()
            a2a_url = os.getenv("SCAPE_A2A_URL", "")
            if a2a_url:
                fetch_cloud_run_id_token(a2a_url)
        except Exception:
            pass

    store = AtomicWalletAndGovernanceStore(in_memory_only=offline_mode)
    guard = FailClosedModelArmorGuard(live_api_enabled=live_cloud)
    tracer = UnifiedTraceBridge(cloud_trace_enabled=live_cloud)
    mem_bank = ScopedMemoryBankClient(in_memory_only=offline_mode)
    plugin = ScapeGovernancePlugin(store=store, guard=guard, tracer=tracer)
    wf = build_scape_workflow(
        memory_bank=mem_bank,
        use_live_llm=False,
    )
    copilot_adk_app = App(
        name="scape_web_copilot_app",
        root_agent=wf,
        resumability_config=ResumabilityConfig(is_resumable=True),
        plugins=[plugin],
    )
    runner = InMemoryRunner(app=copilot_adk_app)

    runtime_cfg: dict[str, str] = {
        "scape_mode": os.getenv("SCAPE_MODE", "google_native"),
        "tenant_profile": os.getenv("SCAPE_TENANT_PROFILE", ""),
    }

    bff = FastAPI(
        title="SCAPE & Google Agent Platform Reference UI",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
    )

    def _issue_or_get_session(request: Request, response: Response) -> tuple[str, str]:
        is_https = request.url.scheme == "https"
        cookie_name = "__Host-scape_sid" if is_https else "scape_sid"
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
        cookie_name = "__Host-scape_sid" if is_https else "scape_sid"
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
        return {"status": "ok", "service": "scape-steward-web"}

    @bff.get("/favicon.ico")
    async def favicon() -> Response:
        return Response(content=FAVICON_SVG, media_type="image/svg+xml")

    @bff.get("/api/bootstrap")
    async def bootstrap(request: Request, response: Response) -> dict[str, Any]:
        _, csrf_token = _issue_or_get_session(request, response)
        profile = load_tenant_profile(
            profile_override=runtime_cfg["tenant_profile"] or None
        )
        pointer_path = PROMPTS_DIR / "active_version.json"
        pointer = (
            json.loads(pointer_path.read_text(encoding="utf-8"))
            if pointer_path.is_file()
            else {"active_version": "v2", "behavior_score": 96.2}
        )
        v1_txt = (PROMPTS_DIR / "synthesizer_v1_flawed.txt").read_text(encoding="utf-8")
        v2_txt = (PROMPTS_DIR / "synthesizer_v2_optimized.txt").read_text(encoding="utf-8")

        return {
            "csrf_token": csrf_token,
            "scape_mode": runtime_cfg["scape_mode"],
            "available_profiles": list_available_profiles(),
            "tenant": profile.model_dump(),
            "incidents": INCIDENT_PRESETS,
            "agent_state": store.get_agent_state("devx-incident-copilot"),
            "wallet_state": store.get_wallet_state("wallet-devx-ops"),
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
        }

    @bff.post("/api/config/mode")
    async def switch_mode(req: ModeSwitchRequest, request: Request) -> dict[str, Any]:
        _verify_csrf(request)
        profile = load_tenant_profile(profile_override=req.tenant_profile)
        runtime_cfg["scape_mode"] = req.scape_mode
        runtime_cfg["tenant_profile"] = req.tenant_profile
        return {
            "scape_mode": runtime_cfg["scape_mode"],
            "tenant": profile.model_dump(),
        }

    @bff.post("/api/copilot/triage")
    async def start_copilot_triage(req: TriageStartRequest, request: Request) -> dict[str, Any]:
        _verify_csrf(request)
        t0 = time.perf_counter()
        try:
            store.assert_agent_active("devx-incident-copilot")
            store.reserve_preflight_budget("wallet-devx-ops")
            verdict = guard.inspect_text(req.operator_prompt, direction="USER_PROMPT")
            trace_id = tracer.new_trace_id()
            sess_preview_id = f"sess-{trace_id[:10]}"
            store.record_guardrail_audit(
                trace_id=trace_id,
                session_id=sess_preview_id,
                agent_id="devx-incident-copilot",
                direction="USER_PROMPT",
                verdict=verdict,
            )
            if not verdict.allowed:
                raise ModelArmorBlockedError(verdict.summary, verdict)
        except KillSwitchHaltedError as exc:
            raise HTTPException(status_code=423, detail=str(exc)) from exc
        except WalletBudgetExceededError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ModelArmorBlockedError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        init_state: dict[str, Any] = {
            "incident_id": req.incident_id,
            "service_name": req.service_name,
            "app_id": req.app_id,
            "scape_mode": req.scape_mode,
            "trace_id": trace_id,
        }
        if req.scape_mode == "comcast_hybrid":
            t_gw, t_mcp = mint_demo_adr011_token_pair()
            init_state["authorization_bearer"] = t_gw
            init_state["x_user_authorization_bearer"] = t_mcp

        session = await runner.session_service.create_session(
            app_name="scape_web_copilot_app",
            user_id="sre-oncall-01",
            state=init_state,
        )

        stream_messages: list[str] = []
        pending_approval: dict[str, Any] | None = None

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

        updated = await runner.session_service.get_session(
            app_name="scape_web_copilot_app",
            user_id="sre-oncall-01",
            session_id=session.id,
        )
        st = updated.state if updated else {}

        ledger_row = store.settle_turn_spend(
            wallet_id="wallet-devx-ops",
            agent_id="devx-incident-copilot",
            session_id=session.id,
            trace_id=trace_id,
            scape_mode=req.scape_mode,
            input_tokens=520,
            output_tokens=260,
            outcome="COPILOT_TRIAGE_SYNTHESIZED",
            incident_id=req.incident_id,
            incident_resolved=pending_approval is None,
        )
        tracer.record_span(
            trace_id=trace_id,
            session_id=session.id,
            span_name="copilot.workflow_triage",
            stage="adk_workflow_graph",
            duration_ms=(time.perf_counter() - t0) * 1000,
            scape_mode=req.scape_mode,
            devhub_app_id=req.app_id,
            attributes={
                "incident.id": req.incident_id,
                "hitl.paused": pending_approval is not None,
                "pii.masked_inline": verdict.pii_masked,
            },
        )

        return {
            "session_id": session.id,
            "trace_id": trace_id,
            "status": "WAITING_AG3_APPROVAL" if pending_approval else "COMPLETED",
            "pii_masked_inline": verdict.pii_masked,
            "sanitized_prompt": verdict.sanitized_text,
            "stream_messages": stream_messages,
            "correlated_bundle": st.get("correlated_bundle_dict"),
            "sandbox_anomaly": (
                json.loads(st["sandbox_anomaly_summary"])
                if st.get("sandbox_anomaly_summary")
                else None
            ),
            "assessment": st.get("incident_assessment"),
            "pending_approval": pending_approval,
            "remediation_outcome": st.get("remediation_outcome"),
            "postmortem_record": st.get("postmortem_record"),
            "wallet_settlement": ledger_row,
        }

    @bff.post("/api/copilot/resume")
    async def resume_copilot_hitl(req: HitlResumeRequest, request: Request) -> dict[str, Any]:
        _verify_csrf(request)
        t0 = time.perf_counter()
        try:
            store.assert_agent_active("devx-incident-copilot")
        except KillSwitchHaltedError as exc:
            raise HTTPException(status_code=423, detail=str(exc)) from exc

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
            app_name="scape_web_copilot_app",
            user_id="sre-oncall-01",
            session_id=req.session_id,
        )
        if updated is None:
            raise HTTPException(status_code=404, detail="Workflow session not found.")
        st = updated.state
        trace_id = str(st.get("trace_id") or tracer.new_trace_id())
        inc_id = str(st.get("incident_id") or "INC-4092")

        store.reserve_preflight_budget("wallet-devx-ops")
        ledger_row = store.settle_turn_spend(
            wallet_id="wallet-devx-ops",
            agent_id="devx-incident-copilot",
            session_id=req.session_id,
            trace_id=trace_id,
            scape_mode=runtime_cfg["scape_mode"],
            input_tokens=210,
            output_tokens=140,
            outcome="AG3_HITL_RESUMED_AND_RESOLVED" if req.approved else "AG3_HELD_MANUAL",
            incident_id=inc_id,
            incident_resolved=req.approved,
        )
        tracer.record_span(
            trace_id=trace_id,
            session_id=req.session_id,
            span_name="copilot.ag3_hitl_resume_and_a2a",
            stage="hitl_resume",
            duration_ms=(time.perf_counter() - t0) * 1000,
            scape_mode=runtime_cfg["scape_mode"],
            attributes={
                "ag3.approved": req.approved,
                "ag3.approver": req.approver_principal,
            },
        )
        return {
            "session_id": req.session_id,
            "trace_id": trace_id,
            "status": "COMPLETED",
            "stream_messages": messages,
            "remediation_outcome": st.get("remediation_outcome"),
            "postmortem_record": st.get("postmortem_record"),
            "wallet_settlement": ledger_row,
            "memories": mem_bank.retrieve_memories(verified_user_id="sre-oncall-01", limit=5),
        }

    @bff.post("/api/steward/kill-switch")
    async def update_kill_switch(
        req: KillSwitchUpdateRequest, request: Request
    ) -> dict[str, Any]:
        _verify_csrf(request)
        updated = store.set_agent_status("devx-incident-copilot", req.status)
        return {"agent_state": updated}

    @bff.post("/api/steward/wallet-cap")
    async def update_wallet_cap(req: WalletCapUpdateRequest, request: Request) -> dict[str, Any]:
        _verify_csrf(request)
        updated = store.update_wallet_cap(
            "wallet-devx-ops",
            monthly_cap_nano_usd=req.monthly_cap_nano_usd,
            reset_spend=req.reset_spend,
        )
        return {"wallet_state": updated}

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
            agent_id="devx-incident-copilot",
            direction="USER_PROMPT",
            verdict=verdict,
        )
        tracer.record_span(
            trace_id=trace_id,
            session_id="steward-threat-lab",
            span_name="threat_lab.model_armor_inspect",
            stage="guardrail_test",
            duration_ms=verdict.latency_ms,
            scape_mode=runtime_cfg["scape_mode"],
            attributes={
                "allowed": verdict.allowed,
                "action": verdict.action_taken,
                "pii_masked": verdict.pii_masked,
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
        return {
            "adr011_valid_pair": valid_res,
            "mismatched_azp_blocked_fail_closed": forged_blocked,
        }

    @bff.post("/api/steward/proofs/{proof_id}")
    async def trigger_single_proof(proof_id: int, request: Request) -> dict[str, Any]:
        _verify_csrf(request)
        if proof_id < 1 or proof_id > 8:
            raise HTTPException(status_code=400, detail="proof_id must be 1..8")
        return await run_single_proof(proof_id, live_cloud=live_cloud)

    @bff.post("/api/steward/proofs-all")
    async def trigger_all_proofs(request: Request) -> dict[str, Any]:
        _verify_csrf(request)
        return await run_all_beyond_scape_proofs(live_cloud=live_cloud)

    @bff.post("/api/steward/closed-loop-eval")
    async def trigger_closed_loop(request: Request) -> dict[str, Any]:
        _verify_csrf(request)
        return await execute_closed_loop_flywheel(live_cloud=live_cloud)

    @bff.get("/api/steward/telemetry")
    async def get_telemetry_snapshot() -> dict[str, Any]:
        return {
            "agent_state": store.get_agent_state("devx-incident-copilot"),
            "wallet_state": store.get_wallet_state("wallet-devx-ops"),
            "recent_traces": tracer.list_recent_traces(limit=12),
            "recent_ledger": store.recent_ledger_rows(limit=12),
            "recent_guardrail_audits": store.recent_guardrail_audits(limit=12),
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
