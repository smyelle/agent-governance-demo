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

"""ADK 2.0 `CymbalGovernancePlugin(BasePlugin)` enforcing unified platform controls.

Enforces across both `CYMBAL_PLATFORM_MODE=google_native` and `enterprise_hybrid`:
1. Zero-Bypass Kill Switch (`ACTIVE` / `PAUSED` / `DISABLED`) across model, MCP, and A2A.
2. Zero-Secret `AGENT_IDENTITY` posture + `ADR-011` dual-token `azp` correlation.
3. Atomic nano-USD Wallet preflight reservation (`HTTP 403 budget_exceeded`) +
   exact post-model BigQuery `wallet_ledger` settlement.
4. 3-step NFKC/Base64/Hex unpacker + inline Cloud SDP PII masking + fail-closed
   Model Armor `sanitize_user_prompt` / `sanitize_model_response` (skipping
   internal `part.thought == True` parts).
5. UAP Policy V2 CEL per-tool authorization parity (`read_only_hint == true` vs
   principal-scoped mutating tools vs blocked `destructive_hint == true` tools).
"""

from __future__ import annotations

import os
import time
from typing import Any

from google.adk.plugins.base_plugin import BasePlugin
from google.genai import types

from cymbal_agent.governance.identity_obo import (
    inspect_zero_secret_posture,
    verify_adr011_dual_tokens,
)
from cymbal_agent.governance.model_armor_guard import (
    FailClosedModelArmorGuard,
    ModelArmorBlockedError,
)
from cymbal_agent.governance.telemetry_bridge import UnifiedTraceBridge
from cymbal_agent.governance.wallet_ledger import (
    AtomicWalletAndGovernanceStore,
    DEFAULT_PREFLIGHT_RESERVATION_NANO_USD,
)

READ_ONLY_MCP_TOOLS = frozenset(
    {
        "",
        "inspect_candidate_agent_manifest",
        "verify_tier1_intake_and_supergraph",
        "fetch_production_otel_traces",
        "query_golden_signal_metrics",
        "check_release_and_change_freeze",
        "lookup_service_topology_and_runbook",
    }
)
SCOPED_NON_DESTRUCTIVE_TOOLS = frozenset(
    {
        "record_compliance_evidence_note",
        "annotate_incident_ticket",
    }
)
DESTRUCTIVE_MCP_TOOLS = frozenset(
    {
        "force_bypass_governance_gate",
        "purge_production_valkey_stream",
    }
)


class UapToolPolicyDeniedError(PermissionError):
    """HTTP 403 PERMISSION_DENIED raised when UAP Policy V2 CEL denies a tool call."""

    def __init__(self, tool_name: str, principal: str, rule_id: str) -> None:
        self.status_code = 403
        self.tool_name = tool_name
        self.principal = principal
        self.rule_id = rule_id
        super().__init__(
            f"403 PERMISSION_DENIED (UAP Policy V2 CEL rule '{rule_id}'): "
            f"Tool '{tool_name}' denied for principal '{principal}' despite coarse mcp.use scope."
        )


def evaluate_uap_cel_tool_policy(
    tool_name: str,
    principal: str = "spiffe://cymbal-agent-platform.svc.id.goog/ns/agent-runtime/sa/cymbal-ops-release-agent",
    read_only_hint: bool | None = None,
    destructive_hint: bool | None = None,
) -> dict[str, Any]:
    """Deterministic evaluator matching infra/manifests/uap_project_policy.json."""
    clean = (tool_name or "").strip()
    is_read_only = read_only_hint if read_only_hint is not None else (clean in READ_ONLY_MCP_TOOLS)
    is_destructive = (
        destructive_hint if destructive_hint is not None else (clean in DESTRUCTIVE_MCP_TOOLS)
    )

    if clean == "" or is_read_only:
        return {
            "allowed": True,
            "rule_id": "allow-mcp-handshake-and-readonly-tools",
            "tool_name": clean,
        }

    if is_destructive:
        raise UapToolPolicyDeniedError(
            tool_name=clean,
            principal=principal,
            rule_id="deny-destructive-mcp-tools-by-default",
        )

    if clean in SCOPED_NON_DESTRUCTIVE_TOOLS and "cymbal-ops-release-agent" in principal:
        return {
            "allowed": True,
            "rule_id": "allow-scoped-incident-annotation",
            "tool_name": clean,
        }

    raise UapToolPolicyDeniedError(
        tool_name=clean,
        principal=principal,
        rule_id="default-zero-trust-deny",
    )


class CymbalGovernancePlugin(BasePlugin):
    """Unified ADK 2.0 governance plugin for model, tool, identity, and wallet gates."""

    def __init__(
        self,
        *,
        name: str = "cymbal_governance_plugin",
        store: AtomicWalletAndGovernanceStore | None = None,
        guard: FailClosedModelArmorGuard | None = None,
        tracer: UnifiedTraceBridge | None = None,
        agent_id: str = "cymbal-ops-release-agent",
        wallet_id: str = "wallet-cymbal-ops",
        architecture_mode: str | None = None,
    ) -> None:
        super().__init__(name=name)
        self.store = store or AtomicWalletAndGovernanceStore()
        self.guard = guard or FailClosedModelArmorGuard()
        self.tracer = tracer or UnifiedTraceBridge()
        self.agent_id = agent_id
        self.wallet_id = wallet_id
        self._default_mode = architecture_mode or os.getenv(
            "CYMBAL_PLATFORM_MODE", "enterprise_hybrid"
        )

    def _active_mode(self, state: Any = None) -> str:
        if state and isinstance(state, dict) and state.get("architecture_mode"):
            return str(state["architecture_mode"])
        return os.getenv("CYMBAL_PLATFORM_MODE", self._default_mode)

    def _ensure_trace_id(self, state: Any) -> str:
        try:
            if "trace_id" not in state or not state["trace_id"]:
                state["trace_id"] = self.tracer.new_trace_id()
            return str(state["trace_id"])
        except Exception:
            return self.tracer.new_trace_id()

    async def before_run_callback(self, *, invocation_context: Any) -> types.Content | None:
        t0 = time.perf_counter()
        session = getattr(invocation_context, "session", None)
        state = getattr(session, "state", {}) if session is not None else {}
        session_id = getattr(session, "id", "session-local")
        trace_id = self._ensure_trace_id(state)
        mode = self._active_mode(state)

        agent_doc = self.store.assert_agent_active(self.agent_id)
        posture = inspect_zero_secret_posture(agent_id=self.agent_id)
        state["zero_secret_posture"] = posture.summary
        state["spiffe_id"] = posture.spiffe_id

        if mode == "enterprise_hybrid":
            t_gw = state.get("authorization_bearer")
            t_mcp = state.get("x_user_authorization_bearer")
            if t_gw and t_mcp:
                obo_res = verify_adr011_dual_tokens(str(t_gw), str(t_mcp))
                state["adr011_verification"] = obo_res

        self.tracer.record_span(
            trace_id=trace_id,
            session_id=session_id,
            span_name="governance.before_run_gate",
            stage="kill_switch_and_identity",
            duration_ms=(time.perf_counter() - t0) * 1000,
            architecture_mode=mode,
            attributes={
                "cymbal.agent_id": self.agent_id,
                "cymbal.agent_status": agent_doc.get("status", "ACTIVE"),
                "cymbal.spiffe_id": posture.spiffe_id,
                "cymbal.zero_secret_compliant": posture.zero_secret_compliant,
            },
        )
        return None

    async def before_agent_callback(
        self, *, agent: Any, callback_context: Any
    ) -> types.Content | None:
        self.store.assert_agent_active(self.agent_id)
        return None

    async def before_model_callback(
        self, *, callback_context: Any, llm_request: Any
    ) -> Any:
        t0 = time.perf_counter()
        state = getattr(callback_context, "state", {})
        session_id = getattr(getattr(callback_context, "session", None), "id", "session-local")
        trace_id = self._ensure_trace_id(state)
        mode = self._active_mode(state)

        self.store.assert_agent_active(self.agent_id)

        # 1. Atomic pre-flight budget reservation (strict fail-closed HTTP 403)
        reservation_id = self.store.reserve_preflight_budget(
            wallet_id=self.wallet_id,
            reserve_nano_usd=DEFAULT_PREFLIGHT_RESERVATION_NANO_USD,
        )
        state["last_wallet_reservation_id"] = reservation_id

        # 2. Extract non-thought user prompt text, scrub PII inline, and run fail-closed Model Armor
        dynamic_policy = state.get("dynamic_guardrail_policy")
        collected_texts: list[str] = []
        for content in getattr(llm_request, "contents", None) or []:
            for part in getattr(content, "parts", None) or []:
                if getattr(part, "thought", False):
                    continue
                if getattr(part, "text", None):
                    txt = str(part.text)
                    verdict = self.guard.inspect_text(
                        txt,
                        direction="USER_PROMPT",
                        dynamic_policy=dynamic_policy,
                    )
                    self.store.record_guardrail_audit(
                        trace_id=trace_id,
                        session_id=session_id,
                        agent_id=self.agent_id,
                        direction="USER_PROMPT",
                        verdict=verdict,
                    )
                    if not verdict.allowed:
                        self.tracer.record_span(
                            trace_id=trace_id,
                            session_id=session_id,
                            span_name="governance.model_armor.prompt_blocked",
                            stage="guardrail_block",
                            duration_ms=(time.perf_counter() - t0) * 1000,
                            architecture_mode=mode,
                            attributes={
                                "guardrail.template": verdict.template_id,
                                "guardrail.action": verdict.action_taken,
                                "guardrail.injection": verdict.injection_detected,
                                "guardrail.malicious_uri": verdict.malicious_uri_detected,
                            },
                        )
                        raise ModelArmorBlockedError(verdict.summary, verdict)
                    if verdict.pii_masked:
                        part.text = verdict.sanitized_text
                        state["pii_masked_inline"] = True
                    collected_texts.append(part.text)

        # 3. Hybrid gateway passthrough: set adjustable Gemini safety_settings=OFF so
        # Model Armor acts as the single deterministic policy plane without double-filtering.
        if mode == "enterprise_hybrid" and getattr(llm_request, "config", None) is not None:
            llm_request.config.safety_settings = [
                types.SafetySetting(
                    category=types.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
                    threshold=types.HarmBlockThreshold.OFF,
                ),
                types.SafetySetting(
                    category=types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
                    threshold=types.HarmBlockThreshold.OFF,
                ),
                types.SafetySetting(
                    category=types.HarmCategory.HARM_CATEGORY_HARASSMENT,
                    threshold=types.HarmBlockThreshold.OFF,
                ),
                types.SafetySetting(
                    category=types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
                    threshold=types.HarmBlockThreshold.OFF,
                ),
            ]
            state["hybrid_gateway_safety_off_applied"] = True

        self.tracer.record_span(
            trace_id=trace_id,
            session_id=session_id,
            span_name="governance.before_model_guard",
            stage="wallet_preflight_and_model_armor",
            duration_ms=(time.perf_counter() - t0) * 1000,
            architecture_mode=mode,
            attributes={
                "wallet.reservation_id": reservation_id,
                "prompt.segments_scanned": len(collected_texts),
                "cymbal.hybrid_safety_off": mode == "enterprise_hybrid",
            },
        )
        return None

    async def after_model_callback(
        self, *, callback_context: Any, llm_response: Any
    ) -> Any:
        t0 = time.perf_counter()
        state = getattr(callback_context, "state", {})
        session_id = getattr(getattr(callback_context, "session", None), "id", "session-local")
        trace_id = self._ensure_trace_id(state)
        mode = self._active_mode(state)

        content = getattr(llm_response, "content", None)
        for part in getattr(content, "parts", None) or []:
            if getattr(part, "thought", False):
                continue
            if getattr(part, "text", None):
                verdict = self.guard.inspect_text(
                    str(part.text),
                    direction="MODEL_RESPONSE",
                    block_malicious_urls_inline_mask_only=True,
                )
                self.store.record_guardrail_audit(
                    trace_id=trace_id,
                    session_id=session_id,
                    agent_id=self.agent_id,
                    direction="MODEL_RESPONSE",
                    verdict=verdict,
                )
                if not verdict.allowed:
                    raise ModelArmorBlockedError(verdict.summary, verdict)
                if verdict.pii_masked or verdict.malicious_uri_detected:
                    part.text = verdict.sanitized_text

        usage = getattr(llm_response, "usage_metadata", None)
        in_tok = int(getattr(usage, "prompt_token_count", 0) or 180)
        out_tok = int(getattr(usage, "candidates_token_count", 0) or 120)
        incident_id = str(state.get("incident_id", "INC-4092"))

        ledger_row = self.store.settle_turn_spend(
            wallet_id=self.wallet_id,
            agent_id=self.agent_id,
            session_id=session_id,
            trace_id=trace_id,
            architecture_mode=mode,
            model_id=os.getenv("GEMINI_MODEL", "gemini-3.8-flash"),
            input_tokens=in_tok,
            output_tokens=out_tok,
            outcome="MODEL_INFERENCE_SETTLED",
            incident_id=incident_id,
            incident_resolved=False,
        )
        state["last_wallet_settlement"] = ledger_row

        self.tracer.record_span(
            trace_id=trace_id,
            session_id=session_id,
            span_name="gen_ai.model_inference_and_settlement",
            stage="after_model_settlement",
            duration_ms=(time.perf_counter() - t0) * 1000,
            architecture_mode=mode,
            attributes={
                "gen_ai.request.model": ledger_row["model_id"],
                "gen_ai.usage.input_tokens": in_tok,
                "gen_ai.usage.output_tokens": out_tok,
                "wallet.total_cost_nano_usd": ledger_row["total_cost_nano_usd"],
            },
        )
        return None

    async def before_tool_callback(
        self, *, tool: Any, tool_args: dict[str, Any], tool_context: Any
    ) -> dict[str, Any] | None:
        t0 = time.perf_counter()
        state = getattr(tool_context, "state", {})
        session_id = getattr(getattr(tool_context, "session", None), "id", "session-local")
        trace_id = self._ensure_trace_id(state)
        mode = self._active_mode(state)

        self.store.assert_agent_active(self.agent_id)

        tool_name = getattr(tool, "name", "") or ""
        principal = str(
            state.get(
                "spiffe_id",
                f"spiffe://cymbal-agent-platform.svc.id.goog/ns/agent-runtime/sa/{self.agent_id}",
            )
        )
        decision = evaluate_uap_cel_tool_policy(tool_name=tool_name, principal=principal)

        self.tracer.record_span(
            trace_id=trace_id,
            session_id=session_id,
            span_name=f"uap.tool_authz.{tool_name or 'mcp_handshake'}",
            stage="uap_cel_tool_gate",
            duration_ms=(time.perf_counter() - t0) * 1000,
            architecture_mode=mode,
            attributes={
                "mcp.tool.name": tool_name,
                "uap.rule_id": decision["rule_id"],
                "uap.allowed": decision["allowed"],
            },
        )
        return None
