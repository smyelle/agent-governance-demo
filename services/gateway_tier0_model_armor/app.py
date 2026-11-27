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

"""Standalone OpenAI-Compatible Tier-0 Model Armor HTTP Middleware Adapter.

Provides:
- `GET /healthz`: Adapter health and fail-closed readiness probe.
- `POST /v1/guardrails/compile-policy`: Compiles dynamic per-request policies
  onto the 3-tier Model Armor base template pool (blocking `AG5` with HTTP 403).
- `POST /v1/guardrails/prefilter`: Standalone Tier-0 pre-filter hook for AI
  gateways, inspecting the latest `user` turn plus non-`user`/trailing turns
  from OpenAI `messages[]` (`skip_thoughts=False`).
- `POST /v1/guardrails/inspect-response`: Inspects downstream LLM completions,
  stripping `thought: true` parts and scanning/masking visible response parts.
- `POST /v1/chat/completions`: OpenAI-compatible reverse-proxy middleware that
  enforces Tier-0 input pre-filtering, optional secondary ensemble escalation,
  and output inspection with strict SSRF host allowlisting.
"""

from __future__ import annotations

from dataclasses import asdict
import os
from typing import Any
import urllib.parse

from fastapi import Body, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
import httpx
from pydantic import BaseModel, Field
import uvicorn

try:
    from .guard_core import (
        DynamicGuardrailPolicyPayload,
        FailClosedModelArmorGuard,
        GuardrailVerdict,
        ProhibitedAgencyTierError,
        compile_dynamic_policy_to_base_template,
    )
except ImportError:
    from guard_core import (  # type: ignore[no-redef]
        DynamicGuardrailPolicyPayload,
        FailClosedModelArmorGuard,
        GuardrailVerdict,
        ProhibitedAgencyTierError,
        compile_dynamic_policy_to_base_template,
    )


class PrefilterRequest(BaseModel):
    text: str | None = None
    messages: list[dict[str, Any]] | None = None
    dynamic_policy: DynamicGuardrailPolicyPayload | None = None


class InspectResponseRequest(BaseModel):
    text: str | None = None
    choices: list[dict[str, Any]] | None = None
    messages: list[dict[str, Any]] | None = None
    dynamic_policy: DynamicGuardrailPolicyPayload | None = None
    block_malicious_urls_inline_mask_only: bool = True


class ChatCompletionProxyRequest(BaseModel):
    model: str = Field(default="gemini-3.8-flash")
    messages: list[dict[str, Any]]
    dynamic_policy: DynamicGuardrailPolicyPayload | None = None
    temperature: float | None = None
    max_tokens: int | None = None
    stream: bool = False
    metadata: dict[str, Any] | None = None

    model_config = {"extra": "allow"}


def _expose_policy_ids() -> bool:
    return os.getenv("EXPOSE_POLICY_IDS", "false").lower() in {"1", "true", "yes"}


def _serialize_verdict(verdict: GuardrailVerdict) -> dict[str, Any]:
    data = asdict(verdict)
    if not _expose_policy_ids():
        data["template_id"] = f"redacted:{verdict.resolved_tier}"
    return data


def _build_policy_from_headers_and_body(
    body_policy: DynamicGuardrailPolicyPayload | None,
    *,
    x_business_unit: str | None = None,
    x_risk_tier: str | None = None,
    x_sdp_pii_mode: str | None = None,
    x_ensemble_role: str | None = None,
) -> DynamicGuardrailPolicyPayload:
    base = body_policy.model_dump() if body_policy is not None else {}
    if x_business_unit and x_business_unit.strip():
        base["business_unit"] = x_business_unit.strip()
    if x_risk_tier and x_risk_tier.strip():
        base["risk_tier"] = x_risk_tier.strip().upper()
    if x_sdp_pii_mode and x_sdp_pii_mode.strip():
        base["sdp_pii_mode"] = x_sdp_pii_mode.strip().upper()
    if x_ensemble_role and x_ensemble_role.strip():
        base["ensemble_role"] = x_ensemble_role.strip()
    return DynamicGuardrailPolicyPayload.model_validate(base)


def _strip_thought_parts(content: Any) -> Any:
    """Recursively removes any dict item with thought=True from list/dict content."""
    if isinstance(content, list):
        cleaned: list[Any] = []
        for item in content:
            if isinstance(item, dict):
                if item.get("thought") is True:
                    continue
                item_copy = dict(item)
                if isinstance(item_copy.get("text"), (list, dict)):
                    stripped_text = _strip_thought_parts(item_copy["text"])
                    item_copy["text"] = stripped_text
                    if (
                        stripped_text in ([], "", None)
                        and not item_copy.get("parts")
                        and not item_copy.get("content")
                        and not item_copy.get("value")
                    ):
                        continue
                if "parts" in item_copy:
                    stripped_parts = _strip_thought_parts(item_copy["parts"])
                    item_copy["parts"] = stripped_parts
                    if (
                        stripped_parts in ([], "", None)
                        and not item_copy.get("text")
                        and not item_copy.get("content")
                        and not item_copy.get("value")
                    ):
                        continue
                if isinstance(item_copy.get("content"), (list, dict)):
                    stripped_nested = _strip_thought_parts(item_copy["content"])
                    item_copy["content"] = stripped_nested
                    if (
                        stripped_nested in ([], "", None)
                        and not item_copy.get("text")
                        and not item_copy.get("parts")
                        and not item_copy.get("value")
                    ):
                        continue
                cleaned.append(item_copy)
            elif isinstance(item, list):
                stripped_sub = _strip_thought_parts(item)
                if stripped_sub:
                    cleaned.append(stripped_sub)
            else:
                cleaned.append(item)
        return cleaned
    if isinstance(content, dict):
        if content.get("thought") is True:
            return ""
        content_copy = dict(content)
        if isinstance(content_copy.get("text"), (list, dict)):
            content_copy["text"] = _strip_thought_parts(content_copy["text"])
        if "parts" in content_copy:
            content_copy["parts"] = _strip_thought_parts(content_copy["parts"])
        if isinstance(content_copy.get("content"), (list, dict)):
            content_copy["content"] = _strip_thought_parts(content_copy["content"])
        return content_copy
    return content


def _extract_content_text(content: Any, *, skip_thoughts: bool = False) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        segments: list[str] = []
        for item in content:
            extracted = _extract_content_text(item, skip_thoughts=skip_thoughts)
            if extracted:
                segments.append(extracted)
        return "\n".join(segments)
    if isinstance(content, dict):
        if skip_thoughts and content.get("thought") is True:
            return ""
        segments = []
        item_type = content.get("type")
        if item_type in (None, "text", "input_text", "output_text"):
            text_val = content.get("text")
            if isinstance(text_val, str) and text_val:
                segments.append(text_val)
            elif (
                isinstance(text_val, dict)
                and not (skip_thoughts and text_val.get("thought") is True)
                and isinstance(text_val.get("value"), str)
                and text_val["value"]
            ):
                segments.append(text_val["value"])
            elif isinstance(text_val, (list, dict)):
                nested_text = _extract_content_text(text_val, skip_thoughts=skip_thoughts)
                if nested_text:
                    segments.append(nested_text)
            elif isinstance(content.get("value"), str) and content["value"]:
                segments.append(content["value"])
        if "content" in content:
            nested_content = _extract_content_text(
                content.get("content"), skip_thoughts=skip_thoughts
            )
            if nested_content:
                segments.append(nested_content)
        if "parts" in content:
            parts_text = _extract_content_text(
                content.get("parts"), skip_thoughts=skip_thoughts
            )
            if parts_text:
                segments.append(parts_text)
        return "\n".join(segments)
    return ""


def extract_latest_user_turn(messages: list[dict[str, Any]]) -> tuple[int | None, str]:
    """Returns (index, text) for only the latest user message in OpenAI messages[]."""
    for idx in range(len(messages) - 1, -1, -1):
        msg = messages[idx]
        if str(msg.get("role", "")).lower() == "user":
            return idx, _extract_content_text(msg.get("content"), skip_thoughts=False)
    return None, ""


def _replace_user_turn_text(
    messages: list[dict[str, Any]], idx: int | None, sanitized_text: str
) -> list[dict[str, Any]]:
    copied = [dict(m) for m in messages]
    if idx is not None and 0 <= idx < len(copied):
        copied[idx]["content"] = sanitized_text
    return copied


def _inspect_messages_payload(
    messages: list[dict[str, Any]],
    *,
    active_guard: FailClosedModelArmorGuard,
    policy: DynamicGuardrailPolicyPayload,
) -> tuple[GuardrailVerdict, list[dict[str, Any]]]:
    """Inspects latest user turn plus all non-user/assistant and trailing turns."""
    if not messages:
        raise HTTPException(
            status_code=422,
            detail="messages must not be empty.",
        )

    latest_idx, latest_user_text = extract_latest_user_turn(messages)
    sanitized_messages = [dict(m) for m in messages]

    if latest_idx is None:
        combined_texts: list[str] = []
        primary_verdict: GuardrailVerdict | None = None
        any_escalate = False
        any_pii_masked = False
        all_pii_types: list[str] = []
        any_uri = False
        max_unpacked = 0
        total_urls = 0

        for idx, msg in enumerate(messages):
            turn_text = _extract_content_text(msg.get("content"), skip_thoughts=False)
            if not turn_text:
                continue
            verdict = active_guard.inspect_text(
                turn_text,
                direction="USER_PROMPT",
                dynamic_policy=policy,
            )
            if not verdict.allowed:
                return verdict, sanitized_messages
            combined_texts.append(verdict.sanitized_text)
            if verdict.pii_masked or verdict.malicious_uri_detected:
                sanitized_messages[idx]["content"] = verdict.sanitized_text
            any_escalate = any_escalate or verdict.escalate_to_secondary_voters
            any_pii_masked = any_pii_masked or verdict.pii_masked
            for ptype in verdict.pii_types_masked:
                if ptype not in all_pii_types:
                    all_pii_types.append(ptype)
            any_uri = any_uri or verdict.malicious_uri_detected
            max_unpacked = max(max_unpacked, verdict.unpacked_layers)
            total_urls += verdict.scanned_urls_count
            primary_verdict = verdict

        if primary_verdict is None:
            primary_verdict = active_guard.inspect_text(
                "",
                direction="USER_PROMPT",
                dynamic_policy=policy,
            )
        else:
            primary_verdict.sanitized_text = "\n".join(combined_texts)
            primary_verdict.escalate_to_secondary_voters = any_escalate
            primary_verdict.pii_masked = any_pii_masked
            primary_verdict.pii_types_masked = all_pii_types
            primary_verdict.malicious_uri_detected = any_uri
            primary_verdict.unpacked_layers = max_unpacked
            primary_verdict.scanned_urls_count = total_urls

        return primary_verdict, sanitized_messages

    in_verdict = active_guard.inspect_text(
        latest_user_text,
        direction="USER_PROMPT",
        dynamic_policy=policy,
    )
    if not in_verdict.allowed:
        return in_verdict, sanitized_messages

    sanitized_messages[latest_idx]["content"] = in_verdict.sanitized_text

    for idx, msg in enumerate(messages):
        if idx == latest_idx:
            continue
        role = str(msg.get("role", "")).lower()
        if role in {"user", "assistant"} and idx < latest_idx:
            continue
        turn_text = _extract_content_text(msg.get("content"), skip_thoughts=False)
        if not turn_text:
            continue
        turn_verdict = active_guard.inspect_text(
            turn_text,
            direction="USER_PROMPT",
            dynamic_policy=policy,
        )
        if not turn_verdict.allowed:
            return turn_verdict, sanitized_messages
        if turn_verdict.pii_masked:
            sanitized_messages[idx]["content"] = turn_verdict.sanitized_text
            in_verdict.pii_masked = True
            for ptype in turn_verdict.pii_types_masked:
                if ptype not in in_verdict.pii_types_masked:
                    in_verdict.pii_types_masked.append(ptype)
        if turn_verdict.escalate_to_secondary_voters:
            in_verdict.escalate_to_secondary_voters = True
        in_verdict.unpacked_layers = max(
            in_verdict.unpacked_layers, turn_verdict.unpacked_layers
        )
        in_verdict.scanned_urls_count += turn_verdict.scanned_urls_count

    return in_verdict, sanitized_messages


def _effective_port(parsed: urllib.parse.ParseResult) -> int:
    if parsed.port is not None:
        return parsed.port
    return 443 if parsed.scheme == "https" else 80


def _validate_target_url(
    override_url: str | None,
    default_url: str,
    *,
    purpose: str,
) -> str:
    candidate = (override_url or "").strip() or default_url.strip()
    if not candidate:
        return ""
    parsed = urllib.parse.urlparse(candidate)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise HTTPException(
            status_code=403,
            detail={
                "error": {
                    "code": "invalid_target_url",
                    "message": f"Invalid {purpose} URL scheme or host.",
                }
            },
        )
    if override_url and override_url.strip():
        allowed_hosts_raw = os.getenv("ALLOWED_UPSTREAM_HOSTS", "")
        allowed_hosts_any_port: set[str] = set()
        allowed_host_ports: set[tuple[str, int]] = set()
        for raw_entry in allowed_hosts_raw.split(","):
            entry = raw_entry.strip().lower()
            if not entry:
                continue
            if ":" in entry and not entry.startswith("["):
                host_part, _, port_part = entry.rpartition(":")
                if port_part.isdigit():
                    allowed_host_ports.add((host_part, int(port_part)))
                    continue
            elif entry.startswith("[") and "]:" in entry:
                host_part, _, port_part = entry.rpartition(":")
                if port_part.isdigit():
                    allowed_host_ports.add((host_part.strip("[]"), int(port_part)))
                    continue
            allowed_hosts_any_port.add(entry.strip("[]"))

        if default_url.strip():
            default_parsed = urllib.parse.urlparse(default_url.strip())
            if default_parsed.hostname:
                allowed_host_ports.add(
                    (default_parsed.hostname.lower(), _effective_port(default_parsed))
                )

        cand_host = parsed.hostname.lower()
        cand_port = _effective_port(parsed)
        if (
            cand_host not in allowed_hosts_any_port
            and (cand_host, cand_port) not in allowed_host_ports
        ):
            raise HTTPException(
                status_code=403,
                detail={
                    "error": {
                        "code": "ssrf_host_not_allowlisted",
                        "message": (
                            f"Override {purpose} target '{parsed.netloc}' is not in "
                            "ALLOWED_UPSTREAM_HOSTS."
                        ),
                    }
                },
            )
    return candidate


def _error_response_for_verdict(verdict: GuardrailVerdict) -> JSONResponse:
    if verdict.action_taken in {
        "BLOCKED_FAIL_CLOSED",
        "BLOCKED_PARTIAL_OR_FAILURE",
    }:
        return JSONResponse(
            status_code=503,
            content={
                "error": {
                    "code": "guardrail_provider_unavailable",
                    "message": verdict.summary,
                    "action_taken": verdict.action_taken,
                    "verdict": _serialize_verdict(verdict),
                }
            },
        )

    err_code = (
        "prohibited_agency_tier"
        if verdict.action_taken == "BLOCKED_PROHIBITED_AGENCY_TIER"
        else "content_filter"
    )
    return JSONResponse(
        status_code=403,
        content={
            "error": {
                "code": err_code,
                "message": verdict.summary,
                "action_taken": verdict.action_taken,
                "verdict": _serialize_verdict(verdict),
            }
        },
    )


def _optional_guardrail_results(verdict: GuardrailVerdict) -> dict[str, Any] | None:
    if (
        verdict.pii_masked
        or verdict.pii_types_masked
        or verdict.malicious_uri_detected
        or verdict.unpacked_layers > 0
        or verdict.escalate_to_secondary_voters
    ):
        return {
            "tier0_action": verdict.action_taken,
            "pii_masked": verdict.pii_masked,
            "pii_types_detected": verdict.pii_types_masked,
            "unpacked_layers": verdict.unpacked_layers,
            "scanned_urls_count": verdict.scanned_urls_count,
            "escalate_to_secondary_voters": verdict.escalate_to_secondary_voters,
        }
    return None


def create_app(guard: FailClosedModelArmorGuard | None = None) -> FastAPI:
    service_app = FastAPI(
        title="Cymbal Tier-0 Model Armor Gateway Middleware Adapter",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
    )
    service_app.state.guard = guard or FailClosedModelArmorGuard()
    service_app.state.http_transport = None

    @service_app.middleware("http")
    async def apply_security_headers(request: Request, call_next: Any) -> Any:
        if request.method not in {"GET", "POST", "OPTIONS"}:
            return JSONResponse({"detail": "Method not allowed"}, status_code=405)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'"
        )
        return response

    @service_app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        active_guard: FailClosedModelArmorGuard = service_app.state.guard
        return {
            "status": "ok",
            "service": "gateway-tier0-model-armor",
            "fail_closed": True,
            "live_model_armor": active_guard.live_api_enabled,
            "upstream_configured": bool(os.getenv("UPSTREAM_GATEWAY_URL", "").strip()),
        }

    @service_app.post("/v1/guardrails/compile-policy")
    async def compile_policy(
        payload: DynamicGuardrailPolicyPayload | None = Body(default=None),
        x_business_unit: str | None = Header(default=None),
        x_risk_tier: str | None = Header(default=None),
        x_sdp_pii_mode: str | None = Header(default=None),
        x_ensemble_role: str | None = Header(default=None),
    ) -> Any:
        try:
            policy = _build_policy_from_headers_and_body(
                payload,
                x_business_unit=x_business_unit,
                x_risk_tier=x_risk_tier,
                x_sdp_pii_mode=x_sdp_pii_mode,
                x_ensemble_role=x_ensemble_role,
            )
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        active_guard: FailClosedModelArmorGuard = service_app.state.guard
        try:
            compiled = compile_dynamic_policy_to_base_template(
                policy,
                project_id=active_guard.project_id,
                location=active_guard.location,
                default_template=active_guard.template_id,
            )
        except ProhibitedAgencyTierError as exc:
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "code": "prohibited_agency_tier",
                        "action_taken": "BLOCKED_PROHIBITED_AGENCY_TIER",
                        "message": str(exc),
                    }
                },
            )
        if not _expose_policy_ids():
            compiled["resolved_template"] = f"redacted:{compiled['resolved_tier']}"
        return compiled

    @service_app.post("/v1/guardrails/prefilter")
    async def prefilter(
        payload: PrefilterRequest,
        x_business_unit: str | None = Header(default=None),
        x_risk_tier: str | None = Header(default=None),
        x_sdp_pii_mode: str | None = Header(default=None),
        x_ensemble_role: str | None = Header(default=None),
    ) -> Any:
        try:
            policy = _build_policy_from_headers_and_body(
                payload.dynamic_policy,
                x_business_unit=x_business_unit,
                x_risk_tier=x_risk_tier,
                x_sdp_pii_mode=x_sdp_pii_mode,
                x_ensemble_role=x_ensemble_role,
            )
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        active_guard: FailClosedModelArmorGuard = service_app.state.guard
        sanitized_messages: list[dict[str, Any]] | None = None
        if payload.messages is not None:
            verdict, sanitized_messages = _inspect_messages_payload(
                payload.messages,
                active_guard=active_guard,
                policy=policy,
            )
        elif payload.text is not None:
            verdict = active_guard.inspect_text(
                payload.text,
                direction="USER_PROMPT",
                dynamic_policy=policy,
            )
        else:
            raise HTTPException(
                status_code=422,
                detail="Either 'text' or 'messages' must be provided.",
            )

        if not verdict.allowed:
            return _error_response_for_verdict(verdict)

        response_body: dict[str, Any] = {
            "allowed": True,
            "sanitized_text": verdict.sanitized_text,
            "escalate_to_secondary_voters": verdict.escalate_to_secondary_voters,
            "verdict": _serialize_verdict(verdict),
        }
        if sanitized_messages is not None:
            response_body["sanitized_messages"] = sanitized_messages
        findings = _optional_guardrail_results(verdict)
        if findings is not None:
            response_body["guardrail_results"] = findings
        return response_body

    @service_app.post("/v1/guardrails/inspect-response")
    async def inspect_response(
        payload: InspectResponseRequest,
        x_business_unit: str | None = Header(default=None),
        x_risk_tier: str | None = Header(default=None),
        x_sdp_pii_mode: str | None = Header(default=None),
        x_ensemble_role: str | None = Header(default=None),
    ) -> Any:
        try:
            policy = _build_policy_from_headers_and_body(
                payload.dynamic_policy,
                x_business_unit=x_business_unit,
                x_risk_tier=x_risk_tier,
                x_sdp_pii_mode=x_sdp_pii_mode,
                x_ensemble_role=x_ensemble_role,
            )
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        active_guard: FailClosedModelArmorGuard = service_app.state.guard

        if payload.text is not None:
            verdict = active_guard.inspect_text(
                payload.text,
                direction="MODEL_RESPONSE",
                dynamic_policy=policy,
                block_malicious_urls_inline_mask_only=(
                    payload.block_malicious_urls_inline_mask_only
                ),
            )
            if not verdict.allowed:
                return _error_response_for_verdict(verdict)
            body: dict[str, Any] = {
                "allowed": True,
                "sanitized_text": verdict.sanitized_text,
                "verdict": _serialize_verdict(verdict),
            }
            findings = _optional_guardrail_results(verdict)
            if findings is not None:
                body["guardrail_results"] = findings
            return body

        if payload.choices:
            sanitized_choices: list[dict[str, Any]] = []
            choice_texts: list[str] = []
            primary_verdict: GuardrailVerdict | None = None
            any_pii_masked = False
            all_pii_types: list[str] = []
            any_uri = False
            any_escalate = False
            max_unpacked = 0
            total_urls = 0

            for choice in payload.choices:
                choice_copy = dict(choice)
                msg = choice_copy.get("message")
                if isinstance(msg, dict):
                    msg_copy = dict(msg)
                    if choice_copy.get("thought") is True or msg_copy.get("thought") is True:
                        msg_copy["content"] = ""
                        if "parts" in msg_copy:
                            msg_copy["parts"] = []
                    elif "content" in msg_copy:
                        msg_copy["content"] = _strip_thought_parts(msg_copy.get("content"))
                    choice_text = _extract_content_text(
                        msg_copy.get("content"), skip_thoughts=True
                    )
                    if choice_text:
                        verdict = active_guard.inspect_text(
                            choice_text,
                            direction="MODEL_RESPONSE",
                            dynamic_policy=policy,
                            block_malicious_urls_inline_mask_only=(
                                payload.block_malicious_urls_inline_mask_only
                            ),
                        )
                        if not verdict.allowed:
                            return _error_response_for_verdict(verdict)
                        choice_texts.append(verdict.sanitized_text)
                        if verdict.pii_masked or verdict.malicious_uri_detected:
                            msg_copy["content"] = verdict.sanitized_text
                        any_pii_masked = any_pii_masked or verdict.pii_masked
                        for ptype in verdict.pii_types_masked:
                            if ptype not in all_pii_types:
                                all_pii_types.append(ptype)
                        any_uri = any_uri or verdict.malicious_uri_detected
                        any_escalate = any_escalate or verdict.escalate_to_secondary_voters
                        max_unpacked = max(max_unpacked, verdict.unpacked_layers)
                        total_urls += verdict.scanned_urls_count
                        primary_verdict = verdict
                    choice_copy["message"] = msg_copy
                sanitized_choices.append(choice_copy)

            if primary_verdict is None:
                primary_verdict = active_guard.inspect_text(
                    "",
                    direction="MODEL_RESPONSE",
                    dynamic_policy=policy,
                    block_malicious_urls_inline_mask_only=(
                        payload.block_malicious_urls_inline_mask_only
                    ),
                )
                if not primary_verdict.allowed:
                    return _error_response_for_verdict(primary_verdict)
            else:
                primary_verdict.sanitized_text = "\n".join(choice_texts)
                primary_verdict.pii_masked = any_pii_masked
                primary_verdict.pii_types_masked = all_pii_types
                primary_verdict.malicious_uri_detected = any_uri
                primary_verdict.escalate_to_secondary_voters = any_escalate
                primary_verdict.unpacked_layers = max_unpacked
                primary_verdict.scanned_urls_count = total_urls

            body = {
                "allowed": True,
                "sanitized_text": primary_verdict.sanitized_text,
                "sanitized_choices": sanitized_choices,
                "verdict": _serialize_verdict(primary_verdict),
            }
            findings = _optional_guardrail_results(primary_verdict)
            if findings is not None:
                body["guardrail_results"] = findings
            return body

        if payload.messages:
            sanitized_messages: list[dict[str, Any]] = []
            msg_texts: list[str] = []
            primary_verdict = None
            any_pii_masked = False
            all_pii_types = []
            any_uri = False
            any_escalate = False
            max_unpacked = 0
            total_urls = 0

            for msg in payload.messages:
                msg_copy = dict(msg)
                if msg_copy.get("thought") is True:
                    msg_copy["content"] = ""
                    if "parts" in msg_copy:
                        msg_copy["parts"] = []
                elif "content" in msg_copy:
                    msg_copy["content"] = _strip_thought_parts(msg_copy.get("content"))
                msg_text = _extract_content_text(
                    msg_copy.get("content"), skip_thoughts=True
                )
                if msg_text:
                    verdict = active_guard.inspect_text(
                        msg_text,
                        direction="MODEL_RESPONSE",
                        dynamic_policy=policy,
                        block_malicious_urls_inline_mask_only=(
                            payload.block_malicious_urls_inline_mask_only
                        ),
                    )
                    if not verdict.allowed:
                        return _error_response_for_verdict(verdict)
                    msg_texts.append(verdict.sanitized_text)
                    if verdict.pii_masked or verdict.malicious_uri_detected:
                        msg_copy["content"] = verdict.sanitized_text
                    any_pii_masked = any_pii_masked or verdict.pii_masked
                    for ptype in verdict.pii_types_masked:
                        if ptype not in all_pii_types:
                            all_pii_types.append(ptype)
                    any_uri = any_uri or verdict.malicious_uri_detected
                    any_escalate = any_escalate or verdict.escalate_to_secondary_voters
                    max_unpacked = max(max_unpacked, verdict.unpacked_layers)
                    total_urls += verdict.scanned_urls_count
                    primary_verdict = verdict
                sanitized_messages.append(msg_copy)

            if primary_verdict is None:
                primary_verdict = active_guard.inspect_text(
                    "",
                    direction="MODEL_RESPONSE",
                    dynamic_policy=policy,
                    block_malicious_urls_inline_mask_only=(
                        payload.block_malicious_urls_inline_mask_only
                    ),
                )
                if not primary_verdict.allowed:
                    return _error_response_for_verdict(primary_verdict)
            else:
                primary_verdict.sanitized_text = "\n".join(msg_texts)
                primary_verdict.pii_masked = any_pii_masked
                primary_verdict.pii_types_masked = all_pii_types
                primary_verdict.malicious_uri_detected = any_uri
                primary_verdict.escalate_to_secondary_voters = any_escalate
                primary_verdict.unpacked_layers = max_unpacked
                primary_verdict.scanned_urls_count = total_urls

            body = {
                "allowed": True,
                "sanitized_text": primary_verdict.sanitized_text,
                "sanitized_messages": sanitized_messages,
                "verdict": _serialize_verdict(primary_verdict),
            }
            findings = _optional_guardrail_results(primary_verdict)
            if findings is not None:
                body["guardrail_results"] = findings
            return body

        raise HTTPException(
            status_code=422,
            detail="Either 'text', 'choices', or 'messages' must be provided.",
        )

    @service_app.post("/v1/chat/completions")
    async def chat_completions_proxy(
        payload: ChatCompletionProxyRequest,
        authorization: str | None = Header(default=None),
        traceparent: str | None = Header(default=None),
        x_trace_session_id: str | None = Header(default=None),
        x_business_unit: str | None = Header(default=None),
        x_risk_tier: str | None = Header(default=None),
        x_sdp_pii_mode: str | None = Header(default=None),
        x_ensemble_role: str | None = Header(default=None),
        x_upstream_gateway_url: str | None = Header(default=None),
        x_secondary_guardrail_url: str | None = Header(default=None),
    ) -> Any:
        try:
            policy = _build_policy_from_headers_and_body(
                payload.dynamic_policy,
                x_business_unit=x_business_unit,
                x_risk_tier=x_risk_tier,
                x_sdp_pii_mode=x_sdp_pii_mode,
                x_ensemble_role=x_ensemble_role,
            )
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        if payload.stream:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": {
                        "code": "streaming_disabled_for_buffered_inspection",
                        "message": (
                            "Set stream=false; buffered full-response inspection is "
                            "required for fail-closed output enforcement."
                        ),
                    }
                },
            )

        active_guard: FailClosedModelArmorGuard = service_app.state.guard
        in_verdict, sanitized_messages = _inspect_messages_payload(
            payload.messages,
            active_guard=active_guard,
            policy=policy,
        )
        if not in_verdict.allowed:
            return _error_response_for_verdict(in_verdict)

        default_secondary = os.getenv("SECONDARY_GUARDRAIL_URL", "")
        secondary_url = _validate_target_url(
            x_secondary_guardrail_url,
            default_secondary,
            purpose="secondary guardrail",
        )
        default_upstream = os.getenv("UPSTREAM_GATEWAY_URL", "")
        upstream_url = _validate_target_url(
            x_upstream_gateway_url,
            default_upstream,
            purpose="upstream gateway",
        )

        client_kwargs: dict[str, Any] = {"timeout": 15.0}
        if service_app.state.http_transport is not None:
            client_kwargs["transport"] = service_app.state.http_transport

        async with httpx.AsyncClient(**client_kwargs) as client:
            if in_verdict.escalate_to_secondary_voters and secondary_url:
                sec_fail_closed = (
                    os.getenv("SECONDARY_FAIL_CLOSED", "true").lower()
                    in {"1", "true", "yes"}
                )
                try:
                    sec_resp = await client.post(
                        secondary_url,
                        json={
                            "text": in_verdict.sanitized_text,
                            "dynamic_policy_key": in_verdict.dynamic_policy_key,
                            "risk_tier": policy.risk_tier,
                        },
                    )
                    if sec_resp.status_code == 403:
                        return JSONResponse(
                            status_code=403,
                            content={
                                "error": {
                                    "code": "content_filter",
                                    "message": "Blocked by secondary guardrail ensemble voter.",
                                    "action_taken": "BLOCKED_SECONDARY_VOTER",
                                }
                            },
                        )
                    if sec_resp.status_code != 200:
                        if sec_fail_closed:
                            return JSONResponse(
                                status_code=503,
                                content={
                                    "error": {
                                        "code": "guardrail_provider_unavailable",
                                        "message": (
                                            "Secondary guardrail voter returned non-200 status "
                                            f"({sec_resp.status_code}); blocked fail-closed."
                                        ),
                                    }
                                },
                            )
                    else:
                        try:
                            sec_data = sec_resp.json()
                        except ValueError:
                            if sec_fail_closed:
                                return JSONResponse(
                                    status_code=503,
                                    content={
                                        "error": {
                                            "code": "guardrail_provider_unavailable",
                                            "message": "Secondary guardrail voter returned invalid JSON.",
                                        }
                                    },
                                )
                            sec_data = {}
                        if isinstance(sec_data, dict) and sec_data.get("allowed") is False:
                            return JSONResponse(
                                status_code=403,
                                content={
                                    "error": {
                                        "code": "content_filter",
                                        "message": "Blocked by secondary guardrail ensemble voter.",
                                        "action_taken": "BLOCKED_SECONDARY_VOTER",
                                    }
                                },
                            )
                except httpx.HTTPError as exc:
                    if sec_fail_closed:
                        return JSONResponse(
                            status_code=503,
                            content={
                                "error": {
                                    "code": "guardrail_provider_unavailable",
                                    "message": (
                                        "Secondary guardrail voter unreachable; "
                                        f"blocked fail-closed ({type(exc).__name__})."
                                    ),
                                }
                            },
                        )

            if not upstream_url:
                return JSONResponse(
                    status_code=501,
                    content={
                        "error": {
                            "code": "upstream_gateway_not_configured",
                            "message": (
                                "UPSTREAM_GATEWAY_URL is not configured; use "
                                "/v1/guardrails/prefilter for inspection-only mode."
                            ),
                        }
                    },
                )

            target_endpoint = (
                upstream_url
                if upstream_url.rstrip("/").endswith("/chat/completions")
                else f"{upstream_url.rstrip('/')}/chat/completions"
            )
            forward_payload = payload.model_dump(exclude_none=True, exclude={"dynamic_policy"})
            forward_payload["messages"] = sanitized_messages
            forward_headers: dict[str, str] = {
                "Content-Type": "application/json",
                "X-Guardrail-Tier0-Key": in_verdict.dynamic_policy_key,
            }
            if authorization:
                forward_headers["Authorization"] = authorization
            if traceparent:
                forward_headers["traceparent"] = traceparent
            if x_trace_session_id:
                forward_headers["X-Trace-Session-Id"] = x_trace_session_id

            try:
                upstream_resp = await client.post(
                    target_endpoint,
                    json=forward_payload,
                    headers=forward_headers,
                )
            except httpx.HTTPError as exc:
                return JSONResponse(
                    status_code=502,
                    content={
                        "error": {
                            "code": "upstream_gateway_error",
                            "message": f"Upstream gateway request failed: {type(exc).__name__}",
                        }
                    },
                )

        if upstream_resp.status_code >= 400:
            try:
                err_json = upstream_resp.json()
            except ValueError:
                err_json = {"detail": upstream_resp.text}
            return JSONResponse(status_code=upstream_resp.status_code, content=err_json)

        completion_data = upstream_resp.json()
        choices = completion_data.get("choices") or []
        any_out_pii_masked = False
        all_out_pii_types: list[str] = []
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            msg = choice.get("message")
            if not isinstance(msg, dict):
                continue
            if choice.get("thought") is True or msg.get("thought") is True:
                msg["content"] = ""
                if "parts" in msg:
                    msg["parts"] = []
            elif "content" in msg:
                msg["content"] = _strip_thought_parts(msg.get("content"))
            out_text = _extract_content_text(msg.get("content"), skip_thoughts=True)
            if not out_text:
                continue
            out_verdict = active_guard.inspect_text(
                out_text,
                direction="MODEL_RESPONSE",
                dynamic_policy=policy,
                block_malicious_urls_inline_mask_only=False,
            )
            if not out_verdict.allowed:
                return _error_response_for_verdict(out_verdict)
            if out_verdict.pii_masked or out_verdict.malicious_uri_detected:
                msg["content"] = out_verdict.sanitized_text
            if out_verdict.pii_masked:
                any_out_pii_masked = True
            for ptype in out_verdict.pii_types_masked:
                if ptype not in all_out_pii_types:
                    all_out_pii_types.append(ptype)

        findings = _optional_guardrail_results(in_verdict)
        if any_out_pii_masked or all_out_pii_types:
            findings = findings or {}
            findings["output_pii_masked"] = any_out_pii_masked
            findings["output_pii_types"] = all_out_pii_types
        if findings is not None:
            completion_data["guardrail_results"] = findings

        return completion_data

    return service_app


app = create_app()


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    bind_host = os.getenv("BIND_HOST", "127.0.0.1")
    uvicorn.run(app, host=bind_host, port=port)
