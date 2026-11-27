# Tier-0 Model Armor Gateway Middleware Adapter

Standalone, OpenAI-compatible HTTP pre-filter and reverse-proxy middleware for Enterprise AI Gateways. Executes dynamic per-request Model Armor policy routing, 3-layer obfuscation unpacking, inline Cloud SDP PII redaction, and fail-closed `sanitize_user_prompt` / `sanitize_model_response` inspection ahead of secondary ensemble guardrail voters and upstream LLM backends.

## Key Security & Architectural Properties

1. **Dynamic Policy Routing (`AG1`-`AG4`) & Unconditional `AG5` Block**:
   - `DynamicGuardrailPolicyPayload` compiles hundreds of logical business-unit, sensitivity, and SDP mode combinations onto a bounded 3-template pool (`CYMBAL_MODEL_ARMOR_LOW_TEMPLATE`, `CYMBAL_MODEL_ARMOR_DEFAULT_TEMPLATE`, `CYMBAL_MODEL_ARMOR_STRICT_TEMPLATE`).
   - Requests declaring `risk_tier="AG5"` (body or `X-Risk-Tier: AG5`) are unconditionally blocked with `HTTP 403` (`prohibited_agency_tier`).
2. **Strict Fail-Closed Guardrail Enforcement**:
   - Any Model Armor `401`, timeout, network exception, or non-`SUCCESS` `invocation_result` returns `HTTP 503` (`guardrail_provider_unavailable`, `action_taken="BLOCKED_FAIL_CLOSED"`).
   - Prompt injections, malicious/phishing URIs, or `BLOCK_ON_MATCH` PII hits return `HTTP 403` before any upstream inference call.
3. **Latest-Turn Extraction & Inline PII Redaction**:
   - Inbound `USER_PROMPT` scanning inspects the latest `user` turn plus non-`user`/trailing turns (`skip_thoughts=False`) without re-scanning prior `user`/`assistant` history, while outbound `MODEL_RESPONSE` scanning strips `thought: true` parts and scans/masks visible response parts (replacing raw SSN/MAC/card strings).
4. **Tier-0 Short-Circuiting & Secondary Ensemble Escalation**:
   - Clean `AG1`/`AG2` Tier-0 turns complete without invoking secondary voters (`escalate_to_secondary_voters=false`).
   - High-risk (`AG3`/`AG4`), `INSPECT_ONLY` PII-flagged, or `parallel_ensemble_voter` turns set `escalate_to_secondary_voters=true` and optionally call `SECONDARY_GUARDRAIL_URL` before upstream inference.
5. **SSRF Protection & Zero Template Leakage**:
   - Override headers (`X-Upstream-Gateway-URL`, `X-Secondary-Guardrail-URL`) are blocked with `HTTP 403` unless their hostnames appear in `ALLOWED_UPSTREAM_HOSTS`.
   - `EXPOSE_POLICY_IDS` defaults to `false`, omitting internal GCP template resource URIs from external HTTP payloads.

## Endpoints

- `GET /healthz`: Liveness and fail-closed readiness status.
- `POST /v1/guardrails/compile-policy`: Compile a `DynamicGuardrailPolicyPayload` onto the 3-tier template pool.
- `POST /v1/guardrails/prefilter`: Standalone pre-filter hook accepting `text` or OpenAI `messages[]`.
- `POST /v1/guardrails/inspect-response`: Output inspection hook for `MODEL_RESPONSE` `text`, `choices[]`, or `messages[]`.
- `POST /v1/chat/completions`: OpenAI-compatible reverse-proxy middleware forwarding sanitized payloads to `UPSTREAM_GATEWAY_URL`.

## Local Execution

```bash
uvicorn services.gateway_tier0_model_armor.app:app --host 127.0.0.1 --port 8080
```

## Container Build

```bash
docker build -t gateway-tier0-model-armor services/gateway_tier0_model_armor/
```
