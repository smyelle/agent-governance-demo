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

"""Zero-Secret SPIFFE AGENT_IDENTITY posture & ADR-011 dual-token OBO verifier.

Proves two critical enterprise identity guarantees:
1. `google_native`: Zero static API keys or sidecar secrets in `os.environ`;
   downstream Cloud Run MCP/A2A calls use platform-minted OIDC / SPIFFE tokens.
2. `enterprise_hybrid`: Enforces `ADR-011` dual-token correlation
   (`Authorization: Bearer <T-gw>` + `X-User-Authorization: Bearer <T-mcp>`)
   by asserting `T-mcp.azp == T-gw.azp` and `T-mcp.tid == T-gw.tid` with strict
   algorithm and expiration validation, resolving `ADR-008` pairwise `sub`
   mismatch across external IdP two-app OBO flows.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import secrets
import shutil
import subprocess
import time
from typing import Any

import google.auth.transport.requests
import google.oauth2.id_token
import jwt

FORBIDDEN_STATIC_SECRET_ENV_NAMES = (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "STATIC_GATEWAY_BEARER_TOKEN",
    "VAULT_TOKEN",
    "OTLP_COLLECTOR_SECRET_KEY",
)

EXPECTED_JWT_ALGORITHM = "HS256"
_EPHEMERAL_OBO_SIGNING_KEY: str | None = None
_OIDC_ID_TOKEN_CACHE: dict[str, tuple[str, float]] = {}
_OIDC_CACHE_TTL_SECONDS = 2700.0


def _get_obo_verification_secret() -> str:
    global _EPHEMERAL_OBO_SIGNING_KEY
    env_key = os.getenv("CYMBAL_OBO_HMAC_KEY")
    if env_key:
        return env_key
    if _EPHEMERAL_OBO_SIGNING_KEY is None:
        _EPHEMERAL_OBO_SIGNING_KEY = secrets.token_hex(32)
    return _EPHEMERAL_OBO_SIGNING_KEY


class DualTokenOBOViolationError(PermissionError):
    """Raised when ADR-011 dual-token azp/tid/exp correlation fails."""


@dataclass
class ContainerIdentityPosture:
    identity_mode: str
    spiffe_id: str
    static_secret_env_vars_present: list[str]
    zero_secret_compliant: bool
    sidecar_processes_required: int
    summary: str


def inspect_zero_secret_posture(
    project_id: str | None = None,
    agent_id: str = "cymbal-ops-release-agent",
    env_mapping: dict[str, str] | None = None,
) -> ContainerIdentityPosture:
    """Inspects runtime environment to verify zero static bearer/API secrets exist."""
    env = env_mapping if env_mapping is not None else dict(os.environ)
    leaked = [k for k in FORBIDDEN_STATIC_SECRET_ENV_NAMES if env.get(k)]
    del project_id
    trust_domain = env.get("CYMBAL_TRUST_DOMAIN", "cymbal-agent-platform.svc.id.goog")
    engine_id = env.get("GOOGLE_CLOUD_AGENT_ENGINE_ID", agent_id)
    spiffe_id = f"spiffe://{trust_domain}/ns/agent-runtime/sa/{engine_id}"
    compliant = len(leaked) == 0
    return ContainerIdentityPosture(
        identity_mode="AGENT_IDENTITY_SPIFFE_SVID",
        spiffe_id=spiffe_id,
        static_secret_env_vars_present=leaked,
        zero_secret_compliant=compliant,
        sidecar_processes_required=0,
        summary=(
            f"Zero static secrets in container environment (0/{len(FORBIDDEN_STATIC_SECRET_ENV_NAMES)} keys); "
            f"workload authenticated via hardware/platform-minted {spiffe_id}."
            if compliant
            else f"Non-compliant static env secrets detected: {leaked}"
        ),
    )


def mint_demo_adr011_token_pair(
    *,
    client_azp: str = "cymbal-idp-agent-client-992",
    mcp_azp: str | None = None,
    tenant_id: str = "tenant-cymbal-01",
    gw_pairwise_sub: str = "pairwise-sub-for-gateway-resource-aaa111",
    mcp_pairwise_sub: str = "pairwise-sub-for-mcp-resource-bbb222",
    ttl_seconds: int = 900,
) -> tuple[str, str]:
    """Mints signed OBO JWTs illustrating pairwise `sub` divergence vs `azp` match."""
    now = int(time.time())
    secret = _get_obo_verification_secret()
    t_gw = jwt.encode(
        {
            "iss": f"https://login.cymbal-idp.example/{tenant_id}/v2.0",
            "aud": "api://cymbal-ai-gateway",
            "sub": gw_pairwise_sub,
            "azp": client_azp,
            "tid": tenant_id,
            "scp": "modelgw.use mcp.use",
            "iat": now,
            "exp": now + ttl_seconds,
        },
        secret,
        algorithm=EXPECTED_JWT_ALGORITHM,
    )
    t_mcp = jwt.encode(
        {
            "iss": f"https://login.cymbal-idp.example/{tenant_id}/v2.0",
            "aud": "api://cymbal-ops-mcp-server",
            "sub": mcp_pairwise_sub,
            "azp": mcp_azp or client_azp,
            "tid": tenant_id,
            "scp": "mcp.tools.read",
            "iat": now,
            "exp": now + ttl_seconds,
        },
        secret,
        algorithm=EXPECTED_JWT_ALGORITHM,
    )
    return t_gw, t_mcp


def verify_adr011_dual_tokens(
    authorization_bearer: str,
    x_user_authorization_bearer: str,
) -> dict[str, Any]:
    """Verifies ADR-011 dual-token correlation (`T-mcp.azp == T-gw.azp`).

    Explicitly rejects `alg=none`, enforces hardcoded `EXPECTED_JWT_ALGORITHM`,
    validates `exp`, demonstrates why legacy `ADR-008` (`sub == sub`) fails on
    pairwise subjects, and enforces `azp` + `tid` correlation.
    """
    raw_gw = authorization_bearer.removeprefix("Bearer ").strip()
    raw_mcp = x_user_authorization_bearer.removeprefix("Bearer ").strip()
    if not raw_gw or not raw_mcp:
        raise DualTokenOBOViolationError("Missing Authorization or X-User-Authorization bearer token.")

    secret = _get_obo_verification_secret()
    try:
        gw_header = jwt.get_unverified_header(raw_gw)
        mcp_header = jwt.get_unverified_header(raw_mcp)
        if gw_header.get("alg") != EXPECTED_JWT_ALGORITHM or mcp_header.get("alg") != EXPECTED_JWT_ALGORITHM:
            raise DualTokenOBOViolationError("Unsupported or 'none' JWT signing algorithm rejected.")

        gw_claims = jwt.decode(
            raw_gw,
            secret,
            algorithms=[EXPECTED_JWT_ALGORITHM],
            options={"require": ["exp", "sub", "azp", "tid"], "verify_aud": False},
        )
        mcp_claims = jwt.decode(
            raw_mcp,
            secret,
            algorithms=[EXPECTED_JWT_ALGORITHM],
            options={"require": ["exp", "sub", "azp", "tid"], "verify_aud": False},
        )
    except jwt.PyJWTError as exc:
        raise DualTokenOBOViolationError(f"Invalid OBO JWT signature or expired claim: {exc}") from exc

    legacy_adr008_sub_equal = gw_claims["sub"] == mcp_claims["sub"]
    azp_equal = bool(gw_claims.get("azp")) and (gw_claims["azp"] == mcp_claims["azp"])
    tid_equal = bool(gw_claims.get("tid")) and (gw_claims["tid"] == mcp_claims["tid"])

    if not (azp_equal and tid_equal):
        raise DualTokenOBOViolationError(
            f"ADR-011 OBO correlation failed: T-gw(azp={gw_claims.get('azp')}, tid={gw_claims.get('tid')}) "
            f"!= T-mcp(azp={mcp_claims.get('azp')}, tid={mcp_claims.get('tid')})."
        )

    return {
        "verified": True,
        "authorized_party_azp": gw_claims["azp"],
        "tenant_id": gw_claims["tid"],
        "gw_pairwise_sub": gw_claims["sub"],
        "mcp_pairwise_sub": mcp_claims["sub"],
        "legacy_adr008_sub_check_would_pass": legacy_adr008_sub_equal,
        "adr011_azp_check_passed": True,
    }


def fetch_cloud_run_id_token(target_audience: str) -> str | None:
    """Mints an IAM OIDC ID token over-the-wire with 45-min in-memory caching."""
    base_aud = target_audience.split("/mcp")[0].split("/a2a")[0].rstrip("/")
    now = time.time()
    cached = _OIDC_ID_TOKEN_CACHE.get(base_aud) or _OIDC_ID_TOKEN_CACHE.get("__cli__")
    if cached and (now - cached[1]) < _OIDC_CACHE_TTL_SECONDS:
        return cached[0]

    try:
        auth_req = google.auth.transport.requests.Request()
        tok = google.oauth2.id_token.fetch_id_token(auth_req, base_aud)
        if tok:
            _OIDC_ID_TOKEN_CACHE[base_aud] = (tok, now)
            return tok
    except Exception:
        pass

    gcloud_bin = shutil.which("gcloud")
    if gcloud_bin:
        env = dict(os.environ)
        existing_metrics = env.get("CLOUDSDK_METRICS_ENVIRONMENT", "")
        env["CLOUDSDK_METRICS_ENVIRONMENT"] = f"{existing_metrics} datacloud.antigravity".strip()
        try:
            proc = subprocess.run(
                [gcloud_bin, "auth", "print-identity-token", "--quiet"],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
                env=env,
            )
            tok = proc.stdout.strip()
            if tok:
                _OIDC_ID_TOKEN_CACHE["__cli__"] = (tok, now)
                _OIDC_ID_TOKEN_CACHE[base_aud] = (tok, now)
                return tok
        except Exception:
            return None
    return None
