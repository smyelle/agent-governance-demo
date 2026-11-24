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

"""Web UI & Cloud Run Compliance Test Suite for Cymbal Core Operations & Release Agent."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from web.api import create_bff_app


@pytest.fixture()
def bff_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("CYMBAL_BFF_OFFLINE", "true")
    monkeypatch.setenv("CYMBAL_RUNTIME_STATE_DIR", str(tmp_path / "runtime_state"))
    monkeypatch.delenv("K_SERVICE", raising=False)
    monkeypatch.delenv("K_REVISION", raising=False)
    app = create_bff_app(offline_mode=True)
    return TestClient(app, base_url="http://127.0.0.1:8080")


def test_local_http_bootstrap_and_security_headers(bff_client: TestClient) -> None:
    health = bff_client.get("/healthz")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert health.json()["service"] == "cymbal-ops-release-web"
    assert health.json()["target"] == "local_dev"

    idx = bff_client.get("/")
    assert idx.status_code == 200
    assert 'id="runtime-env-pill"' in idx.text
    assert 'id="vertical-pipeline-list"' in idx.text

    csp = idx.headers.get("content-security-policy", "")
    assert "default-src 'self'" in csp
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp
    assert idx.headers.get("x-content-type-options") == "nosniff"
    assert idx.headers.get("x-frame-options") == "DENY"
    assert idx.headers.get("cross-origin-opener-policy") == "same-origin-allow-popups"
    assert idx.headers.get("cross-origin-resource-policy") == "same-origin"
    assert "camera=()" in idx.headers.get("permissions-policy", "")

    set_cookie = idx.headers.get("set-cookie", "").lower()
    assert "cymbal_sid=" in set_cookie
    assert "httponly" in set_cookie
    assert "samesite=strict" in set_cookie

    boot = bff_client.get("/api/bootstrap")
    assert boot.status_code == 200
    assert boot.headers.get("cache-control") == "no-store"

    payload = boot.json()
    assert payload["csrf_token"]
    assert payload["runtime_environment"]["target"] == "local_dev"
    services = payload["platform_services"]["services"]
    assert len(services) == 9
    assert [s["step"] for s in services] == list(range(1, 10))


def test_cloud_run_https_proxy_headers_and_host_cookie(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CYMBAL_BFF_OFFLINE", "true")
    monkeypatch.setenv("CYMBAL_RUNTIME_STATE_DIR", str(tmp_path / "cr_state"))
    monkeypatch.setenv("K_SERVICE", "cymbal-ops-release-web")
    monkeypatch.setenv("K_REVISION", "cymbal-ops-release-web-00001-rev")

    app = create_bff_app(offline_mode=True)
    client = TestClient(app, base_url="http://127.0.0.1:8080")

    cr_headers = {
        "X-Forwarded-Proto": "https",
        "X-Forwarded-For": "203.0.113.42, 34.117.0.1",
        "X-Goog-Authenticated-User-Email": "accounts.google.com:operator@example.org",
    }
    boot = client.get("/api/bootstrap", headers=cr_headers)
    assert boot.status_code == 200
    assert "max-age=" in boot.headers.get("strict-transport-security", "")

    raw_cookie = boot.headers.get("set-cookie", "")
    assert raw_cookie.startswith("__Host-cymbal_sid=")
    lower_cookie = raw_cookie.lower()
    assert "secure" in lower_cookie
    assert "httponly" in lower_cookie
    assert "samesite=strict" in lower_cookie
    assert "path=/" in lower_cookie
    assert "domain=" not in lower_cookie

    rt = boot.json()["runtime_environment"]
    assert rt["target"] == "cloud_run"
    assert rt["service_name"] == "cymbal-ops-release-web"
    assert rt["revision"] == "cymbal-ops-release-web-00001-rev"
    assert rt["https_enforced"] is True
    assert rt["iap_verified"] is True
    assert "operator@example.org" not in str(rt)


def test_stateless_signed_csrf_and_session_revocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CYMBAL_BFF_OFFLINE", "true")
    monkeypatch.setenv("CYMBAL_RUNTIME_STATE_DIR", str(tmp_path / "csrf_state"))
    app_instance_1 = create_bff_app(offline_mode=True)
    app_instance_2 = create_bff_app(offline_mode=True)

    c1 = TestClient(app_instance_1, base_url="http://127.0.0.1:8080")
    boot = c1.get("/api/bootstrap")
    csrf = boot.json()["csrf_token"]
    sid = c1.cookies.get("cymbal_sid")
    assert sid

    # Missing CSRF token must fail 403
    no_csrf = c1.post("/api/config/mode", json={"architecture_mode": "enterprise_hybrid"})
    assert no_csrf.status_code == 403

    # Forged CSRF token must fail 403
    bad_csrf = c1.post(
        "/api/config/mode",
        headers={"X-CSRF-Token": "00" * 32},
        json={"architecture_mode": "enterprise_hybrid"},
    )
    assert bad_csrf.status_code == 403

    # Second horizontally scaled Cloud Run instance accepts valid HMAC-signed cookie + CSRF
    c2 = TestClient(app_instance_2, base_url="http://127.0.0.1:8080")
    c2.cookies.set("cymbal_sid", sid)
    ok_resp = c2.post(
        "/api/config/mode",
        headers={"X-CSRF-Token": csrf},
        json={"architecture_mode": "enterprise_hybrid"},
    )
    assert ok_resp.status_code == 200
    assert ok_resp.json()["architecture_mode"] == "enterprise_hybrid"

    # Explicit session reset revokes cookie and emits Clear-Site-Data
    reset = c2.post("/api/session/reset", headers={"X-CSRF-Token": csrf})
    assert reset.status_code == 200
    assert "cookies" in reset.headers.get("clear-site-data", "")

    post_revoke = c2.post(
        "/api/config/mode",
        headers={"X-CSRF-Token": csrf},
        json={"architecture_mode": "google_native"},
    )
    assert post_revoke.status_code == 403


def test_fetch_metadata_cross_site_isolation_and_method_allowlist(
    bff_client: TestClient,
) -> None:
    # Cross-site API request rejected pre-auth with 403
    blocked_api = bff_client.get(
        "/api/bootstrap",
        headers={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "cors"},
    )
    assert blocked_api.status_code == 403

    # Cross-site iframe embed rejected with 403
    blocked_iframe = bff_client.get(
        "/",
        headers={
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "iframe",
        },
    )
    assert blocked_iframe.status_code == 403

    # Standard top-level link navigation allowed
    nav_ok = bff_client.get(
        "/",
        headers={
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document",
        },
    )
    assert nav_ok.status_code == 200

    # Disallowed HTTP methods rejected with 405
    put_res = bff_client.put("/api/bootstrap")
    assert put_res.status_code == 405
    del_res = bff_client.delete("/api/bootstrap")
    assert del_res.status_code == 405


def test_end_to_end_triage_hitl_resume_and_runtime_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_dir = tmp_path / "nonroot_state"
    monkeypatch.setenv("CYMBAL_BFF_OFFLINE", "true")
    monkeypatch.setenv("CYMBAL_RUNTIME_STATE_DIR", str(state_dir))
    app = create_bff_app(offline_mode=True)
    client = TestClient(app, base_url="http://127.0.0.1:8080")

    boot = client.get("/api/bootstrap")
    csrf = boot.json()["csrf_token"]
    headers = {"X-CSRF-Token": csrf}

    # 1. Dynamic Per-Request Model Armor Policy Router (Inline SDP Mask vs Strict BU Block)
    guard_res = client.post(
        "/api/steward/guardrail-test",
        headers=headers,
        json={
            "sample_text": "Log snippet: subscriber SSN 123-45-6789 on MAC aa:bb:cc:dd:ee:ff",
            "dynamic_policy": {
                "business_unit": "core_cable",
                "risk_tier": "AG2",
                "sdp_pii_mode": "DEIDENTIFY_INLINE",
                "ensemble_role": "tier0_prefilter",
            },
        },
    )
    assert guard_res.status_code == 200
    g_body = guard_res.json()
    assert g_body["allowed"] is True
    assert g_body["pii_masked"] is True
    assert "123-45-6789" not in g_body["sanitized_text"]

    strict_res = client.post(
        "/api/steward/guardrail-test",
        headers=headers,
        json={
            "sample_text": "Log snippet: subscriber SSN 123-45-6789",
            "dynamic_policy": {
                "business_unit": "intl_sky",
                "risk_tier": "AG3",
                "sdp_pii_mode": "BLOCK_ON_MATCH",
                "ensemble_role": "parallel_ensemble_voter",
            },
        },
    )
    assert strict_res.status_code == 200
    assert strict_res.json()["allowed"] is False
    assert strict_res.json()["action_taken"] == "BLOCKED_SDP_PII_POLICY"

    # 2. ADK 2.0 Governance Audit pauses at AG3 RequestInput checkpoint
    triage = client.post(
        "/api/agent/audit",
        headers=headers,
        json={
            "candidate_id": "CAND-101",
            "agent_name": "billing-dispute-assistant",
            "app_id": "SVC-CYMBAL-101",
            "operator_prompt": (
                "Audit CAND-101 (billing-dispute-assistant) and prepare Terraform Paved-Path deployment."
            ),
            "architecture_mode": "enterprise_hybrid",
        },
    )
    assert triage.status_code == 200
    t_body = triage.json()
    assert t_body["status"] == "WAITING_AG3_APPROVAL"
    assert t_body["pending_approval"]["interrupt_id"].startswith("ag3_deploy_")

    # 3. Durable HITL resume executes governed A2A Paved-Path deployment
    resume = client.post(
        "/api/agent/resume",
        headers=headers,
        json={
            "session_id": t_body["session_id"],
            "interrupt_id": t_body["pending_approval"]["interrupt_id"],
            "approved": True,
            "approver_principal": "gov-steward-lead",
            "reason": "Verified Terraform Paved Path & Golden Blueprint in smoke test.",
        },
    )
    assert resume.status_code == 200
    r_body = resume.json()
    assert r_body["status"] == "COMPLETED"
    assert r_body["remediation_outcome"]["status"] == "DEPLOYED_PAVED_PATH"
    assert r_body["remediation_outcome"]["compliance_verified"] is True

    # 4. 6-Stage Closed-Loop Optimizer writes runtime artifacts safely under CYMBAL_RUNTIME_STATE_DIR
    fly = client.post("/api/steward/closed-loop-eval", headers=headers, json={})
    assert fly.status_code == 200
    assert fly.json()["status"] == "PROMOTED_V2"
    assert fly.json()["flywheel_stages_count"] == 6
    assert (state_dir / "prompts" / "active_version.json").is_file()
    assert (state_dir / "prompts" / "enterprise_golden_blueprint_v2.json").is_file()
