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

import json
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from web.api import STATIC_DIR, create_bff_app


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
    assert 'id="sidebar-brand-title"' in idx.text
    assert 'id="pinned-template-section"' not in idx.text
    assert 'id="ten-tile-strip"' not in idx.text
    assert 'id="right-inspector-drawer"' not in idx.text
    assert 'id="runtime-env-pill"' not in idx.text

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
    blocked_api = bff_client.get(
        "/api/bootstrap",
        headers={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "cors"},
    )
    assert blocked_api.status_code == 403

    blocked_iframe = bff_client.get(
        "/",
        headers={
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "iframe",
        },
    )
    assert blocked_iframe.status_code == 403

    nav_ok = bff_client.get(
        "/",
        headers={
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document",
        },
    )
    assert nav_ok.status_code == 200

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

    fly = client.post("/api/steward/closed-loop-eval", headers=headers, json={})
    assert fly.status_code == 200
    assert fly.json()["status"] == "PROMOTED_V2"
    assert fly.json()["flywheel_stages_count"] == 6
    assert (state_dir / "prompts" / "active_version.json").is_file()
    assert (state_dir / "prompts" / "enterprise_golden_blueprint_v2.json").is_file()


def test_production_cymbal_lifecycle_console_and_zero_meta_terms(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CYMBAL_BFF_OFFLINE", "true")
    monkeypatch.setenv("CYMBAL_RUNTIME_STATE_DIR", str(tmp_path / "lifecycle_state"))
    app = create_bff_app(offline_mode=True)
    client = TestClient(app, base_url="http://127.0.0.1:8080")

    # 1. Verify all 4 Lifecycle SPA routes & production Cymbal Agent Governance Platform shell
    for route in ("/", "/build", "/evaluate", "/deploy", "/govern"):
        html_res = client.get(route)
        assert html_res.status_code == 200
        assert "Cymbal Agent Governance Platform" in html_res.text
        assert 'id="left-lifecycle-nav"' in html_res.text
        assert 'id="pinned-template-section"' not in html_res.text
        assert 'id="center-workspace"' in html_res.text
        assert 'id="right-inspector-drawer"' not in html_res.text
        assert 'id="template-profile-fieldset"' not in html_res.text
        assert 'data-stage="build"' in html_res.text
        assert 'data-stage="evaluate"' in html_res.text
        assert 'data-stage="deploy"' in html_res.text
        assert 'data-stage="govern"' in html_res.text

    # 2. Enforce zero "Mock" / "Persona" / "User Journey" meta-language in frontend assets & bootstrap data
    for asset_name in ("index.html", "styles.css", "app.js"):
        asset_text = (STATIC_DIR / asset_name).read_text(encoding="utf-8").lower()
        assert "mock" not in asset_text, f"Forbidden term 'mock' found in {asset_name}"
        assert "persona" not in asset_text, f"Forbidden term 'persona' found in {asset_name}"
        assert "user journey" not in asset_text

    boot = client.get("/api/bootstrap").json()
    for section_key in ("tenant", "slot_catalog", "templates", "rubric", "operations_metrics", "executive_costs"):
        serialized = json.dumps(boot[section_key]).lower()
        assert "mock" not in serialized, f"Forbidden term 'mock' in bootstrap.{section_key}"
        assert "persona" not in serialized, f"Forbidden term 'persona' in bootstrap.{section_key}"

    csrf = boot["csrf_token"]
    headers = {"X-CSRF-Token": csrf}

    # 3. Verify 10 vendor-neutral functional components, real vendor/OSS + Google names & seeded inventory
    assert len(boot["slot_catalog"]) == 10
    for slot_item in boot["slot_catalog"]:
        assert slot_item["gcp_name"].startswith("Google "), slot_item
        assert not slot_item["cymbal_name"].startswith("Cymbal "), slot_item
    slot_map = {s["slot_id"]: s for s in boot["slot_catalog"]}
    assert slot_map["identity_access"]["gcp_name"] == "Google Agent Identity (SPIFFE + WIF)"
    assert slot_map["runtime_sandbox"]["gcp_name"] == "Google Agent Runtime (Agent Engine + gVisor)"
    assert slot_map["identity_access"]["cymbal_name"] == "Okta OIDC + HashiCorp Vault"

    css_text = (STATIC_DIR / "styles.css").read_text(encoding="utf-8")
    assert "overflow: clip;" in css_text
    assert ".pagination-bar" in css_text
    assert ".component-expander" in css_text
    assert ".segmented-radio-input" in css_text
    assert ".table-filter-row" in css_text
    assert ".inline-action-form" in css_text
    assert ".inline-single-action-row" in css_text
    assert ".four-tile-strip" in css_text
    assert ".subtab-bar" not in css_text
    js_text = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    assert "Select functional capability" not in js_text
    assert "buildActiveAgentContextBar" not in js_text
    assert "subtab-bar" not in js_text
    assert "buildNestedComponentExpanders" in js_text
    assert "buildNestedEvaluateExpanders" in js_text
    assert "buildExpandedDeployRow" in js_text
    assert "buildInteractiveTableHead" in js_text
    assert "populateGovernPoliciesBody" in js_text
    assert "populateGovernFleetBody" in js_text
    assert "populateGovernFinopsBody" in js_text
    assert "populateGovernControlsBody" in js_text
    assert 'providers.every((p) => p === "google_gcp")' not in js_text
    assert boot["tenant"]["terminology"]["sidebar_brand"] == "Cymbal Agent Governance Platform"

    assert len(boot["templates"]) >= 25
    for t_item in boot["templates"]:
        assert "gate_verdict" in t_item
        assert "recommendations_count" in t_item
        assert "component_costs" in t_item
    tpl_timestamps = [t["updated_at"] for t in boot["templates"]]
    assert tpl_timestamps == sorted(tpl_timestamps, reverse=True)
    statuses = {t["lifecycle_status"] for t in boot["templates"]}
    assert statuses == {"DEPLOYED", "DRAFT"}

    dep_list = boot["operations_metrics"]["deployments"]
    assert len(dep_list) >= 22
    dep_timestamps = [d["deployed_at"] for d in dep_list]
    assert dep_timestamps == sorted(dep_timestamps, reverse=True)
    tpl_by_id = {t["template_id"]: t for t in boot["templates"]}
    assert "example-agent-1" in tpl_by_id
    assert "network-telemetry-advisor" in tpl_by_id
    assert "subscriber-billing-concierge" in tpl_by_id
    assert all(
        c["provider"] == "google_gcp"
        for c in tpl_by_id["network-telemetry-advisor"]["components"].values()
    )
    assert all(
        c["provider"] == "cymbal_stack"
        for c in tpl_by_id["subscriber-billing-concierge"]["components"].values()
    )

    # 4. Build -> Import Manifest -> Evaluate -> Remediate -> Deploy -> Govern
    bad_upload = client.post(
        "/api/templates/upload",
        headers=headers,
        json={"filename": "malicious.py", "content": "print('nope')"},
    )
    assert bad_upload.status_code == 400

    unmanaged_yaml = (
        "agent_name: unmanaged-claims-agent\n"
        "app_id: svc-cymbal-999\n"
        "intake_id: ''\n"
        "business_unit: core_cable\n"
        "risk_tier: AG3\n"
        "static_secrets_in_env: ['LEGACY_API_KEY']\n"
        "destructive_mcp_tools_exposed: true\n"
        "uap_cel_per_tool_enforced: false\n"
        "sdp_pii_mode: NONE\n"
        "behavior_score: 55.0\n"
        "components:\n"
        "  runtime_sandbox: cymbal_stack\n"
    )
    up_res = client.post(
        "/api/templates/upload",
        headers=headers,
        json={"filename": "unmanaged-claims.yaml", "content": unmanaged_yaml},
    )
    assert up_res.status_code == 200
    working_tpl = up_res.json()["template"]
    eval_initial = up_res.json()["evaluation"]
    assert eval_initial["gate_passed"] is False
    assert eval_initial["overall_score"] < 50.0
    assert set(eval_initial["pillar_scores"].keys()) == {
        "Control",
        "Intelligence",
        "Economics",
        "Experience",
    }

    # Save template via /api/agents/save
    save_res = client.post("/api/agents/save", headers=headers, json=working_tpl)
    assert save_res.status_code == 200
    assert any(t["agent_name"] == "unmanaged-claims-agent" for t in save_res.json()["templates"])

    # Premature deploy must fail gate check (400)
    blocked_dep = client.post(
        "/api/templates/deploy",
        headers=headers,
        json={"template": working_tpl, "initial_score": eval_initial["overall_score"]},
    )
    assert blocked_dep.status_code == 400

    # Remediate findings via customize + accept
    initial_score = eval_initial["overall_score"]
    cur_eval = eval_initial
    for idx, rec in enumerate(list(cur_eval["recommendations"])):
        if idx == 0:
            rem_res = client.post(
                "/api/templates/remediate",
                headers=headers,
                json={
                    "template": working_tpl,
                    "rule_id": rec["rule_id"],
                    "action": "customize",
                    "custom_provider": "google_gcp",
                    "custom_parameters": {"clear_static_secrets": True},
                },
            )
        else:
            rem_res = client.post(
                "/api/templates/remediate",
                headers=headers,
                json={
                    "template": working_tpl,
                    "rule_id": rec["rule_id"],
                    "action": "accept",
                },
            )
        assert rem_res.status_code == 200
        working_tpl = rem_res.json()["template"]
        cur_eval = rem_res.json()["evaluation"]

    assert cur_eval["gate_passed"] is True
    assert cur_eval["overall_score"] >= 95.0

    dep_before_cnt = boot["operations_metrics"]["total_deployments"]
    hist_before_usd = boot["executive_costs"]["total_historical_cumulative_usd"]

    dep_res = client.post(
        "/api/templates/deploy",
        headers=headers,
        json={
            "template": working_tpl,
            "initial_score": initial_score,
            "approver_principal": "platform-governance-lead",
        },
    )
    assert dep_res.status_code == 200
    dep_payload = dep_res.json()
    assert dep_payload["deployment"]["remediated_prior_to_deploy"] is True
    assert dep_payload["operations_metrics"]["total_deployments"] == dep_before_cnt + 1
    assert dep_payload["executive_costs"]["total_historical_cumulative_usd"] > hist_before_usd
    assert len(dep_payload["executive_costs"]["component_cost_rollup"]) == 10
    assert len(dep_payload["executive_costs"]["pillar_cost_rollup"]) == 4

    # Govern -> Policies & Rubric live threshold update immediately governs Evaluate
    rubric = boot["rubric"]
    rubric["passing_score_threshold"] = 99.5
    rub_save = client.post("/api/ops/rubric", headers=headers, json=rubric)
    assert rub_save.status_code == 200
    re_eval = client.post(
        "/api/templates/evaluate",
        headers=headers,
        json={"template": tpl_by_id["subscriber-billing-concierge"]},
    )
    assert re_eval.status_code == 200
    assert re_eval.json()["evaluation"]["passing_threshold"] == 99.5
    assert re_eval.json()["evaluation"]["gate_passed"] is False
