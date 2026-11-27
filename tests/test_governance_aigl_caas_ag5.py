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

"""Tests for AG5 unconditional blocks, 12-domain/49-factor CaaS, 7-phase AIGL, ADR-004, RUB-01..10, and YAML starters."""

from __future__ import annotations

from pathlib import Path

import pytest

from cymbal_agent.governance.model_armor_guard import (
    DynamicGuardrailPolicyPayload,
    FailClosedModelArmorGuard,
)
from cymbal_agent.governance.workbench_state import (
    AIGL_PHASE_SPECS,
    CAAS_49_FACTORS,
    CAAS_RISK_DOMAINS,
    ORDERED_SLOT_IDS,
    PHASE5_REVIEWER_ROLES,
    AgentDeploymentTemplate,
    SlotSelectionConfig,
    WorkbenchGovernanceEngine,
    _build_default_rubric,
    _default_slot_map,
    apply_remediation_action_to_template,
    build_localized_slot_catalog,
    calculate_template_component_costs,
    evaluate_caas_49_factor_matrix,
    evaluate_phase5_reviewer_gate,
    evaluate_template_against_rubric,
    export_template_to_yaml,
    generate_terraform_paved_path_preview,
    list_local_starter_templates,
    load_local_starter_template,
    parse_uploaded_template_manifest,
)
from cymbal_agent.schemas import Phase5ReviewerSignoff
import cymbal_agent.tenant as tenant_mod
from cymbal_agent.tenant import SlotTcoOverride, TenantProfile, load_tenant_profile


def _compliant_template(
    *,
    provider: str = "cymbal_stack",
    risk_tier: str = "AG2",
    template_mode: str = "custom",
) -> AgentDeploymentTemplate:
    return AgentDeploymentTemplate(
        template_id=f"tpl-{provider}-{risk_tier.lower()}",
        name=f"tpl-{provider}-{risk_tier.lower()}",
        template_mode=template_mode,  # type: ignore[arg-type]
        agent_name=f"agent-{provider}-{risk_tier.lower()}",
        app_id="svc-cymbal-500",
        intake_id="atlas-2026-5000",
        business_unit="core_cable",
        risk_tier=risk_tier,  # type: ignore[arg-type]
        static_secrets_in_env=[],
        destructive_mcp_tools_exposed=False,
        uap_cel_per_tool_enforced=True,
        sdp_pii_mode="DEIDENTIFY_INLINE",
        prompt_version="v2",
        behavior_score=95.0,
        components=_default_slot_map(provider),  # type: ignore[arg-type]
    )


def test_ag5_unconditional_block_across_rubric_exceptions_deploy_armor_and_phase5(
    tmp_path: Path,
) -> None:
    prof = load_tenant_profile(profile_override="cymbal_core")
    rubric = _build_default_rubric(prof)

    # Even 10/10 google_gcp slots with 100.0 score MUST be blocked when risk_tier == AG5
    ag5_tpl = _compliant_template(provider="google_gcp", risk_tier="AG5", template_mode="google_gcp")
    ev = evaluate_template_against_rubric(ag5_tpl, rubric, profile=prof)
    assert ev["overall_score"] == 100.0
    assert ev["ag5_prohibited_blocked"] is True
    assert ev["gate_passed"] is False
    assert ev["overall_status"] == "BLOCKED"
    assert ev["mandatory_failures_count"] >= 1
    assert ev["recommendations"][0]["rec_id"] == "REC-AEGIS-AG5"
    assert ev["recommendations"][0]["severity"] == "MANDATORY_GATE"
    assert ev["recommendations"][0]["status"] == "BLOCKED"

    # Exception override cannot bypass AG5
    with pytest.raises(ValueError, match="AG5"):
        apply_remediation_action_to_template(
            ag5_tpl,
            rule_id="RUB-03",
            action="exception",
            rubric=rubric,
            exception_reason="Requested override",
            profile=prof,
        )

    # Workbench record_deployment rejects AG5
    engine = WorkbenchGovernanceEngine(state_dir=tmp_path / "wb")
    with pytest.raises(ValueError, match="AG5"):
        engine.record_deployment(template=ag5_tpl, initial_score=100.0)

    # FailClosedModelArmorGuard blocks AG5 unconditionally even offline on benign text
    guard = FailClosedModelArmorGuard(live_api_enabled=False)
    verdict = guard.inspect_text(
        "Benign status check",
        dynamic_policy=DynamicGuardrailPolicyPayload(risk_tier="AG5"),
    )
    assert verdict.allowed is False
    assert verdict.filter_match_state == "POLICY_PROHIBITED"
    assert verdict.action_taken == "BLOCKED_PROHIBITED_AG5_TIER"

    # Phase 5 7-reviewer gate forces all 7 roles Denied on AG5
    p5 = evaluate_phase5_reviewer_gate(ag5_tpl)
    assert p5["verdict"] == "DENIED"
    assert p5["denied_count"] == 7
    assert all(r["status"] == "Denied" for r in p5["reviewers"])


def test_caas_12_domain_49_factor_matrix_and_level2_collapse() -> None:
    assert len(CAAS_RISK_DOMAINS) == 12
    assert sum(d["factor_count"] for d in CAAS_RISK_DOMAINS) == 49
    assert len(CAAS_49_FACTORS) == 49

    prof = load_tenant_profile(profile_override="cymbal_core")

    # 1. AG2 all-GCP -> Level 0 (49/49 Google-certified automated)
    ag2_gcp = _compliant_template(provider="google_gcp", risk_tier="AG2", template_mode="google_gcp")
    m_ag2 = evaluate_caas_49_factor_matrix(ag2_gcp, profile=prof)
    assert m_ag2["total_domains"] == 12
    assert m_ag2["total_factors"] == 49
    assert m_ag2["effective_caas_level"] == "Level 0"
    assert m_ag2["platform_covered_count"] == 49
    assert m_ag2["manual_review_count"] == 0

    # 2. AG3/AG4 all-GCP -> collapses Level 2 -> Level 1
    for tier in ("AG3", "AG4"):
        tpl = _compliant_template(provider="google_gcp", risk_tier=tier, template_mode="google_gcp")
        m_high = evaluate_caas_49_factor_matrix(tpl, profile=prof)
        assert m_high["baseline_caas_level"] == "Level 2"
        assert m_high["effective_caas_level"] == "Level 1"
        assert m_high["collapsed_from_level_2"] is True
        assert m_high["platform_covered_count"] == 49

    # 3. All custom/cymbal_stack -> Level 2 (manual review factors remain)
    ag3_cust = _compliant_template(provider="cymbal_stack", risk_tier="AG3")
    m_cust = evaluate_caas_49_factor_matrix(ag3_cust, profile=prof)
    assert m_cust["effective_caas_level"] == "Level 2"
    assert m_cust["collapsed_from_level_2"] is False
    assert m_cust["manual_review_count"] > 0

    # 4. AG5 -> Prohibited
    ag5_gcp = _compliant_template(provider="google_gcp", risk_tier="AG5", template_mode="google_gcp")
    m_ag5 = evaluate_caas_49_factor_matrix(ag5_gcp, profile=prof)
    assert m_ag5["baseline_caas_level"] == "Prohibited"
    assert m_ag5["effective_caas_level"] == "Prohibited"
    factor_map = {f["factor_id"]: f for f in m_ag5["factors"]}
    assert factor_map["f04_level_of_autonomy"]["coverage_state"] == "prohibited_ag5"
    assert factor_map["f05_agency_tier_ag1_ag5"]["coverage_state"] == "prohibited_ag5"
    dom_map = {d["domain_id"]: d for d in m_ag5["domains"]}
    assert dom_map["inherent_use_case_risk"]["status"] == "PROHIBITED"


def test_aigl_7_phases_and_phase5_7_reviewer_gate() -> None:
    assert [p["phase"] for p in AIGL_PHASE_SPECS] == [1, 2, 3, 4, 5, 6, 7]
    assert [p["ui_stage"] for p in AIGL_PHASE_SPECS] == [
        "build",
        "build",
        "build",
        "evaluate",
        "deploy",
        "govern",
        "govern",
    ]
    assert PHASE5_REVIEWER_ROLES == (
        "VP",
        "HR",
        "IP",
        "Privacy",
        "PTnO",
        "Compliance",
        "Intl Legal",
    )

    prof = load_tenant_profile(profile_override="cymbal_core")
    rubric = _build_default_rubric(prof)

    # AG5 clamps AIGL at phase 4 (BLOCKED) and marks phases 5-7 NOT_PERMITTED
    ag5_tpl = _compliant_template(provider="google_gcp", risk_tier="AG5", template_mode="google_gcp")
    ag5_tpl.aigl_phase = 6
    ev_ag5 = evaluate_template_against_rubric(ag5_tpl, rubric, profile=prof)
    aigl_ag5 = ev_ag5["aigl_lifecycle"]
    assert aigl_ag5["current_phase"] == 4
    phase_status = {p["phase"]: p["status"] for p in aigl_ag5["phases"]}
    assert phase_status[4] == "BLOCKED"
    assert phase_status[5] == "NOT_PERMITTED"
    assert phase_status[6] == "NOT_PERMITTED"
    assert phase_status[7] == "NOT_PERMITTED"

    # DEPLOYED template reaches phase 7 with phases 1-6 COMPLETED
    dep_tpl = _compliant_template(provider="google_gcp", risk_tier="AG2", template_mode="google_gcp")
    dep_tpl.lifecycle_status = "DEPLOYED"
    ev_dep = evaluate_template_against_rubric(dep_tpl, rubric, profile=prof)
    assert ev_dep["aigl_lifecycle"]["current_phase"] == 7
    assert all(p["status"] == "COMPLETED" for p in ev_dep["aigl_lifecycle"]["phases"][:6])

    # Phase 5 reviewer gate: PENDING_REVIEW -> DENIED -> APPROVED
    draft_tpl = _compliant_template(provider="cymbal_stack", risk_tier="AG3")
    draft_tpl.caas_risk_level = "Level 2"
    assert evaluate_phase5_reviewer_gate(draft_tpl)["verdict"] == "PENDING_REVIEW"

    draft_tpl.reviewer_signoffs = [
        Phase5ReviewerSignoff(role="Privacy", status="Denied", notes="Missing PIA")
    ]
    assert evaluate_phase5_reviewer_gate(draft_tpl)["verdict"] == "DENIED"

    draft_tpl.reviewer_signoffs = [
        Phase5ReviewerSignoff(
            role=role,  # type: ignore[arg-type]
            status="Approved with Conditions" if role == "Compliance" else "Approved",
            reviewer_principal="board-lead",
        )
        for role in PHASE5_REVIEWER_ROLES
    ]
    approved_gate = evaluate_phase5_reviewer_gate(draft_tpl)
    assert approved_gate["verdict"] == "APPROVED"
    assert approved_gate["approved_count"] == 7


def test_adr004_90_day_recertification_timer_recertify_expire_and_offboard(
    tmp_path: Path,
) -> None:
    engine = WorkbenchGovernanceEngine(state_dir=tmp_path / "wb_adr004")
    records = engine.list_recertification_records()
    assert len(records) >= 5
    # INACTIVE / EXPIRED / shortest days_remaining sorted first
    assert records[0]["activity_status"] == "INACTIVE"

    agent_id = "broadband-outage-triage-agent"
    d10 = engine.advance_recertification_timer(agent_id, cycle_day=10, days_since_activity=2)
    assert d10["lifecycle_state"] == "CURRENT"
    assert d10["alert_stage"] == "NONE"
    assert d10["activity_status"] == "ACTIVE"
    assert d10["identity_enabled"] is True

    d75 = engine.advance_recertification_timer(agent_id, cycle_day=75, days_since_activity=5)
    assert d75["lifecycle_state"] == "DUE_SOON"
    assert d75["alert_stage"] == "DAY_75_DUE_IN_15D"

    d85 = engine.advance_recertification_timer(agent_id, cycle_day=85, days_since_activity=5)
    assert d85["alert_stage"] == "DAY_85_REMINDER_5D"

    d89 = engine.advance_recertification_timer(agent_id, cycle_day=89, days_since_activity=31)
    assert d89["alert_stage"] == "DAY_89_FINAL_WARNING_1D"
    assert d89["activity_status"] == "INACTIVE"

    d90 = engine.advance_recertification_timer(agent_id, cycle_day=90, days_since_activity=31)
    assert d90["lifecycle_state"] == "EXPIRED"
    assert d90["alert_stage"] == "DAY_90_EXPIRED"
    assert d90["days_remaining"] == 0
    assert d90["identity_enabled"] is False

    # Recertify resets cycle_day=0, days_remaining=90, prunes scopes_removed, re-enables identity
    recert = engine.recertify_agent(
        agent_id,
        scopes_confirmed=["telemetry.read", "memory.read"],
        scopes_removed=["memory.read"],
        certified_by="steward@enterprise.example",
    )
    assert recert["cycle_day"] == 0
    assert recert["days_remaining"] == 90
    assert recert["lifecycle_state"] == "CURRENT"
    assert recert["identity_enabled"] is True
    assert recert["current_scopes"] == ["telemetry.read"]
    assert recert["audit_log"][0]["action"] == "RECERTIFIED"

    # Expire disables identity immediately
    expired = engine.expire_agent(agent_id, reason="Missed 90-day attestation")
    assert expired["lifecycle_state"] == "EXPIRED"
    assert expired["alert_stage"] == "DAY_90_EXPIRED"
    assert expired["identity_enabled"] is False

    # Offboard decommissions agent and matching fleet deployments
    offboarded = engine.offboard_agent(
        agent_id,
        actor="steward@enterprise.example",
        transfer_owner="archive-steward-team",
    )
    assert offboarded["lifecycle_state"] == "DECOMMISSIONED"
    assert offboarded["identity_enabled"] is False
    assert offboarded["current_scopes"] == []
    assert offboarded["owner_team"] == "archive-steward-team"
    metrics = engine.build_operations_metrics()
    matching_deps = [d for d in metrics["deployments"] if d["agent_name"] == agent_id]
    assert matching_deps and all(d["status"] == "DECOMMISSIONED" for d in matching_deps)


def test_rub_01_to_10_google_target_85_baseline_advisories_yaml_starters_and_enterprise_sync(
    tmp_path: Path,
) -> None:
    prof = load_tenant_profile(profile_override="cymbal_core")
    rubric = _build_default_rubric(prof)

    assert len(rubric.rules) == 10
    assert all(r.remediation_provider == "google_gcp" for r in rubric.rules)

    # Compliant 100% existing stack scores exact 85.0 with 10 ADVISORY recommendations totaling +15.0
    baseline_tpl = _compliant_template(provider="cymbal_stack", risk_tier="AG2")
    ev_base = evaluate_template_against_rubric(baseline_tpl, rubric, profile=prof)
    assert ev_base["overall_score"] == 85.0
    assert ev_base["gate_passed"] is True
    assert ev_base["overall_status"] == "READY_FOR_DEPLOYMENT"
    assert ev_base["mandatory_failures_count"] == 0
    assert len(ev_base["recommendations"]) == 10
    assert all(r["severity"] == "ADVISORY" for r in ev_base["recommendations"])
    assert all(r["recommended_provider"] == "google_gcp" for r in ev_base["recommendations"])
    assert round(sum(r["score_uplift_pts"] for r in ev_base["recommendations"]), 1) == 15.0

    # YAML export <-> import round-trip preserves risk/AIGL/CaaS and all 10 components
    exported_yaml = export_template_to_yaml(baseline_tpl)
    reimported = parse_uploaded_template_manifest(
        exported_yaml, filename="baseline-roundtrip.yaml", profile=prof
    )
    assert reimported.risk_tier == baseline_tpl.risk_tier
    assert reimported.aigl_phase == baseline_tpl.aigl_phase
    assert reimported.caas_risk_level == baseline_tpl.caas_risk_level
    assert list(reimported.components.keys()) == ORDERED_SLOT_IDS
    assert all(c.provider == "cymbal_stack" for c in reimported.components.values())

    # Starter template listing, loading & path traversal protection (isolated in tmp_path)
    starters_dir = tmp_path / "starters"
    starters_dir.mkdir(parents=True)
    (starters_dir / "synthetic_baseline.local.yaml").write_text(exported_yaml, encoding="utf-8")
    listed = list_local_starter_templates(starters_dir=starters_dir, profile=prof)
    assert len(listed) == 1
    assert listed[0]["starter_id"] == "synthetic_baseline"
    assert listed[0]["overall_score"] == 85.0
    loaded_starter = load_local_starter_template(
        "synthetic_baseline", starters_dir=starters_dir, profile=prof
    )
    assert loaded_starter.agent_name == baseline_tpl.agent_name

    for bad_id in ("../secrets", "sub/dir", "sub\\dir", ""):
        with pytest.raises(ValueError):
            load_local_starter_template(bad_id, starters_dir=starters_dir, profile=prof)
    with pytest.raises(FileNotFoundError):
        load_local_starter_template("does-not-exist", starters_dir=starters_dir, profile=prof)

    # enterprise_sync_enabled toggle on Google Cloud slots (+$15/mo bridge & Terraform HCL flags)
    gcp_sync_on = _compliant_template(provider="google_gcp", risk_tier="AG2", template_mode="google_gcp")
    costs_on = calculate_template_component_costs(gcp_sync_on, profile=prof)
    hcl_on = generate_terraform_paved_path_preview(gcp_sync_on, profile=prof)

    bridge_slots = {"identity_access", "agent_registry", "observability_tracing"}
    on_map = {c["slot_id"]: c for c in costs_on["component_costs"]}
    for sid in bridge_slots:
        assert on_map[sid]["sync_bridge_monthly_usd"] == 15.0
        assert on_map[sid]["sync_mode"] == "transition_bridge"

    assert 'gateway_primary_engine  = "google_agent_gateway_psci_uap_cel"' in hcl_on
    assert "entra_wif_federation_sync = true" in hcl_on
    assert "enterprise_catalog_sync = true" in hcl_on
    assert "enterprise_otlp_sync    = true" in hcl_on
    assert prof.governance_defaults.hybrid_otlp_placeholder_url in hcl_on

    # Disable enterprise_sync_enabled via customize remediation action and verify persistence + $45/mo savings
    updated_sync = gcp_sync_on
    for rule_id in ("RUB-01", "RUB-02", "RUB-08"):
        updated_sync = apply_remediation_action_to_template(
            updated_sync,
            rule_id=rule_id,
            action="customize",
            rubric=rubric,
            custom_provider="google_gcp",
            custom_parameters={"enterprise_sync_enabled": False},
            profile=prof,
        )
    for sid in bridge_slots:
        assert updated_sync.components[sid].enterprise_sync_enabled is False

    costs_off = calculate_template_component_costs(updated_sync, profile=prof)
    assert round(costs_on["monthly_run_rate_usd"] - costs_off["monthly_run_rate_usd"], 2) == 45.0
    off_map = {c["slot_id"]: c for c in costs_off["component_costs"]}
    for sid in bridge_slots:
        assert off_map[sid]["sync_bridge_monthly_usd"] == 0.0
        assert off_map[sid]["sync_mode"] == "google_primary_only"

    hcl_off = generate_terraform_paved_path_preview(updated_sync, profile=prof)
    assert "entra_wif_federation_sync = false" in hcl_off
    assert "enterprise_catalog_sync = false" in hcl_off
    assert "enterprise_otlp_sync    = false" in hcl_off
    assert 'secondary_otlp_endpoint = ""' in hcl_off


def test_localized_slot_consolidates_and_rub_capability_delta(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # (a) Generic cymbal_core baseline retains SLOT_CATALOG_SPECS consolidates strings
    core_prof = load_tenant_profile(profile_override="cymbal_core")
    core_catalog = {s["slot_id"]: s for s in build_localized_slot_catalog(core_prof)}
    assert core_catalog["identity_access"]["consolidates"] == "Okta OBO Sidecars, Keycard, HashiCorp Vault"
    assert core_catalog["ai_gateway"]["consolidates"] == "Kong AI Gateway, LiteLLM, Agentgateway, Runlayer"

    baseline_tpl = _compliant_template(provider="cymbal_stack", risk_tier="AG2")
    core_eval = evaluate_template_against_rubric(
        baseline_tpl, _build_default_rubric(core_prof), profile=core_prof
    )
    core_recs = {r["rule_id"]: r for r in core_eval["recommendations"]}
    assert "Okta OBO Sidecars, Keycard, HashiCorp Vault" in core_recs["RUB-01"]["capability_delta"]
    assert "Kong AI Gateway, LiteLLM, Agentgateway, Runlayer" in core_recs["RUB-03"]["capability_delta"]

    # (b) Synthetic vendor-neutral TenantProfile with slot_tco_overrides for all 10 slots
    synthetic_consolidates = {
        sid: f"Acme Internal {sid.replace('_', ' ').title()} Suite"
        for sid in ORDERED_SLOT_IDS
    }
    synthetic_cymbal_names = {
        sid: f"Acme {sid.replace('_', ' ').title()} Stack"
        for sid in ORDERED_SLOT_IDS
    }
    custom_data = core_prof.model_dump()
    custom_data["profile_key"] = "acme_localized"
    custom_data["terminology"]["slot_cymbal_names"] = synthetic_cymbal_names
    custom_data["terminology"]["slot_tco_overrides"] = {
        sid: {
            "cymbal_stack": SlotTcoOverride(
                consolidates=synthetic_consolidates[sid]
            ).model_dump()
        }
        for sid in ORDERED_SLOT_IDS
    }
    custom_prof = TenantProfile.model_validate(custom_data)

    custom_catalog = {s["slot_id"]: s for s in build_localized_slot_catalog(custom_prof)}
    for sid in ORDERED_SLOT_IDS:
        assert custom_catalog[sid]["consolidates"] == synthetic_consolidates[sid]
        assert custom_catalog[sid]["cymbal_name"] == synthetic_cymbal_names[sid]

    custom_eval = evaluate_template_against_rubric(
        baseline_tpl, _build_default_rubric(custom_prof), profile=custom_prof
    )
    assert len(custom_eval["recommendations"]) == 10
    forbidden_oss = (
        "Okta OBO Sidecars",
        "Backstage Plugins",
        "Kong AI Gateway",
        "Guardrails AI",
        "Self-Hosted vLLM",
        "LangGraph Server",
        "Redis Vector Store",
        "Self-Hosted Langfuse",
        "Revenium",
        "Promptfoo",
    )
    for rec in custom_eval["recommendations"]:
        sid = rec["slot_id"]
        delta = rec["capability_delta"]
        assert synthetic_consolidates[sid] in delta
        for oss_str in forbidden_oss:
            assert oss_str not in delta

    # Whitespace-only consolidates override must fall back to SLOT_CATALOG_SPECS default
    ws_data = core_prof.model_dump()
    ws_data["profile_key"] = "acme_whitespace"
    ws_data["terminology"]["slot_tco_overrides"] = {
        "ai_gateway": {"cymbal_stack": SlotTcoOverride(consolidates="   ").model_dump()}
    }
    ws_prof = TenantProfile.model_validate(ws_data)
    ws_catalog = {s["slot_id"]: s for s in build_localized_slot_catalog(ws_prof)}
    assert ws_catalog["ai_gateway"]["consolidates"] == core_catalog["ai_gateway"]["consolidates"]
    ws_eval = evaluate_template_against_rubric(
        baseline_tpl, _build_default_rubric(ws_prof), profile=ws_prof
    )
    ws_recs = {r["rule_id"]: r for r in ws_eval["recommendations"]}
    assert core_catalog["ai_gateway"]["consolidates"] in ws_recs["RUB-03"]["capability_delta"]
    assert "Consolidates     onto" not in ws_recs["RUB-03"]["capability_delta"]

    # Verify build_executive_cost_summary() surfaces localized consolidates via active local override
    import yaml

    synthetic_local = tmp_path / "tenant_profile.local.yaml"
    profile_entry = dict(custom_data)
    profile_entry.pop("profile_key", None)
    synthetic_local.write_text(
        yaml.safe_dump({"active_profile": "acme_localized", "profiles": {"acme_localized": profile_entry}}),
        encoding="utf-8",
    )
    with monkeypatch.context() as mctx:
        mctx.delenv("CYMBAL_TENANT_PROFILE", raising=False)
        mctx.delenv("CYMBAL_TENANT_OVERRIDE_YAML", raising=False)
        mctx.setattr(tenant_mod, "LOCAL_OVERRIDE_PATH", synthetic_local)
        engine = WorkbenchGovernanceEngine(state_dir=tmp_path / "wb_localized")
        finops = engine.build_executive_cost_summary()
        rollup_map = {c["slot_id"]: c for c in finops["component_cost_rollup"]}
        for sid in ORDERED_SLOT_IDS:
            assert rollup_map[sid]["consolidates"] == synthetic_consolidates[sid]

    # (c) Guarded verification against real developer local override file (without literal customer strings)
    if tenant_mod.LOCAL_OVERRIDE_PATH.is_file():
        monkeypatch.delenv("CYMBAL_TENANT_PROFILE", raising=False)
        monkeypatch.delenv("CYMBAL_TENANT_OVERRIDE_YAML", raising=False)
        local_prof = load_tenant_profile()
        assert local_prof.profile_key != "cymbal_core"
        local_catalog = {s["slot_id"]: s for s in build_localized_slot_catalog(local_prof)}
        local_eval = evaluate_template_against_rubric(
            baseline_tpl, _build_default_rubric(local_prof), profile=local_prof
        )
        local_recs = {r["slot_id"]: r for r in local_eval["recommendations"]}
        for sid in ORDERED_SLOT_IDS:
            ov = local_prof.terminology.slot_tco_overrides[sid]["cymbal_stack"]
            assert ov.consolidates
            assert local_catalog[sid]["consolidates"] == ov.consolidates
            assert ov.consolidates in local_recs[sid]["capability_delta"]
            assert "Okta OBO Sidecars" not in local_recs[sid]["capability_delta"]
            assert "Kong AI Gateway" not in local_recs[sid]["capability_delta"]
