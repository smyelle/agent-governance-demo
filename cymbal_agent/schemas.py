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

"""Strict Pydantic schemas for the ADK 2.0 Agent Governance, Optimization & Deployment Workflow."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class GovernanceAuditTriggerInput(BaseModel):
    candidate_id: str = Field(default="CAND-101", description="Candidate agent identifier.")
    agent_name: str = Field(
        default="billing-dispute-assistant", description="Candidate agent workload name."
    )
    app_id: str = Field(default="SVC-CYMBAL-101", description="Enterprise CMDB & Supergraph ID.")
    operator_prompt: str = Field(
        default=(
            "Audit CAND-101 (billing-dispute-assistant) against Tier-1 governance gates, "
            "remediate security/prompt gaps, and prepare Paved-Path deployment."
        ),
        description="Governance reviewer or agent owner instruction.",
    )
    user_id: str = Field(default="gov-reviewer-01", description="Authenticated JWT subject.")
    architecture_mode: Literal["enterprise_hybrid", "google_native"] = Field(
        default="enterprise_hybrid"
    )


class IntakeContextOutput(BaseModel):
    candidate_id: str
    agent_name: str
    app_id: str
    sanitized_operator_prompt: str
    memory_context: str
    recalled_facts_count: int = 0
    pii_masked_inline: bool = False


class ManifestSecuritySignal(BaseModel):
    candidate_id: str
    agent_name: str
    business_unit: str
    runtime_cloud: str
    onboarding_path: str
    static_secrets_found: list[str] = Field(default_factory=list)
    gateway_routed: bool
    spiffe_or_obo_configured: bool
    a2a_card_compliant: bool
    otlp_exporter_configured: bool
    destructive_tools_in_pool: list[str] = Field(default_factory=list)
    guardrail_config_state: str
    current_prompt_version: str
    target_version: str
    summary: str


class Tier1IntakeSupergraphSignal(BaseModel):
    candidate_id: str
    app_id: str
    owning_squad: str
    intake_id: str
    intake_approved: bool
    supergraph_indexed: bool
    catalog_registered: bool
    wallet_quota_bound: bool
    risk_tier: str
    aegis_risk_level: Literal["R1", "R2", "R3", "R4", "R5"] = "R2"
    caas_risk_level: Literal["Level 0", "Level 1", "Level 2", "Prohibited"] = "Level 1"
    aigl_phase: int = Field(default=1, ge=1, le=7)
    policy_freeze_active: bool
    freeze_window_name: str
    vp_exception_required: bool
    downstream_blast_radius: list[str] = Field(default_factory=list)
    checklist_items_passed: int
    checklist_items_total: int
    summary: str


class ProductionTraceEvalSignal(BaseModel):
    candidate_id: str
    agent_name: str
    source_telemetry_platform: str
    cloud_provider: str
    baseline_eval_score: float
    trace_latency_samples_ms: list[float] = Field(default_factory=list)
    failure_rate_pct: float
    hallucinated_tool_calls: int
    unmasked_pii_leaks_detected: int
    failing_trace_clusters: list[str] = Field(default_factory=list)
    degraded_503: bool = False
    summary: str


class CorrelatedGovernanceBundle(BaseModel):
    candidate_id: str
    agent_name: str
    app_id: str
    manifest_security: ManifestSecuritySignal
    tier1_supergraph: Tier1IntakeSupergraphSignal
    production_traces: ProductionTraceEvalSignal
    sandbox_code_prompt: str


class SandboxReadinessOutput(BaseModel):
    readiness_score: float
    z_score: float
    p99_delta_multiplier: float
    blast_radius_breach: bool
    sandbox_runtime: str = "gvisor_builtin_code_executor"
    calculation_summary: str


class GovernanceRemediationAssessment(BaseModel):
    candidate_id: str
    agent_name: str
    app_id: str
    governance_gaps_summary: str
    risk_level: Literal["AG1", "AG2", "AG3", "AG4", "AG5"]
    recommended_route: Literal[
        "advisory_ag1",
        "deploy_ag3_gate",
        "freeze_quarantine",
        "prohibited_ag5_block",
    ]
    policy_freeze_detected: bool = False
    vp_exception_required: bool = False
    degraded_telemetry_mode: bool = False
    from_version: str = "v1"
    to_version: str = "v2-golden-blueprint"
    dynamic_guardrail_spec: str = ""
    terraform_paved_path_hcl: str = ""
    remediation_plan: str
    citations: list[str] = Field(default_factory=list)


class GovernanceApprovalGatePayload(BaseModel):
    interrupt_id: str
    candidate_id: str
    agent_name: str
    app_id: str
    risk_level: str
    from_version: str
    to_version: str
    policy_freeze_active: bool
    vp_exception_required: bool
    remediation_plan: str
    terraform_paved_path_hcl: str = ""


class GovernanceReviewerDecision(BaseModel):
    approved: bool
    approver_principal: str = Field(default="gov-steward-lead")
    vp_exception_ticket: str | None = Field(default=None)
    reason: str = Field(
        default="Verified Tier-1 compliance hooks, dynamic guardrail spec, and Golden Blueprint."
    )


class DeploymentRemediationOutcome(BaseModel):
    status: Literal[
        "DEPLOYED_PAVED_PATH",
        "HELD_FOR_GOVERNANCE_EXCEPTION",
        "ADVISORY_COMPLIANT_AG1",
        "PROHIBITED_AG5_BLOCKED",
    ]
    candidate_id: str
    agent_name: str
    task_id: str
    golden_blueprint_id: str | None = None
    post_deploy_readiness_score: float | None = None
    compliance_verified: bool = False
    terraform_paved_path_hcl: str = ""
    summary: str


class Phase5ReviewerSignoff(BaseModel):
    role: Literal["VP", "HR", "IP", "Privacy", "PTnO", "Compliance", "Intl Legal"]
    status: Literal["Approved", "Approved with Conditions", "Denied", "Pending"] = "Pending"
    conditions: str = ""
    notes: str = ""
    reviewer_principal: str = ""
    updated_at: str = ""


class Adr004RecertificationRecord(BaseModel):
    agent_id: str
    agent_name: str
    description: str = ""
    owner_team: str = ""
    owner_email: str = ""
    current_scopes: list[str] = Field(default_factory=list)
    activity_status: Literal["ACTIVE", "INACTIVE"] = "ACTIVE"
    lifecycle_state: Literal["CURRENT", "DUE_SOON", "EXPIRED", "DECOMMISSIONED"] = "CURRENT"
    alert_stage: Literal[
        "NONE",
        "DAY_75_DUE_IN_15D",
        "DAY_85_REMINDER_5D",
        "DAY_89_FINAL_WARNING_1D",
        "DAY_90_EXPIRED",
    ] = "NONE"
    identity_enabled: bool = True
    cycle_day: int = Field(default=12, ge=0, le=365)
    days_remaining: int = Field(default=78, ge=0, le=90)
    days_since_last_llm_call: int = Field(default=2, ge=0)
    days_since_last_a2a_message: int = Field(default=2, ge=0)
    next_review_date: str = ""
    last_certified_by: str = ""
    last_certified_at: str = ""
    audit_log: list[dict[str, Any]] = Field(default_factory=list)


class GovernanceAuditMemoryRecord(BaseModel):
    candidate_id: str
    agent_name: str
    final_status: str
    memory_persisted: bool
    trace_id: str
    executive_summary: str


# Aliases preserving clean imports across existing runtime entrypoints
IncidentTriggerInput = GovernanceAuditTriggerInput
CorrelatedSignalsBundle = CorrelatedGovernanceBundle
SandboxAnomalyOutput = SandboxReadinessOutput
IncidentAssessment = GovernanceRemediationAssessment
ApprovalGatePayload = GovernanceApprovalGatePayload
RollbackApprovalDecision = GovernanceReviewerDecision
RemediationOutcome = DeploymentRemediationOutcome
PostmortemMemoryRecord = GovernanceAuditMemoryRecord
