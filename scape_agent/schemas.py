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

"""Strict Pydantic schemas for every ADK 2.0 Workflow node, LlmAgent, and HITL gate."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class IncidentTriggerInput(BaseModel):
    incident_id: str = Field(default="INC-4092", description="Incident ticket identifier.")
    service_name: str = Field(default="flow-intel-api", description="Impacted service name.")
    app_id: str = Field(default="DEVHUB-SCAPE-992", description="CMDB application identifier.")
    operator_prompt: str = Field(
        default="Investigate INC-4092 latency spike on flow-intel-api and recommend governed remediation.",
        description="On-call engineer triage request.",
    )
    user_id: str = Field(default="sre-oncall-01", description="Authenticated JWT subject.")
    scape_mode: Literal["google_native", "comcast_hybrid"] = Field(default="google_native")


class IntakeContextOutput(BaseModel):
    incident_id: str
    service_name: str
    app_id: str
    sanitized_operator_prompt: str
    memory_context: str
    recalled_facts_count: int = 0
    pii_masked_inline: bool = False


class ObservabilitySignal(BaseModel):
    incident_id: str
    service_name: str
    baseline_p99_ms: float
    current_p99_ms: float
    latency_samples_ms: list[float] = Field(default_factory=list)
    error_rate_pct: float
    valkey_stream: str
    valkey_memory_saturation_pct: float
    active_release: str
    prior_healthy_release: str
    degraded_503: bool = False
    summary: str


class JiraChangeSignal(BaseModel):
    service_name: str
    deployed_version: str
    rollback_target_version: str
    jira_ticket: str
    recent_pr: str
    change_freeze_active: bool
    freeze_window_name: str
    vp_exception_required: bool
    summary: str


class CmdbRunbookSignal(BaseModel):
    app_id: str
    owning_squad: str
    clara_intake_id: str
    aegis_risk_tier: str
    downstream_blast_radius: list[str] = Field(default_factory=list)
    ama_runbook_id: str
    ama_runbook_steps: list[str] = Field(default_factory=list)
    summary: str


class CorrelatedSignalsBundle(BaseModel):
    incident_id: str
    service_name: str
    app_id: str
    observability: ObservabilitySignal
    jira_change: JiraChangeSignal
    cmdb_runbook: CmdbRunbookSignal
    sandbox_code_prompt: str


class SandboxAnomalyOutput(BaseModel):
    z_score: float
    p99_delta_multiplier: float
    saturation_breach: bool
    sandbox_runtime: str = "gvisor_builtin_code_executor"
    calculation_summary: str


class IncidentAssessment(BaseModel):
    incident_id: str
    service_name: str
    app_id: str
    root_cause_summary: str
    risk_level: Literal["AG1", "AG3"]
    recommended_route: Literal["info_or_ag1", "remediation_ag3"]
    change_freeze_detected: bool = False
    vp_exception_required: bool = False
    degraded_telemetry_mode: bool = False
    target_rollback_from: str = "v2.14.3"
    target_rollback_to: str = "v2.14.2"
    remediation_plan: str
    citations: list[str] = Field(default_factory=list)


class ApprovalGatePayload(BaseModel):
    interrupt_id: str
    incident_id: str
    service_name: str
    app_id: str
    risk_level: str
    from_version: str
    to_version: str
    change_freeze_active: bool
    vp_exception_required: bool
    remediation_plan: str


class RollbackApprovalDecision(BaseModel):
    approved: bool
    approver_principal: str = Field(default="sre-lead-approver")
    vp_exception_ticket: str | None = Field(default=None)
    reason: str = Field(default="Verified golden signals and blast radius.")


class RemediationOutcome(BaseModel):
    status: Literal["ROLLED_BACK", "HELD_FOR_MANUAL_EXCEPTION", "ADVISORY_ONLY"]
    incident_id: str
    service_name: str
    task_id: str
    post_rollback_p99_ms: float | None = None
    slo_recovered: bool = False
    summary: str


class PostmortemMemoryRecord(BaseModel):
    incident_id: str
    service_name: str
    final_status: str
    memory_persisted: bool
    trace_id: str
    executive_summary: str
