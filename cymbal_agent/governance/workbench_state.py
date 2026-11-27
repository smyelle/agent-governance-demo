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

"""Cymbal Platform Lifecycle, Governance Rubric, Fleet Operations & FinOps Engine.

Powers the four lifecycle workspaces:
- Build: 10-component Agent Deployment Template tool (Google Cloud vs. Custom
  Cymbal / Google Cloud selection) + Registered & Draft Agents inventory.
- Evaluate: Governance pillar & workstream rubric scoring, remediation queue,
  and 6-stage behavioral prompt/trace optimization.
- Deploy: Terraform module & dynamic guardrail policy synthesis, approval gate,
  and production fleet enrollment.
- Govern: Live Rubric policies, Fleet Operations analytics, FinOps & Economics
  per-agent and 10-component / 4-pillar cost attribution, and Runtime Controls.
"""

from __future__ import annotations

import copy
import datetime
import json
import os
from pathlib import Path
import re
import threading
from typing import Any, Literal
import uuid

from pydantic import BaseModel, Field
import yaml

from cymbal_agent.schemas import Adr004RecertificationRecord, Phase5ReviewerSignoff
from cymbal_agent.tenant import REPO_ROOT, TenantProfile, load_tenant_profile

STARTERS_DIR = REPO_ROOT / "config" / "starters"

ProviderChoice = Literal[
    "cymbal_stack",
    "google_gcp",
    "unconfigured",
]

TemplateMode = Literal["google_gcp", "custom"]

TemplateOrigin = Literal[
    "google_gcp_standard",
    "cymbal_baseline",
    "custom_hybrid",
    "imported_manifest",
]

MAX_TEMPLATE_UPLOAD_BYTES = 512 * 1024
SAFE_SLUG_RE = re.compile(r"[^a-zA-Z0-9_-]+")

# Map legacy provider keys seamlessly onto production keys
LEGACY_PROVIDER_ALIAS: dict[str, ProviderChoice] = {
    "cymbal_stack": "cymbal_stack",
    "enterprise_mock": "cymbal_stack",
    "google_gcp": "google_gcp",
    "gcp_native": "google_gcp",
    "coexistence_bridge": "google_gcp",
    "unconfigured": "unconfigured",
}

LEGACY_SLOT_ALIAS: dict[str, str] = {
    "agent_identity": "identity_access",
    "agent_gateway": "ai_gateway",
    "trace_observability": "observability_tracing",
    "wallet_kill_switch": "cost_kill_controls",
    "agent_runtime_sandbox": "runtime_sandbox",
    "session_memory": "memory_knowledge",
    "eval_optimizer": "eval_optimization",
}


class SlotSelectionConfig(BaseModel):
    slot_id: str = Field(..., min_length=2, max_length=64)
    provider: ProviderChoice = "google_gcp"
    enabled: bool = True
    enterprise_sync_enabled: bool = True
    parameters: dict[str, Any] = Field(default_factory=dict)


class AgentDeploymentTemplate(BaseModel):
    template_id: str = Field(..., min_length=3, max_length=80)
    name: str = Field(..., min_length=2, max_length=140)
    description: str = Field(default="", max_length=600)
    template_mode: TemplateMode = "custom"
    origin: TemplateOrigin = "custom_hybrid"
    agent_name: str = Field(default="example-agent-1", min_length=2, max_length=80)
    app_id: str = Field(default="svc-cymbal-992", min_length=3, max_length=64)
    intake_id: str = Field(default="atlas-2026-0841", max_length=64)
    business_unit: Literal[
        "core_cable", "media_studio", "intl_sky", "enterprise_shared"
    ] = "core_cable"
    risk_tier: Literal["AG1", "AG2", "AG3", "AG4", "AG5"] = "AG2"
    aegis_risk_level: Literal["R1", "R2", "R3", "R4", "R5"] = "R2"
    aigl_phase: int = Field(default=4, ge=1, le=7)
    caas_risk_level: Literal["Level 0", "Level 1", "Level 2", "Prohibited"] = "Level 1"
    reviewer_signoffs: list[Phase5ReviewerSignoff] = Field(default_factory=list)
    onboarding_path: Literal[
        "Path A: Protocol Adapter",
        "Path B: SDK Integration",
        "Path C: Greenfield",
    ] = "Path C: Greenfield"
    runtime_cloud: Literal["gcp", "aws", "azure", "hybrid_multicloud"] = "gcp"
    estimated_monthly_turns_millions: float = Field(default=3.5, ge=0.1, le=100.0)
    static_secrets_in_env: list[str] = Field(default_factory=list)
    destructive_mcp_tools_exposed: bool = False
    uap_cel_per_tool_enforced: bool = True
    sdp_pii_mode: Literal[
        "DEIDENTIFY_INLINE", "BLOCK_ON_MATCH", "INSPECT_ONLY", "NONE"
    ] = "DEIDENTIFY_INLINE"
    prompt_version: str = Field(default="v2", max_length=40)
    behavior_score: float = Field(default=96.4, ge=0.0, le=100.0)
    system_instruction: str = Field(
        default=(
            "You are a governed Cymbal specialist agent. Enforce policy boundaries, "
            "never echo raw PII, respect active release freeze windows, and handle "
            "upstream 503 tool degradations gracefully with bounded retries."
        ),
        max_length=8000,
    )
    components: dict[str, SlotSelectionConfig] = Field(default_factory=dict)
    applied_remediations: list[str] = Field(default_factory=list)
    exception_overrides: dict[str, str] = Field(default_factory=dict)
    lifecycle_status: Literal["DRAFT", "DEPLOYED"] = "DRAFT"
    latest_deployment_id: str = ""
    updated_at: str = ""
    updated_display: str = ""


class RubricRule(BaseModel):
    rule_id: str = Field(..., min_length=3, max_length=40)
    slot_id: str = Field(..., min_length=2, max_length=64)
    pillar: Literal["Control", "Intelligence", "Economics", "Experience"] = "Control"
    workstream: str = Field(default="Identity & Access Management", max_length=80)
    title: str = Field(..., min_length=4, max_length=160)
    description: str = Field(..., min_length=6, max_length=500)
    mandatory: bool = True
    weight_points: int = Field(default=10, ge=1, le=40)
    min_behavior_score: float | None = Field(default=None, ge=0.0, le=100.0)
    remediation_provider: ProviderChoice = "google_gcp"
    remediation_summary: str = Field(default="", max_length=400)
    enabled: bool = True


class RubricConfig(BaseModel):
    rubric_id: str = "cymbal-platform-rubric-v2"
    name: str = "Cymbal Platform Governance Rubric"
    passing_score_threshold: float = Field(default=85.0, ge=50.0, le=100.0)
    require_enterprise_catalog_sync: bool = True
    updated_by: str = "platform-governance-ops"
    updated_at: str = ""
    rules: list[RubricRule] = Field(default_factory=list)


# 10 Canonical Vendor-Neutral Functional Component Tiles
SLOT_CATALOG_SPECS: list[dict[str, Any]] = [
    {
        "slot_id": "identity_access",
        "step": 1,
        "functional_name": "Identity & Access",
        "pillar": "Control",
        "workstream": "Identity & Access Management",
        "gcp_name": "Google Agent Identity (SPIFFE + WIF)",
        "api_surface": "agentidentity.googleapis.com + sts.googleapis.com (WIF)",
        "consolidates": "Okta OBO Sidecars, Keycard, HashiCorp Vault",
        "pricing": {
            "cymbal_stack": {"base_monthly_usd": 140.0, "infra_monthly_usd": 50.0, "maintenance_monthly_usd": 90.0, "per_1m_turns_usd": 22.0, "onboarding_usd": 180.0},
            "google_gcp": {"base_monthly_usd": 50.0, "infra_monthly_usd": 35.0, "maintenance_monthly_usd": 15.0, "per_1m_turns_usd": 7.0, "onboarding_usd": 65.0},
            "unconfigured": {"base_monthly_usd": 0.0, "infra_monthly_usd": 0.0, "maintenance_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
        },
    },
    {
        "slot_id": "agent_registry",
        "step": 2,
        "functional_name": "Agent Registry",
        "pillar": "Control",
        "workstream": "Agent Registry & Discovery",
        "gcp_name": "Google Agent Registry",
        "api_surface": "agentregistry.googleapis.com + Catalog Sync",
        "consolidates": "Backstage Plugins, ServiceNow Sync Pipelines",
        "pricing": {
            "cymbal_stack": {"base_monthly_usd": 110.0, "infra_monthly_usd": 40.0, "maintenance_monthly_usd": 70.0, "per_1m_turns_usd": 10.0, "onboarding_usd": 210.0},
            "google_gcp": {"base_monthly_usd": 45.0, "infra_monthly_usd": 30.0, "maintenance_monthly_usd": 15.0, "per_1m_turns_usd": 5.0, "onboarding_usd": 60.0},
            "unconfigured": {"base_monthly_usd": 0.0, "infra_monthly_usd": 0.0, "maintenance_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
        },
    },
    {
        "slot_id": "ai_gateway",
        "step": 3,
        "functional_name": "AI & Tool Gateway",
        "pillar": "Control",
        "workstream": "Gateway & Action Authorization",
        "gcp_name": "Google Agent Gateway (PSC-I + UAP CEL)",
        "api_surface": "networkservices.googleapis.com/agentGateways + UAP Policy V2",
        "consolidates": "Kong AI Gateway, LiteLLM, Agentgateway, Runlayer",
        "pricing": {
            "cymbal_stack": {"base_monthly_usd": 230.0, "infra_monthly_usd": 90.0, "maintenance_monthly_usd": 140.0, "per_1m_turns_usd": 58.0, "onboarding_usd": 200.0},
            "google_gcp": {"base_monthly_usd": 105.0, "infra_monthly_usd": 80.0, "maintenance_monthly_usd": 25.0, "per_1m_turns_usd": 26.0, "onboarding_usd": 85.0},
            "unconfigured": {"base_monthly_usd": 0.0, "infra_monthly_usd": 0.0, "maintenance_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
        },
    },
    {
        "slot_id": "safety_guardrails",
        "step": 4,
        "functional_name": "Safety Guardrails",
        "pillar": "Control",
        "workstream": "Policy Guardrails",
        "gcp_name": "Google Model Armor + Cloud SDP",
        "api_surface": "modelarmor.us-central1.rep.googleapis.com + dlp.googleapis.com",
        "consolidates": "Guardrails AI, Microsoft Presidio, Straiker.ai",
        "pricing": {
            "cymbal_stack": {"base_monthly_usd": 180.0, "infra_monthly_usd": 70.0, "maintenance_monthly_usd": 110.0, "per_1m_turns_usd": 1000.0, "onboarding_usd": 250.0},
            "google_gcp": {"base_monthly_usd": 45.0, "infra_monthly_usd": 35.0, "maintenance_monthly_usd": 10.0, "per_1m_turns_usd": 100.0, "onboarding_usd": 75.0},
            "unconfigured": {"base_monthly_usd": 0.0, "infra_monthly_usd": 0.0, "maintenance_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
        },
    },
    {
        "slot_id": "foundation_model",
        "step": 5,
        "functional_name": "Foundation Model",
        "pillar": "Intelligence",
        "workstream": "Model Governance",
        "gcp_name": "Google Gemini 3.8 Flash (Vertex AI)",
        "api_surface": "aiplatform.googleapis.com (gemini-3.8-flash 12-mo LTA)",
        "consolidates": "OpenAI / Self-Hosted vLLM Llama Endpoints",
        "pricing": {
            "cymbal_stack": {"base_monthly_usd": 120.0, "infra_monthly_usd": 50.0, "maintenance_monthly_usd": 70.0, "per_1m_turns_usd": 420.0, "onboarding_usd": 110.0},
            "google_gcp": {"base_monthly_usd": 0.0, "infra_monthly_usd": 0.0, "maintenance_monthly_usd": 0.0, "per_1m_turns_usd": 240.0, "onboarding_usd": 40.0},
            "unconfigured": {"base_monthly_usd": 0.0, "infra_monthly_usd": 0.0, "maintenance_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
        },
    },
    {
        "slot_id": "runtime_sandbox",
        "step": 6,
        "functional_name": "Runtime & Sandbox",
        "pillar": "Experience",
        "workstream": "Workload Architecture",
        "gcp_name": "Google Agent Runtime (Agent Engine + gVisor)",
        "api_surface": "aiplatform.googleapis.com/ReasoningEngine + Cloud Run",
        "consolidates": "LangGraph Server, E2B Firecracker MicroVMs",
        "pricing": {
            "cymbal_stack": {"base_monthly_usd": 260.0, "infra_monthly_usd": 110.0, "maintenance_monthly_usd": 150.0, "per_1m_turns_usd": 185.0, "onboarding_usd": 290.0},
            "google_gcp": {"base_monthly_usd": 120.0, "infra_monthly_usd": 95.0, "maintenance_monthly_usd": 25.0, "per_1m_turns_usd": 95.0, "onboarding_usd": 90.0},
            "unconfigured": {"base_monthly_usd": 0.0, "infra_monthly_usd": 0.0, "maintenance_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
        },
    },
    {
        "slot_id": "memory_knowledge",
        "step": 7,
        "functional_name": "Memory & Knowledge",
        "pillar": "Intelligence",
        "workstream": "Context & State",
        "gcp_name": "Google Vertex AI Memory Bank",
        "api_surface": "aiplatform.googleapis.com/agentEngines.memories",
        "consolidates": "Mem0, Redis Vector Store, Custom ABAC Layers",
        "pricing": {
            "cymbal_stack": {"base_monthly_usd": 175.0, "infra_monthly_usd": 75.0, "maintenance_monthly_usd": 100.0, "per_1m_turns_usd": 52.0, "onboarding_usd": 150.0},
            "google_gcp": {"base_monthly_usd": 65.0, "infra_monthly_usd": 50.0, "maintenance_monthly_usd": 15.0, "per_1m_turns_usd": 18.0, "onboarding_usd": 55.0},
            "unconfigured": {"base_monthly_usd": 0.0, "infra_monthly_usd": 0.0, "maintenance_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
        },
    },
    {
        "slot_id": "observability_tracing",
        "step": 8,
        "functional_name": "Observability & Tracing",
        "pillar": "Control",
        "workstream": "Observability & Security",
        "gcp_name": "Google Cloud Trace & Cloud Logging",
        "api_surface": "cloudtrace.googleapis.com + OTLP v1 resourceSpans",
        "consolidates": "Self-Hosted Langfuse, Custom OTLP Collectors",
        "pricing": {
            "cymbal_stack": {"base_monthly_usd": 165.0, "infra_monthly_usd": 70.0, "maintenance_monthly_usd": 95.0, "per_1m_turns_usd": 48.0, "onboarding_usd": 140.0},
            "google_gcp": {"base_monthly_usd": 65.0, "infra_monthly_usd": 50.0, "maintenance_monthly_usd": 15.0, "per_1m_turns_usd": 20.0, "onboarding_usd": 50.0},
            "unconfigured": {"base_monthly_usd": 0.0, "infra_monthly_usd": 0.0, "maintenance_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
        },
    },
    {
        "slot_id": "cost_kill_controls",
        "step": 9,
        "functional_name": "Cost & Kill Controls",
        "pillar": "Economics",
        "workstream": "Cost Governance & Containment",
        "gcp_name": "Google Firestore Atomic Wallet & Switch",
        "api_surface": "firestore.googleapis.com + bigquery.googleapis.com",
        "consolidates": "Revenium, Helicone, Ascerta (Pay-i)",
        "pricing": {
            "cymbal_stack": {"base_monthly_usd": 150.0, "infra_monthly_usd": 60.0, "maintenance_monthly_usd": 90.0, "per_1m_turns_usd": 30.0, "onboarding_usd": 130.0},
            "google_gcp": {"base_monthly_usd": 55.0, "infra_monthly_usd": 45.0, "maintenance_monthly_usd": 10.0, "per_1m_turns_usd": 12.0, "onboarding_usd": 45.0},
            "unconfigured": {"base_monthly_usd": 0.0, "infra_monthly_usd": 0.0, "maintenance_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
        },
    },
    {
        "slot_id": "eval_optimization",
        "step": 10,
        "functional_name": "Evaluation & Optimization",
        "pillar": "Intelligence",
        "workstream": "Quality Assurance",
        "gcp_name": "Google Vertex AI Gen AI Eval & Optimizer",
        "api_surface": "agentplatform.Client.evals + gemini-3.8-flash Optimizer",
        "consolidates": "LangSmith, Promptfoo, Veris Simulation",
        "pricing": {
            "cymbal_stack": {"base_monthly_usd": 280.0, "infra_monthly_usd": 100.0, "maintenance_monthly_usd": 180.0, "per_1m_turns_usd": 92.0, "onboarding_usd": 340.0},
            "google_gcp": {"base_monthly_usd": 85.0, "infra_monthly_usd": 65.0, "maintenance_monthly_usd": 20.0, "per_1m_turns_usd": 38.0, "onboarding_usd": 85.0},
            "unconfigured": {"base_monthly_usd": 0.0, "infra_monthly_usd": 0.0, "maintenance_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
        },
    },
]

SLOT_SPEC_BY_ID: dict[str, dict[str, Any]] = {s["slot_id"]: s for s in SLOT_CATALOG_SPECS}
ORDERED_SLOT_IDS: list[str] = [s["slot_id"] for s in SLOT_CATALOG_SPECS]
PILLAR_ORDER: list[str] = ["Control", "Intelligence", "Economics", "Experience"]

PHASE5_REVIEWER_ROLES: tuple[str, ...] = (
    "VP",
    "HR",
    "IP",
    "Privacy",
    "PTnO",
    "Compliance",
    "Intl Legal",
)

AIGL_PHASE_SPECS: list[dict[str, Any]] = [
    {
        "phase": 1,
        "name": "Intake & Approval",
        "ui_stage": "build",
        "owners": ["Cyber", "GTO", "Legal"],
        "key_tasks": ["AI conversational intake", "Auto-approval vs legal triage", "Agency tier classification (AG1-AG5)"],
    },
    {
        "phase": 2,
        "name": "Policy Adherence",
        "ui_stage": "build",
        "owners": ["AI Use Case Requestor"],
        "key_tasks": ["Privacy & export check", "Open-source & IPP review", "Data management & access control"],
    },
    {
        "phase": 3,
        "name": "Onboarding",
        "ui_stage": "build",
        "owners": ["AI Use Case Requestor"],
        "key_tasks": ["CMDB / Developer Portal registration", "Agent Registry & SNOW vendor enrollment", "Blueprint & identity provisioning"],
    },
    {
        "phase": 4,
        "name": "Risk Assessment",
        "ui_stage": "evaluate",
        "owners": ["Cyber (TPSA)", "Legal"],
        "key_tasks": ["49-factor / 12-domain CaaS matrix", "AEGIS threat modeling & SDL intake", "PIA & TPSA assessment"],
    },
    {
        "phase": 5,
        "name": "Deployment",
        "ui_stage": "deploy",
        "owners": ["GTO", "D&A", "AI Use Case Requestor"],
        "key_tasks": ["Agent behavioral eval gate", "7-Reviewer parallel board sign-off", "Paved-Path Terraform & lineage binding"],
    },
    {
        "phase": 6,
        "name": "Monitoring & Mitigation",
        "ui_stage": "govern",
        "owners": ["D&A", "Compliance", "Cyber", "GTO"],
        "key_tasks": ["OTLP & Cloud Trace observability", "Atomic Wallet & Kill Switch enforcement", "Continuous drift & audit alerts"],
    },
    {
        "phase": 7,
        "name": "Offboarding",
        "ui_stage": "govern",
        "owners": ["AI Use Case Requestor", "D&A"],
        "key_tasks": ["ADR-004 90-day recertification (Day 75/85/89)", "Scope pruning & EXPIRED auto-disable", "Formal decommission & ownership transfer"],
    },
]

# Canonical 12 Risk Domains / 49 Risk Factors (AI Risk & Control Catalog v0 model)
CAAS_RISK_DOMAINS: list[dict[str, Any]] = [
    {"domain_id": "inherent_use_case_risk", "name": "Inherent use-case & agent risk", "factor_count": 6, "covering_slot_id": "agent_registry", "google_certified_control": "Google Agent Registry + AEGIS AG1-AG5 Tier Gate"},
    {"domain_id": "data_model_risk", "name": "Data & model risk", "factor_count": 6, "covering_slot_id": "foundation_model", "google_certified_control": "Vertex AI Gemini 3.8 Flash LTA + Cloud SDP Data Lineage"},
    {"domain_id": "exposure_risk", "name": "Exposure risk", "factor_count": 4, "covering_slot_id": "ai_gateway", "google_certified_control": "Google Agent Gateway (PSC-I Private Ingress + Egress Control)"},
    {"domain_id": "control_governance_posture", "name": "Control & governance posture", "factor_count": 4, "covering_slot_id": "identity_access", "google_certified_control": "Google Agent Identity (SPIFFE + WIF) + UAP CEL HITL"},
    {"domain_id": "dynamic_monitoring_signals", "name": "Dynamic monitoring signals", "factor_count": 4, "covering_slot_id": "observability_tracing", "google_certified_control": "Google Cloud Trace + OTLP Drift & Anomaly Alerts"},
    {"domain_id": "validity_reliability_robustness", "name": "Validity, reliability & robustness", "factor_count": 4, "covering_slot_id": "eval_optimization", "google_certified_control": "Vertex AI Gen AI Eval & VAPO 8-Case Stress Suite"},
    {"domain_id": "safety_harm_prevention", "name": "Safety & harm prevention", "factor_count": 4, "covering_slot_id": "safety_guardrails", "google_certified_control": "Google Model Armor Dynamic Router + Atomic Kill Switch"},
    {"domain_id": "fairness_harmful_bias", "name": "Fairness & harmful bias", "factor_count": 3, "covering_slot_id": "eval_optimization", "google_certified_control": "Vertex AI Safety & Fairness Rubrics"},
    {"domain_id": "privacy_enhanced_design", "name": "Privacy-enhanced design", "factor_count": 3, "covering_slot_id": "safety_guardrails", "google_certified_control": "Inline Cloud SDP De-identification + Memory Principal Isolation"},
    {"domain_id": "accountability_transparency", "name": "Accountability, transparency & explainability", "factor_count": 4, "covering_slot_id": "observability_tracing", "google_certified_control": "Immutable BigQuery Audit Ledger + W3C Trace Lineage"},
    {"domain_id": "human_factors_contestability", "name": "Human factors, contestability & oversight quality", "factor_count": 4, "covering_slot_id": "runtime_sandbox", "google_certified_control": "ADK 2.0 Resumable RequestInput HITL + Reviewer Appeals"},
    {"domain_id": "societal_legal_environmental", "name": "Societal, legal & environmental impact", "factor_count": 3, "covering_slot_id": "cost_kill_controls", "google_certified_control": "Regional Policy Guardrails + FinOps Token Budgeting"},
]

_CAAS_FACTOR_SPECS: list[tuple[str, str, str, str, str]] = [
    # 1. Inherent use-case & agent risk (6)
    ("inherent_use_case_risk", "f01_use_case_risk_level", "Use case risk level", "automated", "GOVERN 1.1"),
    ("inherent_use_case_risk", "f02_intended_use", "Intended use & business purpose", "partially_automated", "MAP 1.1"),
    ("inherent_use_case_risk", "f03_decision_type", "Decision type & materiality", "partially_automated", "MAP 1.5"),
    ("inherent_use_case_risk", "f04_level_of_autonomy", "Level of autonomy", "automated", "GOVERN 1.3"),
    ("inherent_use_case_risk", "f05_agency_tier_ag1_ag5", "Agency tier (AG1-AG5)", "automated", "GOVERN 1.4"),
    ("inherent_use_case_risk", "f06_potential_impact", "Potential blast-radius impact", "partially_automated", "MAP 5.1"),
    # 2. Data & model risk (6)
    ("data_model_risk", "f07_info_classification", "Information classification", "automated", "MAP 2.3"),
    ("data_model_risk", "f08_training_data_provenance", "Training data type & source", "partially_automated", "MAP 2.1"),
    ("data_model_risk", "f09_data_governance", "Data governance & retention", "automated", "MANAGE 2.2"),
    ("data_model_risk", "f10_ip_copyright", "IP & copyright indemnification", "human_review", "GOVERN 4.2"),
    ("data_model_risk", "f11_model_transparency", "Model card & transparency", "automated", "MEASURE 2.8"),
    ("data_model_risk", "f12_lta_lifecycle_support", "Model 12-month LTA lifecycle", "automated", "GOVERN 1.7"),
    # 3. Exposure risk (4)
    ("exposure_risk", "f13_interaction_surface", "Interaction surface (internal vs customer)", "automated", "MAP 3.1"),
    ("exposure_risk", "f14_third_party_dependency", "Third-party MCP / A2A dependency", "automated", "MAP 3.4"),
    ("exposure_risk", "f15_regulatory_exposure", "Regulatory domain exposure", "partially_automated", "GOVERN 1.1"),
    ("exposure_risk", "f16_cross_border_residency", "Cross-border data residency", "automated", "MAP 3.5"),
    # 4. Control & governance posture (4)
    ("control_governance_posture", "f17_lifecycle_stage", "AIGL lifecycle stage posture", "automated", "GOVERN 1.2"),
    ("control_governance_posture", "f18_managed_env", "Managed vs unmanaged runtime", "automated", "MANAGE 1.3"),
    ("control_governance_posture", "f19_human_oversight_mode", "Human oversight (HITL/HOTL/HOVL)", "automated", "GOVERN 3.2"),
    ("control_governance_posture", "f20_gateway_enforcement", "Gateway & UAP CEL enforcement coverage", "automated", "MANAGE 2.4"),
    # 5. Dynamic monitoring signals (4)
    ("dynamic_monitoring_signals", "f21_drift_degradation", "Behavioral drift & score degradation", "automated", "MEASURE 4.1"),
    ("dynamic_monitoring_signals", "f22_incident_alert_volume", "Incident & alert spike volume", "automated", "MEASURE 4.2"),
    ("dynamic_monitoring_signals", "f23_threat_model_findings", "AEGIS threat model findings", "partially_automated", "MEASURE 2.7"),
    ("dynamic_monitoring_signals", "f24_control_coverage", "Active control telemetry coverage", "automated", "MEASURE 1.1"),
    # 6. Validity, reliability & robustness (4)
    ("validity_reliability_robustness", "f25_performance_validation", "Golden benchmark validation", "automated", "MEASURE 2.5"),
    ("validity_reliability_robustness", "f26_eval_representativeness", "Evaluation corpus representativeness", "partially_automated", "MEASURE 2.1"),
    ("validity_reliability_robustness", "f27_stress_testing", "503 fault & adversarial stress testing", "automated", "MEASURE 2.6"),
    ("validity_reliability_robustness", "f28_known_limitations", "Documented failure boundaries", "partially_automated", "MAP 4.1"),
    # 7. Safety & harm prevention (4)
    ("safety_harm_prevention", "f29_safety_critical_context", "Safety-critical operational context", "partially_automated", "MAP 5.2"),
    ("safety_harm_prevention", "f30_unsafe_output_potential", "Unsafe output & RAI filter posture", "automated", "MEASURE 2.11"),
    ("safety_harm_prevention", "f31_containment_rollback", "Unified kill switch & rollback readiness", "automated", "MANAGE 4.1"),
    ("safety_harm_prevention", "f32_prompt_injection_resilience", "Prompt injection & malicious URI defense", "automated", "MEASURE 2.7"),
    # 8. Fairness & harmful bias (3)
    ("fairness_harmful_bias", "f33_protected_class_impact", "Protected class impact check", "partially_automated", "MEASURE 2.10"),
    ("fairness_harmful_bias", "f34_fairness_assessment", "Fairness rubric evaluation status", "automated", "MEASURE 2.10"),
    ("fairness_harmful_bias", "f35_unequal_performance", "Unequal cohort performance monitoring", "automated", "MEASURE 4.3"),
    # 9. Privacy-enhanced design (3)
    ("privacy_enhanced_design", "f36_pii_data_basis", "PII & subscriber data lawful basis", "human_review", "GOVERN 1.5"),
    ("privacy_enhanced_design", "f37_pia_status", "Privacy Impact Assessment (PIA) status", "partially_automated", "MAP 2.3"),
    ("privacy_enhanced_design", "f38_retention_alignment", "Memory isolation & retention alignment", "automated", "MANAGE 2.2"),
    # 10. Accountability, transparency & explainability (4)
    ("accountability_transparency", "f39_ai_disclosure", "End-user AI disclosure notice", "partially_automated", "GOVERN 4.1"),
    ("accountability_transparency", "f40_interpretability", "Reasoning & tool trace interpretability", "automated", "MEASURE 2.9"),
    ("accountability_transparency", "f41_audit_traceability", "W3C traceparent & ledger traceability", "automated", "GOVERN 1.6"),
    ("accountability_transparency", "f42_docs_completeness", "Golden Blueprint & runbook completeness", "automated", "MAP 1.6"),
    # 11. Human factors, contestability & oversight quality (4)
    ("human_factors_contestability", "f43_automation_bias", "Automation bias & HITL friction check", "partially_automated", "GOVERN 3.1"),
    ("human_factors_contestability", "f44_reviewer_competence", "Designated AG3/Phase-5 reviewer sign-off", "automated", "GOVERN 3.2"),
    ("human_factors_contestability", "f45_appeal_recourse", "User appeal & exception recourse path", "partially_automated", "MANAGE 4.2"),
    ("human_factors_contestability", "f46_accessibility", "Accessibility & operator clarity", "partially_automated", "MAP 1.2"),
    # 12. Societal, legal & environmental impact (3)
    ("societal_legal_environmental", "f47_affected_community", "Affected subscriber/community impact", "human_review", "MAP 5.1"),
    ("societal_legal_environmental", "f48_regulated_domain", "Regulated telecom/media compliance", "partially_automated", "GOVERN 1.1"),
    ("societal_legal_environmental", "f49_resource_intensity", "FinOps budget cap & compute efficiency", "automated", "MEASURE 2.12"),
]

CAAS_49_FACTORS: list[dict[str, Any]] = [
    {
        "factor_id": fid,
        "domain_id": did,
        "name": fname,
        "assessment_mode": mode,
        "nist_ai_rmf": nist,
        "covering_slot_id": next(d["covering_slot_id"] for d in CAAS_RISK_DOMAINS if d["domain_id"] == did),
        "google_certified_control": next(d["google_certified_control"] for d in CAAS_RISK_DOMAINS if d["domain_id"] == did),
    }
    for did, fid, fname, mode, nist in _CAAS_FACTOR_SPECS
]


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _format_display_from_iso(iso_ts: str) -> str:
    try:
        dt = datetime.datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        hour = dt.strftime("%I").lstrip("0") or "12"
        ampm = dt.strftime("%p").lower()
        return f"{dt.month}/{dt.day}/{dt.year} {hour}:{dt.strftime('%M')}{ampm}"
    except Exception:
        return iso_ts


def _display_timestamp_now() -> str:
    return _format_display_from_iso(_utc_now_iso())


def _default_slot_map(provider: ProviderChoice) -> dict[str, SlotSelectionConfig]:
    out: dict[str, SlotSelectionConfig] = {}
    for sid in ORDERED_SLOT_IDS:
        params: dict[str, Any] = {}
        if sid == "foundation_model":
            params = {"model_id": "gemini-3.8-flash" if provider == "google_gcp" else "cymbal-vmg-collection"}
        elif sid == "safety_guardrails":
            params = {"sdp_pii_mode": "DEIDENTIFY_INLINE", "malicious_uri_filter": True}
        elif sid == "ai_gateway":
            params = {"uap_cel_per_tool": provider == "google_gcp", "a2a_enabled": True}
        elif sid == "cost_kill_controls":
            params = {"monthly_cap_usd": 2500.0, "kill_switch_scope": "model_mcp_a2a"}
        out[sid] = SlotSelectionConfig(
            slot_id=sid,
            provider=provider,
            enabled=provider != "unconfigured",
            enterprise_sync_enabled=True,
            parameters=params,
        )
    return out


def build_localized_slot_catalog(profile: TenantProfile | None = None) -> list[dict[str, Any]]:
    prof = profile or load_tenant_profile()
    cymbal_names = prof.terminology.slot_cymbal_names
    tco_overrides = prof.terminology.slot_tco_overrides
    catalog: list[dict[str, Any]] = []
    for spec in SLOT_CATALOG_SPECS:
        sid = spec["slot_id"]
        cymbal_label = cymbal_names.get(sid, f"Cymbal {spec['functional_name']}")
        slot_overrides = tco_overrides.get(sid) or {}
        cymbal_override = slot_overrides.get("cymbal_stack")
        item = copy.deepcopy(spec)
        item["capability_name"] = spec["functional_name"]
        item["cymbal_name"] = cymbal_label
        consolidates_override = (cymbal_override.consolidates or "").strip() if cymbal_override else ""
        if consolidates_override:
            item["consolidates"] = consolidates_override
        item["provider_labels"] = {
            "cymbal_stack": cymbal_label,
            "google_gcp": spec["gcp_name"],
            "unconfigured": "Unconfigured",
        }
        catalog.append(item)
    return catalog


def _build_default_rubric(profile: TenantProfile) -> RubricConfig:
    terms = profile.terminology
    now = _utc_now_iso()
    return RubricConfig(
        rubric_id="cymbal-platform-rubric-v2",
        name=terms.best_practices_name,
        passing_score_threshold=85.0,
        require_enterprise_catalog_sync=True,
        updated_by="platform-governance-ops",
        updated_at=now,
        rules=[
            RubricRule(
                rule_id="RUB-01",
                slot_id="identity_access",
                pillar="Control",
                workstream="Identity & Access Management",
                title="Zero Static Secrets & Workload Identity / OBO",
                description=(
                    "Container runtime must carry zero static API keys and authenticate via "
                    "SPIFFE workload identity or OIDC azp correlation."
                ),
                mandatory=True,
                weight_points=12,
                remediation_provider="google_gcp",
                remediation_summary="Remove static env keys and bind Google Agent Identity (SPIFFE + WIF).",
            ),
            RubricRule(
                rule_id="RUB-02",
                slot_id="agent_registry",
                pillar="Control",
                workstream="Agent Registry & Discovery",
                title=f"Approved {terms.intake_name}, {terms.cmdb_name} & Registry Enrollment",
                description=(
                    "Agent template must specify a valid Intake ID, CMDB App ID, and active "
                    "catalog registration."
                ),
                mandatory=True,
                weight_points=12,
                remediation_provider="google_gcp",
                remediation_summary="Assign approved Intake ID and upgrade to Google Agent Registry (with optional Enterprise Catalog Sync).",
            ),
            RubricRule(
                rule_id="RUB-03",
                slot_id="ai_gateway",
                pillar="Control",
                workstream="Gateway & Action Authorization",
                title="Governed Model, MCP & A2A Gateway + Per-Tool Authorization",
                description=(
                    "All model and tool traffic must route through an authorized gateway, with "
                    "inline UAP CEL per-tool rules blocking destructive MCP calls."
                ),
                mandatory=True,
                weight_points=12,
                remediation_provider="google_gcp",
                remediation_summary="Route via Google Agent Gateway with inline UAP Policy V2 CEL per-tool rules.",
            ),
            RubricRule(
                rule_id="RUB-04",
                slot_id="safety_guardrails",
                pillar="Control",
                workstream="Policy Guardrails",
                title="Dynamic Multi-BU Guardrail Policy & Inline PII Protection",
                description=(
                    "Enforce prompt-injection, malicious URI, and inline PII protection "
                    "(DEIDENTIFY_INLINE or BLOCK_ON_MATCH) across business units."
                ),
                mandatory=True,
                weight_points=12,
                remediation_provider="google_gcp",
                remediation_summary="Attach Google Model Armor Dynamic Policy Router + Inline Cloud SDP.",
            ),
            RubricRule(
                rule_id="RUB-05",
                slot_id="foundation_model",
                pillar="Intelligence",
                workstream="Model Governance",
                title="Long-Term Availability (12-Month) Foundation Model Standard",
                description=(
                    "Production agents must bind an approved enterprise foundation model with "
                    "verified lifecycle support."
                ),
                mandatory=True,
                weight_points=8,
                remediation_provider="google_gcp",
                remediation_summary="Bind Google Gemini 3.8 Flash (Vertex AI 12-month Long-Term Availability).",
            ),
            RubricRule(
                rule_id="RUB-06",
                slot_id="runtime_sandbox",
                pillar="Experience",
                workstream="Workload Architecture",
                title="Isolated Code Execution Sandbox & Standardized Terraform Module",
                description=(
                    "Agent code execution and multi-step workflows should run in an isolated "
                    "gVisor sandbox backed by standardized Terraform modules."
                ),
                mandatory=False,
                weight_points=8,
                remediation_provider="google_gcp",
                remediation_summary="Select Google Agent Runtime (Agent Engine + gVisor).",
            ),
            RubricRule(
                rule_id="RUB-07",
                slot_id="memory_knowledge",
                pillar="Intelligence",
                workstream="Context & State",
                title="Principal-Isolated Session & Longitudinal Audit Memory",
                description=(
                    "Stateful session and audit memory should enforce strict cryptographic JWT "
                    "principal isolation across users and reviewers."
                ),
                mandatory=False,
                weight_points=6,
                remediation_provider="google_gcp",
                remediation_summary="Select Google Vertex AI Memory Bank with verified JWT principal scoping.",
            ),
            RubricRule(
                rule_id="RUB-08",
                slot_id="observability_tracing",
                pillar="Control",
                workstream="Observability & Security",
                title="OpenTelemetry Distributed Span & Guardrail Trace Correlation",
                description=(
                    "Agents must emit W3C traceparent and OpenTelemetry gen_ai.* spans across "
                    "inference, guardrail, and tool hops."
                ),
                mandatory=True,
                weight_points=10,
                remediation_provider="google_gcp",
                remediation_summary="Upgrade to Google Cloud Trace & Cloud Logging (with optional OTLP dual-export sync).",
            ),
            RubricRule(
                rule_id="RUB-09",
                slot_id="cost_kill_controls",
                pillar="Economics",
                workstream="Cost Governance & Containment",
                title="Atomic Pre-Flight Budget Ceiling & Unified Kill Switch",
                description=(
                    "Agents must enforce pre-inference budget caps and honor centralized "
                    "ACTIVE / PAUSED / DISABLED containment controls."
                ),
                mandatory=True,
                weight_points=10,
                remediation_provider="google_gcp",
                remediation_summary="Bind Google Firestore Atomic Wallet preflight and unified runtime kill switch.",
            ),
            RubricRule(
                rule_id="RUB-10",
                slot_id="eval_optimization",
                pillar="Intelligence",
                workstream="Quality Assurance",
                title="Behavioral & Fault-Resilience Evaluation Gate (Score >= 85.0)",
                description=(
                    "Agent instructions and tool trajectories must score >= 85.0 across quality, "
                    "release-freeze, and upstream 503 fault simulations."
                ),
                mandatory=True,
                weight_points=10,
                min_behavior_score=85.0,
                remediation_provider="google_gcp",
                remediation_summary="Run Google Vertex AI Gen AI Eval & 6-Stage Prompt Optimizer (v2).",
            ),
        ],
    )


def _seed_agent_inventory(profile: TenantProfile) -> list[AgentDeploymentTemplate]:
    defs = profile.governance_defaults

    # 1. example-agent-1 (recent hybrid draft)
    ex1_slots = _default_slot_map("cymbal_stack")
    for gcp_sid in (
        "safety_guardrails",
        "foundation_model",
        "runtime_sandbox",
        "memory_knowledge",
        "eval_optimization",
    ):
        ex1_slots[gcp_sid] = _default_slot_map("google_gcp")[gcp_sid]

    agent_1 = AgentDeploymentTemplate(
        template_id="example-agent-1",
        name="example-agent-1",
        description="Hybrid Third-Party/OSS + Google Cloud runtime, guardrails, and evaluation.",
        template_mode="custom",
        origin="custom_hybrid",
        agent_name="example-agent-1",
        app_id=defs.cmdb_app_id,
        intake_id=defs.intake_record_id,
        business_unit="core_cable",
        risk_tier="AG2",
        onboarding_path="Path C: Greenfield",
        runtime_cloud="gcp",
        estimated_monthly_turns_millions=4.0,
        uap_cel_per_tool_enforced=True,
        sdp_pii_mode="DEIDENTIFY_INLINE",
        prompt_version="v2",
        behavior_score=96.4,
        components=ex1_slots,
        lifecycle_status="DRAFT",
        updated_at="2026-11-25T16:40:00Z",
        updated_display=_format_display_from_iso("2026-11-25T16:40:00Z"),
    )

    # 2. network-telemetry-advisor (100% Google Cloud profile)
    agent_2 = AgentDeploymentTemplate(
        template_id="network-telemetry-advisor",
        name="network-telemetry-advisor",
        description="Full Google Cloud Agent Platform deployment template.",
        template_mode="google_gcp",
        origin="google_gcp_standard",
        agent_name="network-telemetry-advisor",
        app_id="svc-cymbal-410",
        intake_id="atlas-2026-1002",
        business_unit="enterprise_shared",
        risk_tier="AG2",
        onboarding_path="Path C: Greenfield",
        runtime_cloud="gcp",
        estimated_monthly_turns_millions=5.0,
        uap_cel_per_tool_enforced=True,
        sdp_pii_mode="DEIDENTIFY_INLINE",
        prompt_version="v2",
        behavior_score=97.0,
        components=_default_slot_map("google_gcp"),
        lifecycle_status="DRAFT",
        updated_at="2026-11-25T15:15:00Z",
        updated_display=_format_display_from_iso("2026-11-25T15:15:00Z"),
    )

    # 3. subscriber-billing-concierge (Custom template selecting Third-Party / OSS components)
    agent_3 = AgentDeploymentTemplate(
        template_id="subscriber-billing-concierge",
        name="subscriber-billing-concierge",
        description="Custom deployment configuration using Third-Party / OSS components.",
        template_mode="custom",
        origin="custom_hybrid",
        agent_name="subscriber-billing-concierge",
        app_id="svc-cymbal-208",
        intake_id="atlas-2026-0889",
        business_unit="core_cable",
        risk_tier="AG2",
        onboarding_path="Path C: Greenfield",
        runtime_cloud="hybrid_multicloud",
        estimated_monthly_turns_millions=4.5,
        uap_cel_per_tool_enforced=False,
        sdp_pii_mode="DEIDENTIFY_INLINE",
        prompt_version="v2",
        behavior_score=88.5,
        components=_default_slot_map("cymbal_stack"),
        lifecycle_status="DEPLOYED",
        latest_deployment_id="DEP-2026-0902",
        updated_at="2026-06-28T16:05:00Z",
        updated_display=_format_display_from_iso("2026-06-28T16:05:00Z"),
    )

    # 4. billing-dispute-assistant (Imported unmanaged Python service needing remediation)
    s4_slots = _default_slot_map("unconfigured")
    s4_slots["foundation_model"] = _default_slot_map("cymbal_stack")["foundation_model"]
    s4_slots["runtime_sandbox"] = _default_slot_map("cymbal_stack")["runtime_sandbox"]
    agent_4 = AgentDeploymentTemplate(
        template_id="billing-dispute-assistant",
        name="billing-dispute-assistant",
        description="Imported Python service missing gateway, registry intake, telemetry, and PII guardrails.",
        template_mode="custom",
        origin="imported_manifest",
        agent_name="billing-dispute-assistant",
        app_id="svc-cymbal-101",
        intake_id="",
        business_unit="core_cable",
        risk_tier="AG3",
        onboarding_path="Path B: SDK Integration",
        runtime_cloud="gcp",
        estimated_monthly_turns_millions=3.2,
        static_secrets_in_env=["OPENAI_API_KEY"],
        destructive_mcp_tools_exposed=True,
        uap_cel_per_tool_enforced=False,
        sdp_pii_mode="NONE",
        prompt_version="v1",
        behavior_score=54.0,
        system_instruction=(
            "Resolve billing disputes immediately using any available refund or account tool."
        ),
        components=s4_slots,
        lifecycle_status="DRAFT",
        updated_at="2026-11-24T14:10:00Z",
        updated_display=_format_display_from_iso("2026-11-24T14:10:00Z"),
    )

    # 5. media-entitlement-router (Cross-cloud workload with failing trace evaluations)
    s5_slots = _default_slot_map("cymbal_stack")
    s5_slots["eval_optimization"] = SlotSelectionConfig(
        slot_id="eval_optimization", provider="unconfigured", enabled=False
    )
    agent_5 = AgentDeploymentTemplate(
        template_id="media-entitlement-router",
        name="media-entitlement-router",
        description="Cross-cloud agent enrolled in foundation services but failing 503 and freeze evaluations.",
        template_mode="custom",
        origin="imported_manifest",
        agent_name="media-entitlement-router",
        app_id="svc-cymbal-204",
        intake_id="atlas-2026-0912",
        business_unit="media_studio",
        risk_tier="AG3",
        onboarding_path="Path A: Protocol Adapter",
        runtime_cloud="aws",
        estimated_monthly_turns_millions=8.0,
        uap_cel_per_tool_enforced=True,
        sdp_pii_mode="DEIDENTIFY_INLINE",
        prompt_version="v1",
        behavior_score=58.0,
        components=s5_slots,
        lifecycle_status="DRAFT",
        updated_at="2026-11-23T17:45:00Z",
        updated_display=_format_display_from_iso("2026-11-23T17:45:00Z"),
    )

    # 6. cpe-fleet-provisioning-agent (High-agency multi-region PII & mutating tool workload)
    s6_slots = _default_slot_map("cymbal_stack")
    s6_slots["safety_guardrails"] = SlotSelectionConfig(
        slot_id="safety_guardrails", provider="unconfigured", enabled=False
    )
    agent_6 = AgentDeploymentTemplate(
        template_id="cpe-fleet-provisioning-agent",
        name="cpe-fleet-provisioning-agent",
        description="Multi-region device provisioning agent handling subscriber logs and mutating MCP tools.",
        template_mode="custom",
        origin="imported_manifest",
        agent_name="cpe-fleet-provisioning-agent",
        app_id="svc-cymbal-309",
        intake_id="atlas-2026-0944",
        business_unit="intl_sky",
        risk_tier="AG3",
        onboarding_path="Path B: SDK Integration",
        runtime_cloud="hybrid_multicloud",
        estimated_monthly_turns_millions=6.5,
        destructive_mcp_tools_exposed=True,
        uap_cel_per_tool_enforced=False,
        sdp_pii_mode="NONE",
        prompt_version="v2",
        behavior_score=89.0,
        components=s6_slots,
        lifecycle_status="DRAFT",
        updated_at="2026-11-22T09:20:00Z",
        updated_display=_format_display_from_iso("2026-11-22T09:20:00Z"),
    )

    return [agent_1, agent_2, agent_3, agent_4, agent_5, agent_6]


def normalize_template_components(
    raw_components: dict[str, Any] | None,
) -> dict[str, SlotSelectionConfig]:
    norm: dict[str, SlotSelectionConfig] = {}
    src = raw_components or {}
    remapped: dict[str, Any] = {}
    for k, v in src.items():
        canonical_key = LEGACY_SLOT_ALIAS.get(k, k)
        remapped[canonical_key] = v

    for sid in ORDERED_SLOT_IDS:
        entry = remapped.get(sid)
        if isinstance(entry, str):
            prov = LEGACY_PROVIDER_ALIAS.get(entry, "unconfigured")
            norm[sid] = SlotSelectionConfig(
                slot_id=sid, provider=prov, enabled=prov != "unconfigured"
            )
        elif isinstance(entry, dict):
            raw_p = str(entry.get("provider", "unconfigured"))
            prov = LEGACY_PROVIDER_ALIAS.get(raw_p, "unconfigured")
            norm[sid] = SlotSelectionConfig(
                slot_id=sid,
                provider=prov,
                enabled=bool(entry.get("enabled", prov != "unconfigured")),
                enterprise_sync_enabled=bool(entry.get("enterprise_sync_enabled", True)),
                parameters=dict(entry.get("parameters") or {}),
            )
        elif isinstance(entry, SlotSelectionConfig):
            norm[sid] = entry.model_copy(update={"slot_id": sid})
        else:
            # Default foundation_model to match runtime_sandbox if importing a 9-slot manifest
            rt = remapped.get("runtime_sandbox")
            if sid == "foundation_model" and rt is not None:
                rt_p = (
                    rt
                    if isinstance(rt, str)
                    else (rt.get("provider", "unconfigured") if isinstance(rt, dict) else "unconfigured")
                )
                prov = LEGACY_PROVIDER_ALIAS.get(str(rt_p), "unconfigured")
                norm[sid] = SlotSelectionConfig(
                    slot_id=sid, provider=prov, enabled=prov != "unconfigured"
                )
            else:
                norm[sid] = SlotSelectionConfig(
                    slot_id=sid, provider="unconfigured", enabled=False
                )
    return norm


def _resolve_slot_pricing(
    spec: dict[str, Any],
    prov: ProviderChoice,
    prof: TenantProfile,
) -> dict[str, Any]:
    sid = str(spec["slot_id"])
    base_rates = dict(spec["pricing"].get(prov, spec["pricing"]["unconfigured"]))
    override = (prof.terminology.slot_tco_overrides.get(sid) or {}).get(prov)
    infra = float(
        override.infra_monthly_usd
        if override and override.infra_monthly_usd is not None
        else base_rates.get("infra_monthly_usd", base_rates["base_monthly_usd"])
    )
    maint = float(
        override.maintenance_monthly_usd
        if override and override.maintenance_monthly_usd is not None
        else base_rates.get("maintenance_monthly_usd", 0.0)
    )
    base_total = (
        round(infra + maint, 2)
        if override and (override.infra_monthly_usd is not None or override.maintenance_monthly_usd is not None)
        else float(base_rates["base_monthly_usd"])
    )
    per_1m = float(
        override.per_1m_turns_usd
        if override and override.per_1m_turns_usd is not None
        else base_rates["per_1m_turns_usd"]
    )
    onboarding = float(
        override.onboarding_usd
        if override and override.onboarding_usd is not None
        else base_rates["onboarding_usd"]
    )
    consolidates = (
        override.consolidates
        if override and override.consolidates
        else spec["consolidates"]
    )
    tco_notes = override.tco_notes if override and override.tco_notes else ""
    return {
        "infra_monthly_usd": round(infra, 2),
        "maintenance_monthly_usd": round(maint, 2),
        "base_monthly_usd": round(base_total, 2),
        "per_1m_turns_usd": round(per_1m, 2),
        "onboarding_usd": round(onboarding, 2),
        "consolidates": consolidates,
        "tco_notes": tco_notes,
    }


def calculate_template_component_costs(
    template: AgentDeploymentTemplate,
    months_active: float = 1.0,
    profile: TenantProfile | None = None,
) -> dict[str, Any]:
    prof = profile or load_tenant_profile()
    slot_catalog = {s["slot_id"]: s for s in build_localized_slot_catalog(prof)}
    turns_m = max(0.1, float(template.estimated_monthly_turns_millions))
    months = max(0.25, float(months_active))
    sync_bridge_slots = {"identity_access", "agent_registry", "observability_tracing"}

    per_slot: list[dict[str, Any]] = []
    monthly_total = 0.0
    onboarding_total = 0.0
    historical_total = 0.0
    cymbal_baseline_monthly = 0.0

    for sid in ORDERED_SLOT_IDS:
        spec = slot_catalog[sid]
        sel = template.components.get(sid) or SlotSelectionConfig(
            slot_id=sid, provider="unconfigured", enabled=False
        )
        prov: ProviderChoice = sel.provider if sel.enabled else "unconfigured"
        rates = _resolve_slot_pricing(spec, prov, prof)
        cymbal_rates = _resolve_slot_pricing(spec, "cymbal_stack", prof)

        sync_bridge_usd = (
            15.0
            if (prov == "google_gcp" and sid in sync_bridge_slots and sel.enterprise_sync_enabled)
            else 0.0
        )
        sync_mode = (
            "transition_bridge"
            if (prov == "google_gcp" and sid in sync_bridge_slots and sel.enterprise_sync_enabled)
            else ("google_primary_only" if prov == "google_gcp" else "customer_managed")
        )

        slot_monthly = round(
            rates["base_monthly_usd"] + sync_bridge_usd + rates["per_1m_turns_usd"] * turns_m,
            2,
        )
        slot_onboarding = round(rates["onboarding_usd"], 2)
        slot_historical = round(slot_monthly * months + slot_onboarding, 2)
        slot_cymbal_monthly = round(
            cymbal_rates["base_monthly_usd"] + cymbal_rates["per_1m_turns_usd"] * turns_m,
            2,
        )

        monthly_total += slot_monthly
        onboarding_total += slot_onboarding
        historical_total += slot_historical
        cymbal_baseline_monthly += slot_cymbal_monthly

        per_slot.append(
            {
                "slot_id": sid,
                "step": spec["step"],
                "pillar": spec["pillar"],
                "workstream": spec["workstream"],
                "functional_name": spec["functional_name"],
                "capability_name": spec["functional_name"],
                "provider": prov,
                "provider_display_name": spec["provider_labels"][prov],
                "enterprise_sync_enabled": bool(sel.enterprise_sync_enabled),
                "sync_mode": sync_mode,
                "sync_bridge_monthly_usd": sync_bridge_usd,
                "infra_monthly_usd": rates["infra_monthly_usd"],
                "maintenance_monthly_usd": rates["maintenance_monthly_usd"],
                "monthly_cost_usd": slot_monthly,
                "onboarding_cost_usd": slot_onboarding,
                "historical_cumulative_usd": slot_historical,
                "baseline_monthly_usd": slot_cymbal_monthly,
                "monthly_savings_usd": round(slot_cymbal_monthly - slot_monthly, 2),
                "consolidates": rates["consolidates"],
                "tco_notes": rates["tco_notes"],
            }
        )

    return {
        "estimated_monthly_turns_millions": turns_m,
        "months_active": months,
        "tco_framing_note": prof.terminology.tco_framing_note,
        "onboarding_eval_cost_usd": round(onboarding_total, 2),
        "monthly_run_rate_usd": round(monthly_total, 2),
        "historical_cumulative_usd": round(historical_total, 2),
        "baseline_monthly_usd": round(cymbal_baseline_monthly, 2),
        "monthly_savings_usd": round(cymbal_baseline_monthly - monthly_total, 2),
        "component_costs": per_slot,
    }


def generate_terraform_paved_path_preview(
    template: AgentDeploymentTemplate,
    profile: TenantProfile | None = None,
) -> str:
    prof = profile or load_tenant_profile()
    defs = prof.governance_defaults
    mod_slug = SAFE_SLUG_RE.sub("_", template.agent_name.lower()).strip("_") or "cymbal_agent"
    id_slot = template.components.get("identity_access")
    reg_slot = template.components.get("agent_registry")
    gw_slot = template.components.get("ai_gateway")
    guard_slot = template.components.get("safety_guardrails")
    mdl_slot = template.components.get("foundation_model")
    otlp_slot = template.components.get("observability_tracing")
    wallet_slot = template.components.get("cost_kill_controls")

    id_prov = id_slot.provider if id_slot else "google_gcp"
    reg_prov = reg_slot.provider if reg_slot else "google_gcp"
    gw_prov = gw_slot.provider if gw_slot else "google_gcp"
    guard_prov = guard_slot.provider if guard_slot else "google_gcp"
    mdl_prov = mdl_slot.provider if mdl_slot else "google_gcp"
    otlp_prov = otlp_slot.provider if otlp_slot else "google_gcp"
    wallet_prov = wallet_slot.provider if wallet_slot else "google_gcp"

    id_sync = bool(id_slot.enterprise_sync_enabled) if id_slot else True
    reg_sync = bool(reg_slot.enterprise_sync_enabled) if reg_slot else True
    otlp_sync = bool(otlp_slot.enterprise_sync_enabled) if otlp_slot else True

    gw_engine = (
        "google_agent_gateway_psci_uap_cel"
        if gw_prov == "google_gcp"
        else "enterprise_custom_gateway"
    )
    gw_endpoint = (
        "https://agentgateway.networkservices.googleapis.com/v1alpha1"
        if gw_prov == "google_gcp"
        else defs.hybrid_gateway_placeholder_url
    )
    id_primary = (
        "google_agent_identity_spiffe_wif"
        if id_prov == "google_gcp"
        else "enterprise_oidc_obo_sidecar"
    )
    reg_primary = (
        "google_agent_registry"
        if reg_prov == "google_gcp"
        else "enterprise_catalog_registry"
    )
    otlp_primary = (
        "google_cloud_trace_and_logging"
        if otlp_prov == "google_gcp"
        else "enterprise_otlp_collector"
    )
    otlp_endpoint = (
        "https://telemetry.googleapis.com/v1/traces"
        if otlp_prov == "google_gcp"
        else defs.hybrid_otlp_placeholder_url
    )
    secondary_otlp = (
        defs.hybrid_otlp_placeholder_url
        if (otlp_prov == "google_gcp" and otlp_sync)
        else ""
    )
    guard_primary = (
        "google_model_armor_cloud_sdp"
        if guard_prov == "google_gcp"
        else "enterprise_guardrail_ensemble"
    )
    cost_kill_primary = (
        "google_firestore_atomic_wallet_and_switch"
        if wallet_prov == "google_gcp"
        else "enterprise_wallet_and_switch"
    )

    return (
        f'module "{mod_slug}_deployment" {{\n'
        f'  source                  = "./infra/terraform"\n'
        f'  agent_id                = "{template.agent_name}"\n'
        f'  cmdb_app_id             = "{template.app_id}"\n'
        f'  governance_intake_id    = "{template.intake_id or defs.intake_record_id}"\n'
        f'  business_unit           = "{prof.terminology.business_units.get(template.business_unit, template.business_unit)}"\n'
        f'  agency_tier             = "{template.risk_tier}"\n'
        f'  identity_provider       = "{id_prov}"\n'
        f'  identity_primary        = "{id_primary}"\n'
        f'  entra_wif_federation_sync = {str(id_sync if id_prov == "google_gcp" else True).lower()}\n'
        f'  registry_provider       = "{reg_prov}"\n'
        f'  registry_primary        = "{reg_primary}"\n'
        f'  enterprise_catalog_sync = {str(reg_sync if reg_prov == "google_gcp" else True).lower()}\n'
        f'  gateway_provider        = "{gw_prov}"\n'
        f'  gateway_primary_engine  = "{gw_engine}"\n'
        f'  gateway_endpoint        = "{gw_endpoint}"\n'
        f'  telemetry_provider      = "{otlp_prov}"\n'
        f'  telemetry_primary       = "{otlp_primary}"\n'
        f'  otlp_collector_endpoint = "{otlp_endpoint}"\n'
        f'  enterprise_otlp_sync    = {str(otlp_sync if otlp_prov == "google_gcp" else True).lower()}\n'
        f'  secondary_otlp_endpoint = "{secondary_otlp}"\n'
        f'  guardrail_provider      = "{guard_prov}"\n'
        f'  guardrail_primary       = "{guard_primary}"\n'
        f'  cost_kill_primary       = "{cost_kill_primary}"\n'
        f'  sdp_pii_mode            = "{template.sdp_pii_mode}"\n'
        f'  uap_cel_per_tool_authz  = {str(template.uap_cel_per_tool_enforced).lower()}\n'
        f'  foundation_model_slot   = "{mdl_prov}"\n'
        f'  gemini_lta_model        = "gemini-3.8-flash"\n'
        f"}}\n"
    )


def generate_dynamic_guardrail_policy_preview(
    template: AgentDeploymentTemplate,
) -> dict[str, Any]:
    sdp_mode = (
        template.sdp_pii_mode
        if template.sdp_pii_mode != "NONE"
        else ("BLOCK_ON_MATCH" if template.business_unit == "intl_sky" else "DEIDENTIFY_INLINE")
    )
    return {
        "business_unit": template.business_unit,
        "risk_tier": template.risk_tier,
        "pi_and_jailbreak_threshold": (
            "LOW_AND_ABOVE"
            if template.risk_tier in {"AG3", "AG4", "AG5"}
            else "MEDIUM_AND_ABOVE"
        ),
        "malicious_uri_filter": True,
        "sdp_pii_mode": sdp_mode,
        "rai_sensitivity": "MEDIUM_AND_ABOVE",
        "resolved_floor_template": (
            "cymbal-strict-ag3-gpp"
            if template.risk_tier in {"AG3", "AG4", "AG5"} or template.business_unit == "intl_sky"
            else "cymbal-default-medium-gpp"
        ),
    }


def evaluate_caas_49_factor_matrix(
    template: AgentDeploymentTemplate,
    profile: TenantProfile | None = None,
) -> dict[str, Any]:
    """Evaluates all 49 risk factors across 12 domains & computes CaaS collapse."""
    prof = profile or load_tenant_profile()
    norm_components = normalize_template_components(template.components)
    slot_catalog = {s["slot_id"]: s for s in build_localized_slot_catalog(prof)}

    factors_out: list[dict[str, Any]] = []
    domains_out: list[dict[str, Any]] = []

    platform_covered = 0
    custom_covered = 0
    manual_gaps = 0

    for factor in CAAS_49_FACTORS:
        sid = factor["covering_slot_id"]
        sel = norm_components.get(sid)
        prov: ProviderChoice = sel.provider if (sel and sel.enabled) else "unconfigured"
        spec = slot_catalog.get(sid, SLOT_CATALOG_SPECS[0])

        has_gap = prov == "unconfigured"
        if sid == "identity_access" and template.static_secrets_in_env:
            has_gap = True
        elif sid == "agent_registry" and not template.intake_id.strip():
            has_gap = True
        elif (
            sid == "ai_gateway"
            and template.destructive_mcp_tools_exposed
            and not template.uap_cel_per_tool_enforced
        ):
            has_gap = True
        elif sid == "safety_guardrails" and template.sdp_pii_mode == "NONE":
            has_gap = True
        elif sid == "eval_optimization" and template.behavior_score < 85.0:
            has_gap = True

        if template.risk_tier == "AG5" and factor["factor_id"] in {
            "f04_level_of_autonomy",
            "f05_agency_tier_ag1_ag5",
        }:
            coverage_state = "prohibited_ag5"
            manual_gaps += 1
        elif prov == "google_gcp" and not has_gap:
            coverage_state = "google_certified_automated"
            platform_covered += 1
        elif prov == "cymbal_stack" and not has_gap:
            if factor["assessment_mode"] == "automated":
                coverage_state = "customer_baseline_control"
                custom_covered += 1
            else:
                coverage_state = "manual_review_required"
                manual_gaps += 1
        else:
            coverage_state = "gap_manual_review"
            manual_gaps += 1

        factors_out.append(
            {
                **factor,
                "provider": prov,
                "provider_label": spec["provider_labels"][prov],
                "coverage_state": coverage_state,
            }
        )

    for dom in CAAS_RISK_DOMAINS:
        did = dom["domain_id"]
        dom_factors = [f for f in factors_out if f["domain_id"] == did]
        gcp_cnt = sum(1 for f in dom_factors if f["coverage_state"] == "google_certified_automated")
        cust_cnt = sum(1 for f in dom_factors if f["coverage_state"] == "customer_baseline_control")
        gap_cnt = len(dom_factors) - gcp_cnt - cust_cnt
        sid = dom["covering_slot_id"]
        sel = norm_components.get(sid)
        prov = sel.provider if (sel and sel.enabled) else "unconfigured"
        domains_out.append(
            {
                **dom,
                "covering_provider": prov,
                "google_certified_count": gcp_cnt,
                "customer_baseline_count": cust_cnt,
                "manual_or_gap_count": gap_cnt,
                "status": (
                    "PROHIBITED"
                    if template.risk_tier == "AG5" and did == "inherent_use_case_risk"
                    else (
                        "CERTIFIED_AUTOMATED"
                        if gap_cnt == 0 and gcp_cnt == len(dom_factors)
                        else ("BASELINE_COVERED" if gap_cnt == 0 else "MANUAL_REVIEW_REQUIRED")
                    )
                ),
            }
        )

    baseline_caas_level = (
        "Prohibited"
        if template.risk_tier == "AG5"
        else ("Level 2" if (template.risk_tier in {"AG3", "AG4"} or manual_gaps > 0) else "Level 1")
    )
    if template.risk_tier == "AG5":
        effective_caas_level = "Prohibited"
        review_sla = "Blocked unconditionally (AG5 prohibited)"
    elif manual_gaps == 0 and platform_covered >= 35:
        effective_caas_level = "Level 0" if template.risk_tier in {"AG1", "AG2"} else "Level 1"
        review_sla = "Auto-approved / Hours (Google-certified controls)"
    elif manual_gaps <= 8 and platform_covered >= 20:
        effective_caas_level = "Level 1"
        review_sla = "Fast-track custom control certification (Hours - 1 day)"
    else:
        effective_caas_level = "Level 2"
        review_sla = "7-Reviewer Parallel Board (Weeks)"

    collapsed = (
        baseline_caas_level == "Level 2"
        and effective_caas_level in {"Level 0", "Level 1"}
    )
    return {
        "total_domains": len(domains_out),
        "total_factors": len(factors_out),
        "baseline_caas_level": baseline_caas_level,
        "effective_caas_level": effective_caas_level,
        "collapsed_from_level_2": collapsed,
        "collapse_summary": (
            f"Collapsed {baseline_caas_level} -> {effective_caas_level} via {platform_covered}/49 Google-certified controls"
            if collapsed
            else f"{effective_caas_level} ({platform_covered}/49 Google-certified, {custom_covered}/49 baseline, {manual_gaps}/49 manual/gap)"
        ),
        "review_sla_estimate": review_sla,
        "platform_covered_count": platform_covered,
        "custom_control_count": custom_covered,
        "manual_review_count": manual_gaps,
        "domains": domains_out,
        "factors": factors_out,
    }


def evaluate_phase5_reviewer_gate(template: AgentDeploymentTemplate) -> dict[str, Any]:
    """Computes Phase 5 Multi-Reviewer Gate across the 7 required enterprise roles."""
    by_role: dict[str, Phase5ReviewerSignoff] = {
        s.role: s for s in (template.reviewer_signoffs or [])
    }
    is_ag5 = template.risk_tier == "AG5"
    reviewers: list[dict[str, Any]] = []
    approved_cnt = 0
    denied_cnt = 0
    pending_cnt = 0

    for role in PHASE5_REVIEWER_ROLES:
        existing = by_role.get(role)
        if is_ag5:
            status = "Denied"
            notes = "AEGIS AG5 (Fully Autonomous) is prohibited and automatically denied."
            conditions = "Downgrade agency tier to AG1-AG4 with HITL/kill-switch controls."
            principal = "policy-gate-enforcer"
            updated_at = _utc_now_iso()
        elif existing is not None:
            status = existing.status
            notes = existing.notes
            conditions = existing.conditions
            principal = existing.reviewer_principal
            updated_at = existing.updated_at
        else:
            default_approved = (
                template.lifecycle_status == "DEPLOYED"
                or (template.caas_risk_level == "Level 0" and bool(template.intake_id.strip()))
            )
            status = "Approved" if default_approved else "Pending"
            notes = "Auto-approved via Level 0 certified controls." if default_approved else "Awaiting Phase 5 reviewer sign-off."
            conditions = ""
            principal = "auto-caas-level0" if default_approved else ""
            updated_at = template.updated_at or ""

        if status in {"Approved", "Approved with Conditions"}:
            approved_cnt += 1
        elif status == "Denied":
            denied_cnt += 1
        else:
            pending_cnt += 1

        reviewers.append(
            {
                "role": role,
                "status": status,
                "conditions": conditions,
                "notes": notes,
                "reviewer_principal": principal,
                "updated_at": updated_at,
            }
        )

    if is_ag5 or denied_cnt > 0:
        verdict = "DENIED"
    elif approved_cnt == len(PHASE5_REVIEWER_ROLES):
        verdict = "APPROVED"
    else:
        verdict = "PENDING_REVIEW"

    return {
        "phase": 5,
        "verdict": verdict,
        "approved_count": approved_cnt,
        "denied_count": denied_cnt,
        "pending_count": pending_cnt,
        "total_reviewers": len(PHASE5_REVIEWER_ROLES),
        "reviewers": reviewers,
    }


def build_aigl_lifecycle_summary(
    template: AgentDeploymentTemplate,
    evaluation: dict[str, Any],
    caas_matrix: dict[str, Any],
) -> dict[str, Any]:
    """Maps the 7 AIGL phases across the 4-stage UI (Build, Evaluate, Deploy, Govern)."""
    current_phase = 7 if template.lifecycle_status == "DEPLOYED" else int(template.aigl_phase or 4)
    if template.risk_tier == "AG5":
        current_phase = min(current_phase, 4)

    phases_out: list[dict[str, Any]] = []
    for spec in AIGL_PHASE_SPECS:
        pnum = int(spec["phase"])
        if template.risk_tier == "AG5" and pnum >= 4:
            p_status = "BLOCKED" if pnum == 4 else "NOT_PERMITTED"
        elif pnum < current_phase:
            p_status = "COMPLETED"
        elif pnum == current_phase:
            p_status = (
                "COMPLETED"
                if (pnum == 5 and evaluation.get("gate_passed"))
                else ("READY" if evaluation.get("gate_passed") else "IN_PROGRESS")
            )
        else:
            p_status = "PENDING"
        phases_out.append({**spec, "status": p_status})

    return {
        "current_phase": current_phase,
        "aegis_tier": template.risk_tier,
        "aegis_risk_level": template.aegis_risk_level,
        "caas_risk_level": caas_matrix.get("effective_caas_level", template.caas_risk_level),
        "phases": phases_out,
    }


def evaluate_template_against_rubric(
    template: AgentDeploymentTemplate,
    rubric: RubricConfig,
    profile: TenantProfile | None = None,
) -> dict[str, Any]:
    prof = profile or load_tenant_profile()
    template.components = normalize_template_components(template.components)
    slot_catalog = {s["slot_id"]: s for s in build_localized_slot_catalog(prof)}
    active_rules = [r for r in rubric.rules if r.enabled]
    total_weight = sum(r.weight_points for r in active_rules) or 100

    earned_weight = 0.0
    pillar_totals: dict[str, list[float]] = {p: [0.0, 0.0] for p in PILLAR_ORDER}
    slot_statuses: dict[str, str] = {sid: "PASSED" for sid in ORDERED_SLOT_IDS}

    rule_results: list[dict[str, Any]] = []
    recommendations: list[dict[str, Any]] = []
    mandatory_blocking_count = 0

    current_costs = calculate_template_component_costs(template, months_active=1.0, profile=prof)

    for rule in active_rules:
        sid = LEGACY_SLOT_ALIAS.get(rule.slot_id, rule.slot_id)
        spec = slot_catalog.get(sid, SLOT_CATALOG_SPECS[0])
        sel = template.components.get(sid) or SlotSelectionConfig(
            slot_id=sid, provider="unconfigured", enabled=False
        )
        prov: ProviderChoice = sel.provider if sel.enabled else "unconfigured"

        passed = True
        gap_reasons: list[str] = []

        if prov == "unconfigured":
            passed = False
            gap_reasons.append(f"{spec['functional_name']} component is not configured.")

        if rule.rule_id == "RUB-01" and template.static_secrets_in_env:
            passed = False
            gap_reasons.append(
                "Static credentials found in environment: "
                + ", ".join(template.static_secrets_in_env)
            )

        if rule.rule_id == "RUB-02" and not template.intake_id.strip():
            passed = False
            gap_reasons.append(f"Missing approved {prof.terminology.intake_name} identifier.")

        if (
            rule.rule_id == "RUB-03"
            and template.destructive_mcp_tools_exposed
            and not template.uap_cel_per_tool_enforced
        ):
            passed = False
            gap_reasons.append(
                "Mutating MCP tools are exposed without inline per-tool UAP CEL authorization."
            )

        if rule.rule_id == "RUB-04":
            if template.sdp_pii_mode == "NONE":
                passed = False
                gap_reasons.append("Inline PII inspection/redaction policy is disabled.")

        if (
            rule.min_behavior_score is not None
            and template.behavior_score < rule.min_behavior_score
        ):
            passed = False
            gap_reasons.append(
                f"Evaluation score {template.behavior_score:.1f}/100 is below required "
                f"{rule.min_behavior_score:.1f}/100 threshold."
            )

        exception_note = template.exception_overrides.get(rule.rule_id, "")
        status_label: Literal["PASSED", "ADVISORY", "EXCEPTION_APPROVED", "FAILED"] = "PASSED"
        if passed and prov == "google_gcp":
            earned_weight += rule.weight_points
            pillar_totals.setdefault(rule.pillar, [0.0, 0.0])[0] += rule.weight_points
            score_uplift = 0.0
        elif passed and prov == "cymbal_stack":
            status_label = "ADVISORY"
            earned_weight += rule.weight_points * 0.85
            pillar_totals.setdefault(rule.pillar, [0.0, 0.0])[0] += rule.weight_points * 0.85
            slot_statuses[sid] = "ADVISORY"
            score_uplift = round((rule.weight_points * 0.15 / total_weight) * 100.0, 1)
            gap_reasons.append(
                f"Baseline mandatory gate satisfied on {spec['provider_labels']['cymbal_stack']}; "
                f"upgrade to {spec['gcp_name']} for +{score_uplift} pts and capability/TCO gains."
            )
        elif exception_note:
            status_label = "EXCEPTION_APPROVED"
            earned_weight += rule.weight_points * 0.5
            pillar_totals.setdefault(rule.pillar, [0.0, 0.0])[0] += rule.weight_points * 0.5
            if slot_statuses.get(sid) == "PASSED":
                slot_statuses[sid] = "ADVISORY"
            score_uplift = round((rule.weight_points * 0.5 / total_weight) * 100.0, 1)
        else:
            status_label = "FAILED"
            if rule.mandatory:
                mandatory_blocking_count += 1
                slot_statuses[sid] = "FAILED"
            elif slot_statuses.get(sid) == "PASSED":
                slot_statuses[sid] = "ADVISORY"
            score_uplift = round((rule.weight_points / total_weight) * 100.0, 1)

        pillar_totals.setdefault(rule.pillar, [0.0, 0.0])[1] += rule.weight_points

        rule_results.append(
            {
                "rule_id": rule.rule_id,
                "slot_id": sid,
                "functional_name": spec["functional_name"],
                "pillar": rule.pillar,
                "workstream": rule.workstream,
                "title": rule.title,
                "mandatory": rule.mandatory,
                "weight_points": rule.weight_points,
                "score_uplift_pct": score_uplift,
                "current_provider": prov,
                "current_provider_label": spec["provider_labels"][prov],
                "status": status_label,
                "gap_reasons": gap_reasons,
                "exception_note": exception_note,
            }
        )

        if status_label in {"FAILED", "ADVISORY"}:
            target_prov = LEGACY_PROVIDER_ALIAS.get(rule.remediation_provider, "google_gcp")
            hypothetical = copy.deepcopy(template)
            hypothetical.components[sid] = SlotSelectionConfig(
                slot_id=sid,
                provider=target_prov,
                enabled=True,
                enterprise_sync_enabled=sel.enterprise_sync_enabled,
                parameters={"remediated_by": rule.rule_id},
            )
            if rule.rule_id == "RUB-01":
                hypothetical.static_secrets_in_env = []
            if rule.rule_id == "RUB-02" and not hypothetical.intake_id:
                hypothetical.intake_id = prof.governance_defaults.intake_record_id
            if rule.rule_id == "RUB-03":
                hypothetical.uap_cel_per_tool_enforced = True
            if rule.rule_id == "RUB-04":
                hypothetical.sdp_pii_mode = (
                    "BLOCK_ON_MATCH"
                    if hypothetical.business_unit == "intl_sky"
                    else "DEIDENTIFY_INLINE"
                )
            if rule.rule_id == "RUB-10":
                hypothetical.prompt_version = "v2"
                hypothetical.behavior_score = 96.4

            patched_costs = calculate_template_component_costs(
                hypothetical, months_active=1.0, profile=prof
            )
            cost_delta = round(
                patched_costs["monthly_run_rate_usd"] - current_costs["monthly_run_rate_usd"],
                2,
            )

            recommendations.append(
                {
                    "rec_id": f"REC-{rule.rule_id}",
                    "rule_id": rule.rule_id,
                    "slot_id": sid,
                    "functional_name": spec["functional_name"],
                    "pillar": rule.pillar,
                    "workstream": rule.workstream,
                    "severity": (
                        "MANDATORY_GATE"
                        if (status_label == "FAILED" and rule.mandatory)
                        else "ADVISORY"
                    ),
                    "status": status_label,
                    "title": rule.title,
                    "finding_detail": " ".join(gap_reasons),
                    "recommendation_summary": rule.remediation_summary,
                    "recommended_provider": target_prov,
                    "recommended_provider_label": spec["provider_labels"][target_prov],
                    "score_uplift_pts": score_uplift,
                    "monthly_cost_delta_usd": cost_delta,
                    "capability_delta": (
                        f"Consolidates {spec['consolidates']} onto {spec['gcp_name']} ({spec['api_surface']})."
                    ),
                    "supports_closed_loop_eval": rule.rule_id == "RUB-10",
                    "before_config": {
                        "slot_id": sid,
                        "provider": prov,
                        "provider_label": spec["provider_labels"][prov],
                    },
                    "after_config": {
                        "slot_id": sid,
                        "provider": target_prov,
                        "provider_label": spec["provider_labels"][target_prov],
                    },
                    "terraform_hcl_preview": generate_terraform_paved_path_preview(
                        hypothetical, profile=prof
                    ),
                }
            )

    overall_score = round((earned_weight / total_weight) * 100.0, 1)
    ag5_blocked = template.risk_tier == "AG5"
    if ag5_blocked:
        mandatory_blocking_count += 1
        recommendations.insert(
            0,
            {
                "rec_id": "REC-AEGIS-AG5",
                "rule_id": "AEGIS-AG5",
                "slot_id": "ai_gateway",
                "functional_name": "Agency Tier Policy",
                "pillar": "Control",
                "workstream": "Agency Autonomy Gate",
                "severity": "MANDATORY_GATE",
                "status": "BLOCKED",
                "title": "AEGIS AG5 (Fully Autonomous) Prohibited",
                "finding_detail": (
                    "AEGIS AG5 (Fully autonomous - no human intervention) is prohibited by "
                    "enterprise policy and cannot be deployed or bypassed via exception overrides."
                ),
                "recommendation_summary": (
                    "Reclassify workload to AG1-AG4 with explicit HITL / kill-switch controls."
                ),
                "recommended_provider": "google_gcp",
                "recommended_provider_label": "Reclassify to AG1-AG4",
                "score_uplift_pts": 0.0,
                "monthly_cost_delta_usd": 0.0,
                "capability_delta": "Mandatory AG5 agency-tier enforcement.",
                "supports_closed_loop_eval": False,
                "before_config": {"slot_id": "risk_tier", "provider": "AG5", "provider_label": "AG5"},
                "after_config": {"slot_id": "risk_tier", "provider": "AG3", "provider_label": "AG3"},
                "terraform_hcl_preview": generate_terraform_paved_path_preview(template, profile=prof),
            },
        )

    gate_passed = (
        not ag5_blocked
        and overall_score >= rubric.passing_score_threshold
        and mandatory_blocking_count == 0
    )
    overall_status = (
        "BLOCKED"
        if ag5_blocked
        else ("READY_FOR_DEPLOYMENT" if gate_passed else "REMEDIATION_REQUIRED")
    )

    pillar_summary = {}
    for p_name, (earned, possible) in pillar_totals.items():
        pillar_summary[p_name] = {
            "earned_pts": round(earned, 1),
            "possible_pts": round(possible, 1),
            "pct": round((earned / possible) * 100.0, 1) if possible > 0 else 100.0,
        }

    caas_matrix = evaluate_caas_49_factor_matrix(template, profile=prof)
    phase5_gate = evaluate_phase5_reviewer_gate(template)
    base_eval = {
        "rubric_id": rubric.rubric_id,
        "rubric_name": rubric.name,
        "overall_score": overall_score,
        "passing_threshold": rubric.passing_score_threshold,
        "gate_passed": gate_passed,
        "overall_status": overall_status,
        "gate_verdict": overall_status,
        "ag5_prohibited_blocked": ag5_blocked,
        "mandatory_failures_count": mandatory_blocking_count,
        "recommendations_count": len(recommendations),
        "pillar_scores": pillar_summary,
        "slot_statuses": slot_statuses,
        "rule_results": rule_results,
        "recommendations": recommendations,
        "cost_estimate": current_costs,
        "caas_matrix": caas_matrix,
        "phase5_reviewer_gate": phase5_gate,
        "dynamic_guardrail_policy_preview": generate_dynamic_guardrail_policy_preview(template),
        "terraform_paved_path_hcl": generate_terraform_paved_path_preview(template, profile=prof),
    }
    base_eval["aigl_lifecycle"] = build_aigl_lifecycle_summary(template, base_eval, caas_matrix)
    return base_eval


def apply_remediation_action_to_template(
    template: AgentDeploymentTemplate,
    *,
    rule_id: str,
    action: Literal["accept", "customize", "exception"],
    rubric: RubricConfig,
    custom_provider: str | None = None,
    custom_parameters: dict[str, Any] | None = None,
    exception_reason: str | None = None,
    profile: TenantProfile | None = None,
) -> AgentDeploymentTemplate:
    prof = profile or load_tenant_profile()
    updated = copy.deepcopy(template)
    updated.components = normalize_template_components(updated.components)

    rule_map = {r.rule_id: r for r in rubric.rules}
    rule = rule_map.get(rule_id)
    if rule is None:
        raise ValueError(f"Unknown rubric rule_id: {rule_id}")

    sid = LEGACY_SLOT_ALIAS.get(rule.slot_id, rule.slot_id)
    if action == "exception":
        if updated.risk_tier == "AG5":
            raise ValueError(
                "AEGIS AG5 (Fully Autonomous) is prohibited and cannot receive an exception override."
            )
        note = (exception_reason or "Approved policy exception recorded.").strip()
        updated.exception_overrides[rule_id] = note[:300]
        updated.updated_at = _utc_now_iso()
        updated.updated_display = _display_timestamp_now()
        return updated

    updated.exception_overrides.pop(rule_id, None)
    resolved_custom = (
        LEGACY_PROVIDER_ALIAS.get(custom_provider, "google_gcp")
        if custom_provider
        else None
    )
    target_provider: ProviderChoice = (
        resolved_custom
        if (action == "customize" and resolved_custom)
        else LEGACY_PROVIDER_ALIAS.get(rule.remediation_provider, "google_gcp")
    )
    existing_slot = updated.components.get(sid) or SlotSelectionConfig(slot_id=sid)
    merged_params = dict(existing_slot.parameters)
    if custom_parameters:
        merged_params.update(custom_parameters)
    sync_enabled = (
        bool(custom_parameters["enterprise_sync_enabled"])
        if (
            action == "customize"
            and custom_parameters is not None
            and "enterprise_sync_enabled" in custom_parameters
        )
        else existing_slot.enterprise_sync_enabled
    )
    updated.components[sid] = SlotSelectionConfig(
        slot_id=sid,
        provider=target_provider,
        enabled=target_provider != "unconfigured",
        enterprise_sync_enabled=sync_enabled,
        parameters=merged_params,
    )
    updated.template_mode = "custom"

    if action == "accept":
        if rule_id == "RUB-01":
            updated.static_secrets_in_env = []
        elif rule_id == "RUB-02" and not updated.intake_id.strip():
            updated.intake_id = prof.governance_defaults.intake_record_id
        elif rule_id == "RUB-03":
            updated.uap_cel_per_tool_enforced = True
        elif rule_id == "RUB-04":
            updated.sdp_pii_mode = (
                "BLOCK_ON_MATCH"
                if updated.business_unit == "intl_sky"
                else "DEIDENTIFY_INLINE"
            )
        elif rule_id == "RUB-10":
            updated.prompt_version = "v2"
            updated.behavior_score = max(updated.behavior_score, 96.4)
    elif action == "customize" and custom_parameters:
        if "sdp_pii_mode" in custom_parameters:
            val = str(custom_parameters["sdp_pii_mode"])
            if val in {"DEIDENTIFY_INLINE", "BLOCK_ON_MATCH", "INSPECT_ONLY", "NONE"}:
                updated.sdp_pii_mode = val  # type: ignore[assignment]
        if "uap_cel_per_tool_enforced" in custom_parameters:
            updated.uap_cel_per_tool_enforced = bool(
                custom_parameters["uap_cel_per_tool_enforced"]
            )
        if "intake_id" in custom_parameters:
            updated.intake_id = str(custom_parameters["intake_id"])[:64]
        if custom_parameters.get("clear_static_secrets"):
            updated.static_secrets_in_env = []
        if "system_instruction" in custom_parameters:
            updated.system_instruction = str(custom_parameters["system_instruction"])[:8000]
            updated.prompt_version = "v2"
            updated.behavior_score = max(updated.behavior_score, 92.0)

    if rule_id not in updated.applied_remediations:
        updated.applied_remediations.append(rule_id)
    updated.updated_at = _utc_now_iso()
    updated.updated_display = _display_timestamp_now()
    return updated


def parse_uploaded_template_manifest(
    raw_content: str,
    filename: str = "agent_manifest.yaml",
    profile: TenantProfile | None = None,
) -> AgentDeploymentTemplate:
    prof = profile or load_tenant_profile()
    encoded = raw_content.encode("utf-8")
    if len(encoded) > MAX_TEMPLATE_UPLOAD_BYTES:
        raise ValueError(
            f"Manifest exceeds maximum allowed size ({MAX_TEMPLATE_UPLOAD_BYTES} bytes)."
        )
    safe_name = Path(filename).name.lower()
    if not safe_name.endswith((".json", ".yaml", ".yml")):
        raise ValueError("Only .json, .yaml, and .yml deployment template files are supported.")

    try:
        parsed = (
            json.loads(raw_content)
            if safe_name.endswith(".json")
            else yaml.safe_load(raw_content)
        )
    except Exception as exc:
        raise ValueError(f"Invalid manifest syntax: {exc}") from exc

    if not isinstance(parsed, dict):
        raise ValueError("Template manifest root must be an object mapping.")

    norm_components = normalize_template_components(parsed.get("components"))
    slug_base = SAFE_SLUG_RE.sub("-", Path(safe_name).stem).strip("-") or "imported-agent"
    agent_id_val = str(parsed.get("agent_name") or parsed.get("template_id") or slug_base)[:80]

    raw_mode = str(parsed.get("template_mode") or "custom").strip()
    template_mode: TemplateMode = raw_mode if raw_mode in {"google_gcp", "custom"} else "custom"  # type: ignore[assignment]

    raw_origin = str(parsed.get("origin") or "imported_manifest").strip()
    valid_origins = {"google_gcp_standard", "cymbal_baseline", "custom_hybrid", "imported_manifest"}
    origin: TemplateOrigin = raw_origin if raw_origin in valid_origins else "imported_manifest"  # type: ignore[assignment]

    raw_onboarding = str(parsed.get("onboarding_path") or "Path B: SDK Integration").strip()
    valid_paths = {
        "Path A: Protocol Adapter",
        "Path B: SDK Integration",
        "Path C: Greenfield",
    }
    onboarding_path = raw_onboarding if raw_onboarding in valid_paths else "Path B: SDK Integration"

    raw_aegis_risk = str(parsed.get("aegis_risk_level") or "R2").strip()
    aegis_risk_level = raw_aegis_risk if raw_aegis_risk in {"R1", "R2", "R3", "R4", "R5"} else "R2"

    raw_caas = str(parsed.get("caas_risk_level") or "Level 1").strip()
    caas_risk_level = (
        raw_caas
        if raw_caas in {"Level 0", "Level 1", "Level 2", "Prohibited"}
        else "Level 1"
    )

    try:
        aigl_phase = max(1, min(7, int(parsed.get("aigl_phase", 4))))
    except (TypeError, ValueError):
        aigl_phase = 4

    tpl_payload: dict[str, Any] = {
        "template_id": str(parsed.get("template_id") or agent_id_val),
        "name": str(parsed.get("name") or agent_id_val),
        "description": str(
            parsed.get("description")
            or f"Imported agent manifest ({safe_name}) registered in {prof.terminology.platform_name}."
        ),
        "template_mode": template_mode,
        "origin": origin,
        "agent_name": agent_id_val,
        "app_id": str(parsed.get("app_id") or "svc-cymbal-imported")[:64],
        "intake_id": str(parsed.get("intake_id") or "")[:64],
        "business_unit": parsed.get("business_unit") or "core_cable",
        "risk_tier": parsed.get("risk_tier") or "AG2",
        "aegis_risk_level": aegis_risk_level,
        "aigl_phase": aigl_phase,
        "caas_risk_level": caas_risk_level,
        "onboarding_path": onboarding_path,
        "runtime_cloud": parsed.get("runtime_cloud") or "gcp",
        "estimated_monthly_turns_millions": float(
            parsed.get("estimated_monthly_turns_millions", 3.0)
        ),
        "static_secrets_in_env": list(parsed.get("static_secrets_in_env") or []),
        "destructive_mcp_tools_exposed": bool(
            parsed.get("destructive_mcp_tools_exposed", False)
        ),
        "uap_cel_per_tool_enforced": bool(parsed.get("uap_cel_per_tool_enforced", False)),
        "sdp_pii_mode": parsed.get("sdp_pii_mode") or "NONE",
        "prompt_version": str(parsed.get("prompt_version") or "v1")[:40],
        "behavior_score": float(parsed.get("behavior_score", 60.0)),
        "system_instruction": str(
            parsed.get("system_instruction")
            or "Imported agent system prompt pending governance evaluation."
        )[:8000],
        "components": norm_components,
        "updated_at": _utc_now_iso(),
        "updated_display": _display_timestamp_now(),
    }
    return AgentDeploymentTemplate.model_validate(tpl_payload)


def export_template_to_yaml(template: AgentDeploymentTemplate) -> str:
    """Serializes an AgentDeploymentTemplate into canonical importable YAML."""
    norm = normalize_template_components(template.components)
    payload = {
        "template_id": template.template_id,
        "name": template.name,
        "description": template.description,
        "template_mode": template.template_mode,
        "origin": template.origin,
        "agent_name": template.agent_name,
        "app_id": template.app_id,
        "intake_id": template.intake_id,
        "business_unit": template.business_unit,
        "risk_tier": template.risk_tier,
        "aegis_risk_level": template.aegis_risk_level,
        "aigl_phase": template.aigl_phase,
        "caas_risk_level": template.caas_risk_level,
        "onboarding_path": template.onboarding_path,
        "runtime_cloud": template.runtime_cloud,
        "estimated_monthly_turns_millions": template.estimated_monthly_turns_millions,
        "static_secrets_in_env": list(template.static_secrets_in_env),
        "destructive_mcp_tools_exposed": template.destructive_mcp_tools_exposed,
        "uap_cel_per_tool_enforced": template.uap_cel_per_tool_enforced,
        "sdp_pii_mode": template.sdp_pii_mode,
        "prompt_version": template.prompt_version,
        "behavior_score": template.behavior_score,
        "system_instruction": template.system_instruction,
        "components": {
            sid: {
                "provider": norm[sid].provider,
                "enabled": norm[sid].enabled,
                "enterprise_sync_enabled": norm[sid].enterprise_sync_enabled,
            }
            for sid in ORDERED_SLOT_IDS
        },
    }
    return yaml.safe_dump(payload, sort_keys=False)


def _load_env_starter_entries() -> list[tuple[str, str]]:
    """Loads optional serialized starter manifests from CYMBAL_STARTER_TEMPLATES_JSON."""
    raw_json = os.getenv("CYMBAL_STARTER_TEMPLATES_JSON", "").strip()
    if not raw_json:
        return []
    try:
        parsed = json.loads(raw_json)
    except json.JSONDecodeError:
        return []
    entries: list[tuple[str, str]] = []
    if isinstance(parsed, dict):
        for fname in sorted(parsed.keys()):
            val = parsed[fname]
            if isinstance(val, str) and val.strip():
                entries.append((str(fname), val))
    elif isinstance(parsed, list):
        for item in parsed:
            if isinstance(item, dict):
                fname = str(item.get("filename") or item.get("name") or "").strip()
                val = str(item.get("content") or item.get("raw_yaml") or "")
                if fname and val.strip():
                    entries.append((fname, val))
    return entries


def list_local_starter_templates(
    starters_dir: Path | None = None,
    profile: TenantProfile | None = None,
) -> list[dict[str, Any]]:
    """Lists pre-generated starter YAML templates from disk or env fallback."""
    target_dir = starters_dir or STARTERS_DIR
    prof = profile or load_tenant_profile()
    rubric = _build_default_rubric(prof)
    sources: list[tuple[str, str]] = []
    if target_dir.is_dir():
        files = sorted(
            list(target_dir.glob("*.local.yaml")) + list(target_dir.glob("*.local.yml")),
            key=lambda p: p.name,
        )
        for p in files:
            try:
                sources.append((p.name, p.read_text(encoding="utf-8")))
            except OSError:
                continue
    if not sources and starters_dir is None:
        sources = _load_env_starter_entries()

    starters: list[dict[str, Any]] = []
    for fname, raw_text in sources:
        try:
            tpl = parse_uploaded_template_manifest(raw_text, filename=fname, profile=prof)
            ev = evaluate_template_against_rubric(tpl, rubric, profile=prof)
            cymbal_cnt = sum(
                1 for c in tpl.components.values() if c.enabled and c.provider == "cymbal_stack"
            )
            gcp_cnt = sum(
                1 for c in tpl.components.values() if c.enabled and c.provider == "google_gcp"
            )
            stem = Path(fname).stem
            if stem.endswith(".local"):
                stem = stem[: -len(".local")]
            starters.append(
                {
                    "starter_id": stem,
                    "filename": fname,
                    "name": tpl.name,
                    "description": tpl.description,
                    "template_mode": tpl.template_mode,
                    "risk_tier": tpl.risk_tier,
                    "overall_score": ev["overall_score"],
                    "gate_passed": ev["gate_passed"],
                    "cymbal_stack_slots": cymbal_cnt,
                    "google_gcp_slots": gcp_cnt,
                    "raw_yaml": raw_text,
                    "template": tpl.model_dump(),
                }
            )
        except Exception:
            continue
    return starters


def load_local_starter_template(
    starter_id: str,
    starters_dir: Path | None = None,
    profile: TenantProfile | None = None,
) -> AgentDeploymentTemplate:
    """Loads a validated starter YAML by starter_id from disk or env fallback."""
    clean_id = (starter_id or "").strip()
    if not clean_id or "/" in clean_id or "\\" in clean_id or ".." in clean_id:
        raise ValueError("Invalid starter_id.")
    target_dir = starters_dir or STARTERS_DIR
    for ext in (".local.yaml", ".local.yml"):
        candidate = target_dir / f"{clean_id}{ext}"
        if candidate.is_file():
            raw_text = candidate.read_text(encoding="utf-8")
            return parse_uploaded_template_manifest(
                raw_text, filename=candidate.name, profile=profile
            )
    if starters_dir is None:
        for fname, raw_text in _load_env_starter_entries():
            stem = Path(fname).stem
            if stem.endswith(".local"):
                stem = stem[: -len(".local")]
            if stem == clean_id or fname == clean_id:
                return parse_uploaded_template_manifest(
                    raw_text, filename=fname, profile=profile
                )
    raise FileNotFoundError(f"Starter template '{clean_id}' not found in {target_dir}.")


def _seed_historical_deployments(profile: TenantProfile) -> list[dict[str, Any]]:
    defs = profile.governance_defaults

    def _hybrid_mix() -> dict[str, SlotSelectionConfig]:
        m = _default_slot_map("cymbal_stack")
        for g in (
            "safety_guardrails",
            "foundation_model",
            "runtime_sandbox",
            "memory_knowledge",
            "eval_optimization",
        ):
            m[g] = _default_slot_map("google_gcp")[g]
        return m

    specs: list[dict[str, Any]] = [
        {
            "deployment_id": "DEP-2026-0901",
            "deployed_at": "2026-06-12T14:20:00Z",
            "agent_name": "broadband-outage-triage-agent",
            "app_id": "svc-cymbal-104",
            "business_unit": "core_cable",
            "risk_tier": "AG3",
            "origin": "custom_hybrid",
            "months_active": 5.5,
            "turns_m": 9.2,
            "initial_score": 61.0,
            "final_score": 96.8,
            "remediated": True,
            "remediations_count": 4,
            "mix": _hybrid_mix(),
        },
        {
            "deployment_id": "DEP-2026-0902",
            "deployed_at": "2026-06-28T16:05:00Z",
            "agent_name": "subscriber-billing-concierge",
            "app_id": "svc-cymbal-208",
            "business_unit": "core_cable",
            "risk_tier": "AG2",
            "origin": "custom_hybrid",
            "months_active": 5.0,
            "turns_m": 6.0,
            "initial_score": 86.0,
            "final_score": 88.5,
            "remediated": False,
            "remediations_count": 0,
            "mix": _default_slot_map("cymbal_stack"),
        },
        {
            "deployment_id": "DEP-2026-0903",
            "deployed_at": "2026-07-14T11:40:00Z",
            "agent_name": "ad-sales-proposal-synthesizer",
            "app_id": "svc-cymbal-311",
            "business_unit": "media_studio",
            "risk_tier": "AG2",
            "origin": "google_gcp_standard",
            "months_active": 4.5,
            "turns_m": 4.2,
            "initial_score": 92.0,
            "final_score": 98.0,
            "remediated": False,
            "remediations_count": 0,
            "mix": _default_slot_map("google_gcp"),
        },
        {
            "deployment_id": "DEP-2026-0904",
            "deployed_at": "2026-07-29T09:15:00Z",
            "agent_name": "content-rights-clearance-agent",
            "app_id": "svc-cymbal-349",
            "business_unit": "media_studio",
            "risk_tier": "AG1",
            "origin": "custom_hybrid",
            "months_active": 4.0,
            "turns_m": 2.8,
            "initial_score": 88.0,
            "final_score": 88.0,
            "remediated": False,
            "remediations_count": 0,
            "mix": _default_slot_map("cymbal_stack"),
        },
        {
            "deployment_id": "DEP-2026-0905",
            "deployed_at": "2026-08-11T17:30:00Z",
            "agent_name": "regional-privacy-retention-agent",
            "app_id": "svc-cymbal-402",
            "business_unit": "intl_sky",
            "risk_tier": "AG3",
            "origin": "imported_manifest",
            "months_active": 3.5,
            "turns_m": 5.5,
            "initial_score": 52.0,
            "final_score": 95.4,
            "remediated": True,
            "remediations_count": 5,
            "mix": _hybrid_mix(),
        },
        {
            "deployment_id": "DEP-2026-0906",
            "deployed_at": "2026-08-24T13:10:00Z",
            "agent_name": "field-technician-dispatch-agent",
            "app_id": "svc-cymbal-512",
            "business_unit": "core_cable",
            "risk_tier": "AG3",
            "origin": "custom_hybrid",
            "months_active": 3.0,
            "turns_m": 7.4,
            "initial_score": 68.0,
            "final_score": 97.2,
            "remediated": True,
            "remediations_count": 3,
            "mix": _hybrid_mix(),
        },
        {
            "deployment_id": "DEP-2026-0907",
            "deployed_at": "2026-09-08T10:50:00Z",
            "agent_name": "enterprise-access-concierge",
            "app_id": "svc-cymbal-601",
            "business_unit": "enterprise_shared",
            "risk_tier": "AG2",
            "origin": "custom_hybrid",
            "months_active": 2.6,
            "turns_m": 3.5,
            "initial_score": 74.0,
            "final_score": 91.0,
            "remediated": True,
            "remediations_count": 2,
            "mix": _hybrid_mix(),
        },
        {
            "deployment_id": "DEP-2026-0908",
            "deployed_at": "2026-09-22T15:45:00Z",
            "agent_name": "streaming-qoe-diagnostics",
            "app_id": "svc-cymbal-455",
            "business_unit": "intl_sky",
            "risk_tier": "AG2",
            "origin": "google_gcp_standard",
            "months_active": 2.2,
            "turns_m": 8.6,
            "initial_score": 94.0,
            "final_score": 98.0,
            "remediated": False,
            "remediations_count": 0,
            "mix": _default_slot_map("google_gcp"),
        },
        {
            "deployment_id": "DEP-2026-0909",
            "deployed_at": "2026-10-05T18:00:00Z",
            "agent_name": "invoice-adjustment-specialist",
            "app_id": "svc-cymbal-778",
            "business_unit": "core_cable",
            "risk_tier": "AG3",
            "origin": "imported_manifest",
            "months_active": 1.7,
            "turns_m": 3.1,
            "initial_score": 34.0,
            "final_score": 94.6,
            "remediated": True,
            "remediations_count": 6,
            "mix": _hybrid_mix(),
        },
        {
            "deployment_id": "DEP-2026-0910",
            "deployed_at": "2026-10-19T12:25:00Z",
            "agent_name": "procurement-contract-reviewer",
            "app_id": "svc-cymbal-688",
            "business_unit": "enterprise_shared",
            "risk_tier": "AG2",
            "origin": "google_gcp_standard",
            "months_active": 1.3,
            "turns_m": 2.2,
            "initial_score": 95.0,
            "final_score": 98.0,
            "remediated": False,
            "remediations_count": 0,
            "mix": _default_slot_map("google_gcp"),
        },
        {
            "deployment_id": "DEP-2026-0911",
            "deployed_at": "2026-11-02T14:10:00Z",
            "agent_name": "partner-entitlement-router",
            "app_id": "svc-cymbal-390",
            "business_unit": "media_studio",
            "risk_tier": "AG3",
            "origin": "imported_manifest",
            "months_active": 0.9,
            "turns_m": 7.8,
            "initial_score": 58.0,
            "final_score": 96.4,
            "remediated": True,
            "remediations_count": 3,
            "mix": _hybrid_mix(),
        },
        {
            "deployment_id": "DEP-2026-0912",
            "deployed_at": "2026-10-28T16:40:00Z",
            "agent_name": "gateway-firmware-rollout-agent",
            "app_id": "svc-cymbal-812",
            "business_unit": "core_cable",
            "risk_tier": "AG3",
            "origin": "custom_hybrid",
            "months_active": 1.0,
            "turns_m": 5.0,
            "initial_score": 70.0,
            "final_score": 97.2,
            "remediated": True,
            "remediations_count": 3,
            "mix": _hybrid_mix(),
        },
        {
            "deployment_id": "DEP-2026-0913",
            "deployed_at": "2026-11-01T10:15:00Z",
            "agent_name": "sports-highlight-clipper-agent",
            "app_id": "svc-cymbal-824",
            "business_unit": "media_studio",
            "risk_tier": "AG2",
            "origin": "google_gcp_standard",
            "months_active": 0.85,
            "turns_m": 6.4,
            "initial_score": 93.0,
            "final_score": 98.0,
            "remediated": False,
            "remediations_count": 0,
            "mix": _default_slot_map("google_gcp"),
        },
        {
            "deployment_id": "DEP-2026-0914",
            "deployed_at": "2026-11-05T14:50:00Z",
            "agent_name": "roaming-tariff-compliance-agent",
            "app_id": "svc-cymbal-839",
            "business_unit": "intl_sky",
            "risk_tier": "AG3",
            "origin": "custom_hybrid",
            "months_active": 0.7,
            "turns_m": 4.1,
            "initial_score": 66.0,
            "final_score": 95.8,
            "remediated": True,
            "remediations_count": 4,
            "mix": _hybrid_mix(),
        },
        {
            "deployment_id": "DEP-2026-0915",
            "deployed_at": "2026-11-09T09:30:00Z",
            "agent_name": "soc-incident-enrichment-agent",
            "app_id": "svc-cymbal-851",
            "business_unit": "enterprise_shared",
            "risk_tier": "AG3",
            "origin": "google_gcp_standard",
            "months_active": 0.6,
            "turns_m": 7.1,
            "initial_score": 94.0,
            "final_score": 98.2,
            "remediated": False,
            "remediations_count": 0,
            "mix": _default_slot_map("google_gcp"),
        },
        {
            "deployment_id": "DEP-2026-0916",
            "deployed_at": "2026-11-12T15:20:00Z",
            "agent_name": "wifi-mesh-channel-optimizer",
            "app_id": "svc-cymbal-866",
            "business_unit": "core_cable",
            "risk_tier": "AG2",
            "origin": "custom_hybrid",
            "months_active": 0.5,
            "turns_m": 8.3,
            "initial_score": 72.0,
            "final_score": 96.0,
            "remediated": True,
            "remediations_count": 2,
            "mix": _hybrid_mix(),
        },
        {
            "deployment_id": "DEP-2026-0917",
            "deployed_at": "2026-11-15T11:05:00Z",
            "agent_name": "syndication-royalty-reconciler",
            "app_id": "svc-cymbal-874",
            "business_unit": "media_studio",
            "risk_tier": "AG2",
            "origin": "imported_manifest",
            "months_active": 0.4,
            "turns_m": 3.4,
            "initial_score": 59.0,
            "final_score": 94.8,
            "remediated": True,
            "remediations_count": 4,
            "mix": _hybrid_mix(),
        },
        {
            "deployment_id": "DEP-2026-0918",
            "deployed_at": "2026-11-18T13:15:00Z",
            "agent_name": "cloud-finops-anomaly-auditor",
            "app_id": "svc-cymbal-883",
            "business_unit": "enterprise_shared",
            "risk_tier": "AG2",
            "origin": "google_gcp_standard",
            "months_active": 0.35,
            "turns_m": 2.9,
            "initial_score": 96.0,
            "final_score": 98.4,
            "remediated": False,
            "remediations_count": 0,
            "mix": _default_slot_map("google_gcp"),
        },
        {
            "deployment_id": "DEP-2026-0919",
            "deployed_at": "2026-11-20T16:40:00Z",
            "agent_name": "multilingual-subtitling-qa-agent",
            "app_id": "svc-cymbal-897",
            "business_unit": "intl_sky",
            "risk_tier": "AG1",
            "origin": "google_gcp_standard",
            "months_active": 0.3,
            "turns_m": 5.8,
            "initial_score": 95.0,
            "final_score": 98.0,
            "remediated": False,
            "remediations_count": 0,
            "mix": _default_slot_map("google_gcp"),
        },
        {
            "deployment_id": "DEP-2026-0920",
            "deployed_at": "2026-11-24T09:35:00Z",
            "agent_name": "ott-playback-drm-diagnostics",
            "app_id": "svc-cymbal-914",
            "business_unit": "media_studio",
            "risk_tier": "AG2",
            "origin": "custom_hybrid",
            "months_active": 0.25,
            "turns_m": 6.9,
            "initial_score": 76.0,
            "final_score": 96.4,
            "remediated": True,
            "remediations_count": 2,
            "mix": _hybrid_mix(),
        },
        {
            "deployment_id": "DEP-2026-0921",
            "deployed_at": "2026-11-25T11:20:00Z",
            "agent_name": "fiber-cut-dispatch-coordinator",
            "app_id": "svc-cymbal-928",
            "business_unit": "core_cable",
            "risk_tier": "AG3",
            "origin": "custom_hybrid",
            "months_active": 0.25,
            "turns_m": 5.2,
            "initial_score": 64.0,
            "final_score": 97.0,
            "remediated": True,
            "remediations_count": 3,
            "mix": _hybrid_mix(),
        },
        {
            "deployment_id": "DEP-2026-0922",
            "deployed_at": "2026-11-25T16:55:00Z",
            "agent_name": "live-stream-ad-insertion-agent",
            "app_id": "svc-cymbal-945",
            "business_unit": "media_studio",
            "risk_tier": "AG2",
            "origin": "google_gcp_standard",
            "months_active": 0.25,
            "turns_m": 9.5,
            "initial_score": 96.4,
            "final_score": 98.5,
            "remediated": False,
            "remediations_count": 0,
            "mix": _default_slot_map("google_gcp"),
        },
    ]

    specs.sort(key=lambda s: str(s["deployed_at"]), reverse=True)

    records: list[dict[str, Any]] = []
    for item in specs:
        tpl = AgentDeploymentTemplate(
            template_id=item["agent_name"],
            name=item["agent_name"],
            agent_name=item["agent_name"],
            app_id=item["app_id"],
            intake_id=defs.intake_record_id,
            business_unit=item["business_unit"],
            risk_tier=item["risk_tier"],
            origin=item["origin"],
            estimated_monthly_turns_millions=item["turns_m"],
            behavior_score=item["final_score"],
            components=item["mix"],
        )
        cost_bd = calculate_template_component_costs(
            tpl, months_active=item["months_active"], profile=profile
        )
        records.append(
            {
                "deployment_id": item["deployment_id"],
                "deployed_at": item["deployed_at"],
                "agent_name": item["agent_name"],
                "app_id": item["app_id"],
                "intake_id": defs.intake_record_id,
                "business_unit": item["business_unit"],
                "business_unit_label": profile.terminology.business_units.get(
                    item["business_unit"], item["business_unit"]
                ),
                "risk_tier": item["risk_tier"],
                "template_id": item["agent_name"],
                "origin": item["origin"],
                "status": "ACTIVE",
                "approver_principal": "platform-governance-lead",
                "initial_eval_score": item["initial_score"],
                "final_eval_score": item["final_score"],
                "remediated_prior_to_deploy": item["remediated"],
                "remediations_applied_count": item["remediations_count"],
                "months_active": item["months_active"],
                "estimated_monthly_turns_millions": item["turns_m"],
                "onboarding_eval_cost_usd": cost_bd["onboarding_eval_cost_usd"],
                "monthly_run_rate_usd": cost_bd["monthly_run_rate_usd"],
                "historical_cumulative_usd": cost_bd["historical_cumulative_usd"],
                "monthly_savings_usd": cost_bd["monthly_savings_usd"],
                "component_choices": {
                    sid: tpl.components[sid].provider for sid in ORDERED_SLOT_IDS
                },
                "component_costs": cost_bd["component_costs"],
                "trace_id": f"trc-{item['deployment_id'].lower()}-w3c",
            }
        )
    return records


def _derive_recertification_signals(
    rec: Adr004RecertificationRecord,
) -> Adr004RecertificationRecord:
    """Computes ADR-004 30-day activity status & Day 75/85/89/90 alert stage."""
    last_activity = min(rec.days_since_last_llm_call, rec.days_since_last_a2a_message)
    rec.activity_status = "ACTIVE" if last_activity <= 30 else "INACTIVE"
    rec.days_remaining = max(0, 90 - rec.cycle_day)

    if rec.lifecycle_state == "DECOMMISSIONED":
        rec.identity_enabled = False
        rec.alert_stage = "NONE"
        return rec

    if rec.cycle_day >= 90 or rec.lifecycle_state == "EXPIRED":
        rec.lifecycle_state = "EXPIRED"
        rec.alert_stage = "DAY_90_EXPIRED"
        rec.identity_enabled = False
    elif rec.cycle_day == 89:
        rec.lifecycle_state = "DUE_SOON"
        rec.alert_stage = "DAY_89_FINAL_WARNING_1D"
        rec.identity_enabled = True
    elif rec.cycle_day >= 85:
        rec.lifecycle_state = "DUE_SOON"
        rec.alert_stage = "DAY_85_REMINDER_5D"
        rec.identity_enabled = True
    elif rec.cycle_day >= 75:
        rec.lifecycle_state = "DUE_SOON"
        rec.alert_stage = "DAY_75_DUE_IN_15D"
        rec.identity_enabled = True
    else:
        rec.lifecycle_state = "CURRENT"
        rec.alert_stage = "NONE"
        rec.identity_enabled = True
    return rec


def _seed_adr004_recertification_records() -> list[Adr004RecertificationRecord]:
    now_dt = datetime.datetime.now(datetime.timezone.utc)
    seeds = [
        {
            "agent_id": "subscriber-billing-concierge",
            "agent_name": "subscriber-billing-concierge",
            "description": "Billing lookup and credit-dispute concierge.",
            "owner_team": "Billing Automation Platform",
            "owner_email": "billing-ai-owners@cymbal.example",
            "current_scopes": ["billing.read", "memory.read", "mcp.use"],
            "cycle_day": 89,
            "days_since_last_llm_call": 42,
            "days_since_last_a2a_message": 45,
            "last_certified_by": "platform-lead@cymbal.example",
        },
        {
            "agent_id": "content-rights-clearance-agent",
            "agent_name": "content-rights-clearance-agent",
            "description": "Legacy catalog rights clearance helper (dormant).",
            "owner_team": "Media Rights Operations",
            "owner_email": "rights-ops@cymbal.example",
            "current_scopes": ["rights.read", "catalog.read"],
            "cycle_day": 86,
            "days_since_last_llm_call": 38,
            "days_since_last_a2a_message": 60,
            "last_certified_by": "media-steward@cymbal.example",
        },
        {
            "agent_id": "broadband-outage-triage-agent",
            "agent_name": "broadband-outage-triage-agent",
            "description": "Broadband telemetry & outage triage workflow agent.",
            "owner_team": "Network SRE AI",
            "owner_email": "net-sre@cymbal.example",
            "current_scopes": ["telemetry.read", "incident.annotate", "memory.write"],
            "cycle_day": 76,
            "days_since_last_llm_call": 1,
            "days_since_last_a2a_message": 2,
            "last_certified_by": "sre-lead@cymbal.example",
        },
        {
            "agent_id": "network-telemetry-advisor",
            "agent_name": "network-telemetry-advisor",
            "description": "Google-native network diagnostics advisor.",
            "owner_team": "Core Platform Engineering",
            "owner_email": "platform-eng@cymbal.example",
            "current_scopes": ["telemetry.read", "memory.read"],
            "cycle_day": 24,
            "days_since_last_llm_call": 0,
            "days_since_last_a2a_message": 1,
            "last_certified_by": "platform-lead@cymbal.example",
        },
        {
            "agent_id": "regional-privacy-retention-agent",
            "agent_name": "regional-privacy-retention-agent",
            "description": "Regional privacy retention & DSR assistant.",
            "owner_team": "Privacy & Compliance",
            "owner_email": "privacy-eng@cymbal.example",
            "current_scopes": ["privacy.audit", "memory.read"],
            "cycle_day": 18,
            "days_since_last_llm_call": 3,
            "days_since_last_a2a_message": 4,
            "last_certified_by": "privacy-lead@cymbal.example",
        },
    ]
    out: list[Adr004RecertificationRecord] = []
    for item in seeds:
        next_dt = now_dt + datetime.timedelta(days=max(0, 90 - item["cycle_day"]))
        rec = Adr004RecertificationRecord(
            **item,
            next_review_date=next_dt.strftime("%Y-%m-%d"),
            last_certified_at=(
                now_dt - datetime.timedelta(days=item["cycle_day"])
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            audit_log=[
                {
                    "action": "CYCLE_STARTED",
                    "actor": item["last_certified_by"],
                    "timestamp": (
                        now_dt - datetime.timedelta(days=item["cycle_day"])
                    ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "detail": "90-day ADR-004 recertification timer initialized.",
                }
            ],
        )
        out.append(_derive_recertification_signals(rec))
    return out


class WorkbenchGovernanceEngine:
    """Thread-safe lifecycle, rubric, inventory, fleet & FinOps state engine."""

    def __init__(self, state_dir: Path | None = None) -> None:
        self._lock = threading.Lock()
        env_dir = os.getenv("CYMBAL_RUNTIME_STATE_DIR")
        if state_dir is not None:
            self._state_dir = state_dir
        elif env_dir:
            self._state_dir = Path(env_dir) / "workbench"
        else:
            self._state_dir = Path("/tmp") / "cymbal_platform_workbench_v4"
        self._state_file = self._state_dir / "platform_state_v4.json"

        prof = load_tenant_profile()
        self._rubric: RubricConfig = _build_default_rubric(prof)
        self._deployments: list[dict[str, Any]] = _seed_historical_deployments(prof)
        seeded_agents: dict[str, AgentDeploymentTemplate] = {
            a.template_id: a for a in _seed_agent_inventory(prof)
        }
        # Register historical deployed agent instances into the unified Build inventory
        for dep in self._deployments:
            tid = str(dep["template_id"])
            if tid in seeded_agents:
                seeded_agents[tid].lifecycle_status = "DEPLOYED"
                seeded_agents[tid].latest_deployment_id = str(dep["deployment_id"])
                continue
            is_gcp_std = dep["origin"] == "google_gcp_standard"
            dep_slots = _default_slot_map("google_gcp") if is_gcp_std else {
                sid: SlotSelectionConfig(
                    slot_id=sid,
                    provider=LEGACY_PROVIDER_ALIAS.get(
                        str((dep.get("component_choices") or {}).get(sid, "google_gcp")),
                        "google_gcp",
                    ),
                    enabled=True,
                )
                for sid in ORDERED_SLOT_IDS
            }
            dep_ts = str(dep["deployed_at"])
            seeded_agents[tid] = AgentDeploymentTemplate(
                template_id=tid,
                name=tid,
                description=f"Production deployed agent instance ({dep['deployment_id']}).",
                template_mode="google_gcp" if is_gcp_std else "custom",
                origin=dep["origin"],
                agent_name=str(dep["agent_name"]),
                app_id=str(dep["app_id"]),
                intake_id=str(dep["intake_id"]),
                business_unit=dep["business_unit"],
                risk_tier=dep["risk_tier"],
                runtime_cloud="gcp",
                estimated_monthly_turns_millions=float(dep["estimated_monthly_turns_millions"]),
                uap_cel_per_tool_enforced=True,
                sdp_pii_mode="DEIDENTIFY_INLINE",
                prompt_version="v2",
                behavior_score=float(dep["final_eval_score"]),
                components=dep_slots,
                lifecycle_status="DEPLOYED",
                latest_deployment_id=str(dep["deployment_id"]),
                updated_at=dep_ts,
                updated_display=_format_display_from_iso(dep_ts),
            )
        self._agents: dict[str, AgentDeploymentTemplate] = seeded_agents
        self._recertifications: dict[str, Adr004RecertificationRecord] = {
            r.agent_id: r for r in _seed_adr004_recertification_records()
        }
        self._load_persisted_if_present()

    def _load_persisted_if_present(self) -> None:
        if not self._state_file.is_file():
            return
        try:
            raw = json.loads(self._state_file.read_text(encoding="utf-8"))
            if isinstance(raw.get("rubric"), dict):
                self._rubric = RubricConfig.model_validate(raw["rubric"])
            if isinstance(raw.get("agents"), list):
                loaded: dict[str, AgentDeploymentTemplate] = {}
                for item in raw["agents"]:
                    item["components"] = normalize_template_components(item.get("components"))
                    tpl = AgentDeploymentTemplate.model_validate(item)
                    loaded[tpl.template_id] = tpl
                if loaded:
                    self._agents = loaded
            if isinstance(raw.get("deployments"), list) and raw["deployments"]:
                self._deployments = list(raw["deployments"])
            if isinstance(raw.get("recertifications"), list) and raw["recertifications"]:
                loaded_recert: dict[str, Adr004RecertificationRecord] = {}
                for item in raw["recertifications"]:
                    rec = _derive_recertification_signals(
                        Adr004RecertificationRecord.model_validate(item)
                    )
                    loaded_recert[rec.agent_id] = rec
                if loaded_recert:
                    self._recertifications = loaded_recert
        except Exception:
            pass

    def _persist_locked(self) -> None:
        try:
            self._state_dir.mkdir(parents=True, exist_ok=True)
            payload = {
                "rubric": self._rubric.model_dump(),
                "agents": [a.model_dump() for a in self._agents.values()],
                "deployments": self._deployments,
                "recertifications": [r.model_dump() for r in self._recertifications.values()],
            }
            self._state_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception:
            pass

    def get_rubric(self) -> RubricConfig:
        with self._lock:
            prof = load_tenant_profile()
            rub = copy.deepcopy(self._rubric)
            rub.name = prof.terminology.best_practices_name
            return rub

    def update_rubric(self, updated_rubric: RubricConfig) -> RubricConfig:
        with self._lock:
            updated_rubric.updated_at = _utc_now_iso()
            self._rubric = copy.deepcopy(updated_rubric)
            self._persist_locked()
            return copy.deepcopy(self._rubric)

    def _enrich_template_dump(
        self,
        norm_tpl: AgentDeploymentTemplate,
        ev: dict[str, Any],
        prof: TenantProfile,
    ) -> dict[str, Any]:
        dumped = norm_tpl.model_dump()
        cost_est = ev["cost_estimate"]
        dumped["business_unit_label"] = prof.terminology.business_units.get(
            norm_tpl.business_unit, norm_tpl.business_unit
        )
        dumped["latest_eval_score"] = ev["overall_score"]
        dumped["passing_threshold"] = ev["passing_threshold"]
        dumped["gate_passed"] = ev["gate_passed"]
        dumped["overall_status"] = ev["overall_status"]
        dumped["gate_verdict"] = ev["gate_verdict"]
        dumped["ag5_prohibited_blocked"] = ev["ag5_prohibited_blocked"]
        dumped["mandatory_failures_count"] = ev["mandatory_failures_count"]
        dumped["recommendations_count"] = ev["recommendations_count"]
        dumped["caas_matrix"] = ev["caas_matrix"]
        dumped["phase5_reviewer_gate"] = ev["phase5_reviewer_gate"]
        dumped["aigl_lifecycle"] = ev["aigl_lifecycle"]
        dumped["monthly_run_rate_usd"] = cost_est["monthly_run_rate_usd"]
        dumped["onboarding_eval_cost_usd"] = cost_est["onboarding_eval_cost_usd"]
        dumped["monthly_savings_usd"] = cost_est["monthly_savings_usd"]
        dumped["historical_cumulative_usd"] = cost_est["historical_cumulative_usd"]
        dumped["component_costs"] = cost_est["component_costs"]
        return dumped

    def list_templates(self) -> list[dict[str, Any]]:
        prof = load_tenant_profile()
        with self._lock:
            rub = copy.deepcopy(self._rubric)
            out: list[dict[str, Any]] = []
            for tpl in self._agents.values():
                norm_tpl = copy.deepcopy(tpl)
                norm_tpl.components = normalize_template_components(norm_tpl.components)
                ev = evaluate_template_against_rubric(norm_tpl, rub, profile=prof)
                out.append(self._enrich_template_dump(norm_tpl, ev, prof))
            out.sort(key=lambda x: str(x.get("updated_at", "")), reverse=True)
            return out

    def upsert_template(self, template: AgentDeploymentTemplate) -> dict[str, Any]:
        prof = load_tenant_profile()
        with self._lock:
            template.components = normalize_template_components(template.components)
            template.updated_at = _utc_now_iso()
            template.updated_display = _display_timestamp_now()
            self._agents[template.template_id] = copy.deepcopy(template)
            self._persist_locked()
            ev = evaluate_template_against_rubric(template, self._rubric, profile=prof)
            return self._enrich_template_dump(template, ev, prof)

    def record_deployment(
        self,
        *,
        template: AgentDeploymentTemplate,
        initial_score: float,
        approver_principal: str = "platform-governance-lead",
        trace_id: str = "",
    ) -> dict[str, Any]:
        if template.risk_tier == "AG5":
            raise ValueError(
                "AEGIS AG5 (Fully Autonomous) is prohibited by enterprise policy and cannot be deployed."
            )
        prof = load_tenant_profile()
        with self._lock:
            dep_id = f"DEP-2026-{1000 + len(self._deployments) + 1}"
            now_iso = _utc_now_iso()
            template.components = normalize_template_components(template.components)
            template.lifecycle_status = "DEPLOYED"
            template.latest_deployment_id = dep_id
            template.updated_at = now_iso
            template.updated_display = _format_display_from_iso(now_iso)
            self._agents[template.template_id] = copy.deepcopy(template)

            ev = evaluate_template_against_rubric(template, self._rubric, profile=prof)
            costs = calculate_template_component_costs(template, months_active=1.0, profile=prof)
            remediated = bool(template.applied_remediations) or (
                ev["overall_score"] > initial_score + 0.05
            )
            record = {
                "deployment_id": dep_id,
                "deployed_at": now_iso,
                "agent_name": template.agent_name,
                "app_id": template.app_id,
                "intake_id": template.intake_id or prof.governance_defaults.intake_record_id,
                "business_unit": template.business_unit,
                "business_unit_label": prof.terminology.business_units.get(
                    template.business_unit, template.business_unit
                ),
                "risk_tier": template.risk_tier,
                "template_id": template.template_id,
                "origin": template.origin,
                "status": "ACTIVE",
                "approver_principal": approver_principal,
                "initial_eval_score": round(float(initial_score), 1),
                "final_eval_score": ev["overall_score"],
                "remediated_prior_to_deploy": remediated,
                "remediations_applied_count": len(template.applied_remediations),
                "applied_remediations": list(template.applied_remediations),
                "exception_overrides": dict(template.exception_overrides),
                "months_active": 1.0,
                "estimated_monthly_turns_millions": template.estimated_monthly_turns_millions,
                "onboarding_eval_cost_usd": costs["onboarding_eval_cost_usd"],
                "monthly_run_rate_usd": costs["monthly_run_rate_usd"],
                "historical_cumulative_usd": costs["historical_cumulative_usd"],
                "monthly_savings_usd": costs["monthly_savings_usd"],
                "component_choices": {
                    sid: (
                        template.components[sid].provider
                        if sid in template.components and template.components[sid].enabled
                        else "unconfigured"
                    )
                    for sid in ORDERED_SLOT_IDS
                },
                "component_costs": costs["component_costs"],
                "trace_id": trace_id or f"trc-{dep_id.lower()}-live",
            }
            self._deployments.insert(0, record)
            self._persist_locked()
            return copy.deepcopy(record)

    def build_operations_metrics(self) -> dict[str, Any]:
        prof = load_tenant_profile()
        slot_catalog = build_localized_slot_catalog(prof)
        with self._lock:
            deps = copy.deepcopy(self._deployments)
        deps.sort(key=lambda d: str(d.get("deployed_at", "")), reverse=True)

        total = len(deps) or 1
        remediated_cnt = sum(1 for d in deps if d.get("remediated_prior_to_deploy"))
        avg_initial = round(
            sum(float(d.get("initial_eval_score", 0.0)) for d in deps) / total, 1
        )
        avg_final = round(
            sum(float(d.get("final_eval_score", 0.0)) for d in deps) / total, 1
        )

        origin_counts: dict[str, int] = {
            "google_gcp_standard": 0,
            "custom_hybrid": 0,
            "imported_manifest": 0,
        }
        slot_adoption: list[dict[str, Any]] = []

        for d in deps:
            raw_orig = str(d.get("origin", "custom_hybrid"))
            orig = "custom_hybrid" if raw_orig == "cymbal_baseline" else raw_orig
            d["origin"] = orig
            origin_counts[orig] = origin_counts.get(orig, 0) + 1
            bu = str(d.get("business_unit", "core_cable"))
            d["business_unit_label"] = prof.terminology.business_units.get(bu, bu)

        for spec in slot_catalog:
            sid = spec["slot_id"]
            counts = {"cymbal_stack": 0, "google_gcp": 0, "unconfigured": 0}
            for d in deps:
                raw_ch = (d.get("component_choices") or {}).get(sid, "google_gcp")
                ch = LEGACY_PROVIDER_ALIAS.get(str(raw_ch), "google_gcp")
                counts[ch] = counts.get(ch, 0) + 1
            slot_adoption.append(
                {
                    "slot_id": sid,
                    "step": spec["step"],
                    "pillar": spec["pillar"],
                    "workstream": spec["workstream"],
                    "functional_name": spec["functional_name"],
                    "provider_labels": spec["provider_labels"],
                    "counts": counts,
                    "google_gcp_pct": round((counts["google_gcp"] / total) * 100.0, 1),
                }
            )

        standard_cnt = origin_counts["google_gcp_standard"]
        return {
            "total_deployments": len(deps),
            "remediated_prior_to_deploy_count": remediated_cnt,
            "remediated_prior_to_deploy_pct": round((remediated_cnt / total) * 100.0, 1),
            "clean_first_pass_count": len(deps) - remediated_cnt,
            "avg_initial_eval_score": avg_initial,
            "avg_final_eval_score": avg_final,
            "avg_score_uplift": round(avg_final - avg_initial, 1),
            "standard_template_count": standard_cnt,
            "custom_or_imported_count": len(deps) - standard_cnt,
            "origin_breakdown": origin_counts,
            "component_adoption": slot_adoption,
            "deployments": deps,
        }

    def build_executive_cost_summary(
        self,
        *,
        business_unit_filter: str = "all",
        origin_filter: str = "all",
    ) -> dict[str, Any]:
        prof = load_tenant_profile()
        slot_catalog = {s["slot_id"]: s for s in build_localized_slot_catalog(prof)}
        with self._lock:
            all_deps = copy.deepcopy(self._deployments)

        filtered: list[dict[str, Any]] = []
        for d in all_deps:
            if business_unit_filter != "all" and d.get("business_unit") != business_unit_filter:
                continue
            if origin_filter != "all" and d.get("origin") != origin_filter:
                continue
            bu = str(d.get("business_unit", "core_cable"))
            d["business_unit_label"] = prof.terminology.business_units.get(bu, bu)
            filtered.append(d)
        filtered.sort(key=lambda d: str(d.get("deployed_at", "")), reverse=True)

        total_historical_usd = round(
            sum(float(d.get("historical_cumulative_usd", 0.0)) for d in filtered), 2
        )
        total_monthly_run_rate_usd = round(
            sum(float(d.get("monthly_run_rate_usd", 0.0)) for d in filtered), 2
        )
        total_onboarding_usd = round(
            sum(float(d.get("onboarding_eval_cost_usd", 0.0)) for d in filtered), 2
        )
        total_monthly_savings_usd = round(
            sum(float(d.get("monthly_savings_usd", 0.0)) for d in filtered), 2
        )

        slot_agg: dict[str, dict[str, Any]] = {}
        pillar_agg: dict[str, dict[str, Any]] = {
            p: {"pillar": p, "historical_cumulative_usd": 0.0, "monthly_run_rate_usd": 0.0}
            for p in PILLAR_ORDER
        }
        for sid in ORDERED_SLOT_IDS:
            spec = slot_catalog[sid]
            slot_agg[sid] = {
                "slot_id": sid,
                "step": spec["step"],
                "pillar": spec["pillar"],
                "workstream": spec["workstream"],
                "functional_name": spec["functional_name"],
                "capability_name": spec["functional_name"],
                "consolidates": spec["consolidates"],
                "provider_labels": spec["provider_labels"],
                "historical_cumulative_usd": 0.0,
                "monthly_run_rate_usd": 0.0,
                "onboarding_cost_usd": 0.0,
                "monthly_savings_usd": 0.0,
                "spend_by_provider_usd": {"cymbal_stack": 0.0, "google_gcp": 0.0},
                "deployments_by_provider": {"cymbal_stack": 0, "google_gcp": 0},
                "top_deployments": [],
            }

        for d in filtered:
            for comp in d.get("component_costs") or []:
                sid = LEGACY_SLOT_ALIAS.get(comp["slot_id"], comp["slot_id"])
                if sid not in slot_agg:
                    continue
                prov = LEGACY_PROVIDER_ALIAS.get(str(comp.get("provider")), "google_gcp")
                hist_c = float(comp.get("historical_cumulative_usd", 0.0))
                mo_c = float(comp.get("monthly_cost_usd", 0.0))
                onb_c = float(comp.get("onboarding_cost_usd", 0.0))
                sav_c = float(comp.get("monthly_savings_usd", 0.0))

                agg = slot_agg[sid]
                agg["historical_cumulative_usd"] = round(
                    agg["historical_cumulative_usd"] + hist_c, 2
                )
                agg["monthly_run_rate_usd"] = round(agg["monthly_run_rate_usd"] + mo_c, 2)
                agg["onboarding_cost_usd"] = round(agg["onboarding_cost_usd"] + onb_c, 2)
                agg["monthly_savings_usd"] = round(agg["monthly_savings_usd"] + sav_c, 2)
                if prov in agg["spend_by_provider_usd"]:
                    agg["spend_by_provider_usd"][prov] = round(
                        agg["spend_by_provider_usd"][prov] + hist_c, 2
                    )
                    agg["deployments_by_provider"][prov] += 1

                p_key = agg["pillar"]
                if p_key in pillar_agg:
                    pillar_agg[p_key]["historical_cumulative_usd"] = round(
                        pillar_agg[p_key]["historical_cumulative_usd"] + hist_c, 2
                    )
                    pillar_agg[p_key]["monthly_run_rate_usd"] = round(
                        pillar_agg[p_key]["monthly_run_rate_usd"] + mo_c, 2
                    )

                agg["top_deployments"].append(
                    {
                        "deployment_id": d["deployment_id"],
                        "agent_name": d["agent_name"],
                        "business_unit_label": d["business_unit_label"],
                        "provider": prov,
                        "historical_cumulative_usd": round(hist_c, 2),
                        "monthly_cost_usd": round(mo_c, 2),
                    }
                )

        denom = total_historical_usd if total_historical_usd > 0 else 1.0
        component_rollup: list[dict[str, Any]] = []
        for sid in ORDERED_SLOT_IDS:
            agg = slot_agg[sid]
            agg["share_of_total_pct"] = round(
                (agg["historical_cumulative_usd"] / denom) * 100.0, 1
            )
            agg["top_deployments"] = sorted(
                agg["top_deployments"],
                key=lambda x: x["historical_cumulative_usd"],
                reverse=True,
            )[:5]
            component_rollup.append(agg)

        pillar_rollup: list[dict[str, Any]] = []
        for p in PILLAR_ORDER:
            pa = pillar_agg[p]
            pa["share_of_total_pct"] = round(
                (pa["historical_cumulative_usd"] / denom) * 100.0, 1
            )
            pillar_rollup.append(pa)

        return {
            "filters": {
                "business_unit": business_unit_filter,
                "origin": origin_filter,
            },
            "deployment_count": len(filtered),
            "total_historical_cumulative_usd": total_historical_usd,
            "total_monthly_run_rate_usd": total_monthly_run_rate_usd,
            "total_onboarding_eval_usd": total_onboarding_usd,
            "projected_annual_run_rate_usd": round(total_monthly_run_rate_usd * 12.0, 2),
            "projected_annual_consolidation_savings_usd": round(
                total_monthly_savings_usd * 12.0, 2
            ),
            "avg_cost_per_deployment_monthly_usd": round(
                total_monthly_run_rate_usd / (len(filtered) or 1), 2
            ),
            "pillar_cost_rollup": pillar_rollup,
            "component_cost_rollup": component_rollup,
            "deployments": filtered,
        }

    def list_recertification_records(self) -> list[dict[str, Any]]:
        """Returns ADR-004 90-day recertification queue (INACTIVE & expiring-soon first)."""
        with self._lock:
            records = [_derive_recertification_signals(copy.deepcopy(r)) for r in self._recertifications.values()]
        records.sort(
            key=lambda r: (
                0 if r.activity_status == "INACTIVE" else 1,
                0 if r.lifecycle_state == "EXPIRED" else 1,
                r.days_remaining,
                r.agent_id,
            )
        )
        return [r.model_dump() for r in records]

    def recertify_agent(
        self,
        agent_id: str,
        *,
        scopes_confirmed: list[str] | None = None,
        scopes_removed: list[str] | None = None,
        certified_by: str = "platform-owner@cymbal.example",
        next_review_date: str | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            rec = self._recertifications.get(agent_id)
            if rec is None:
                raise KeyError(f"Unknown agent_id for recertification: {agent_id}")
            now_dt = datetime.datetime.now(datetime.timezone.utc)
            now_iso = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            removed_set = {s.strip() for s in (scopes_removed or []) if s.strip()}
            if scopes_confirmed is not None:
                updated_scopes = [
                    s.strip()
                    for s in scopes_confirmed
                    if s.strip() and s.strip() not in removed_set
                ]
            else:
                updated_scopes = [s for s in rec.current_scopes if s not in removed_set]

            rec.current_scopes = updated_scopes
            rec.cycle_day = 0
            rec.days_remaining = 90
            rec.lifecycle_state = "CURRENT"
            rec.alert_stage = "NONE"
            rec.identity_enabled = True
            rec.last_certified_by = certified_by
            rec.last_certified_at = now_iso
            rec.next_review_date = next_review_date or (
                now_dt + datetime.timedelta(days=90)
            ).strftime("%Y-%m-%d")
            rec.audit_log.insert(
                0,
                {
                    "action": "RECERTIFIED",
                    "actor": certified_by,
                    "timestamp": now_iso,
                    "scopes_confirmed": updated_scopes,
                    "scopes_removed": sorted(removed_set),
                    "detail": (
                        f"Recertified by {certified_by}; 90-day timer reset; "
                        f"removed scopes={sorted(removed_set)}."
                    ),
                },
            )
            _derive_recertification_signals(rec)
            self._persist_locked()
            return rec.model_dump()

    def expire_agent(
        self,
        agent_id: str,
        *,
        reason: str = "Missed ADR-004 90-day recertification deadline",
    ) -> dict[str, Any]:
        with self._lock:
            rec = self._recertifications.get(agent_id)
            if rec is None:
                raise KeyError(f"Unknown agent_id for expiration: {agent_id}")
            now_iso = _utc_now_iso()
            rec.cycle_day = max(rec.cycle_day, 90)
            rec.lifecycle_state = "EXPIRED"
            rec.alert_stage = "DAY_90_EXPIRED"
            rec.identity_enabled = False
            rec.days_remaining = 0
            rec.audit_log.insert(
                0,
                {
                    "action": "EXPIRED",
                    "actor": "adr004-scheduler",
                    "timestamp": now_iso,
                    "detail": f"Agent expired; Agent Identity disabled so OBO fails ({reason}).",
                },
            )
            self._persist_locked()
            return rec.model_dump()

    def offboard_agent(
        self,
        agent_id: str,
        *,
        actor: str = "platform-owner@cymbal.example",
        transfer_owner: str = "archived-platform-steward",
    ) -> dict[str, Any]:
        with self._lock:
            rec = self._recertifications.get(agent_id)
            if rec is None:
                raise KeyError(f"Unknown agent_id for offboarding: {agent_id}")
            now_iso = _utc_now_iso()
            rec.lifecycle_state = "DECOMMISSIONED"
            rec.identity_enabled = False
            rec.alert_stage = "NONE"
            rec.current_scopes = []
            rec.owner_team = transfer_owner
            rec.audit_log.insert(
                0,
                {
                    "action": "OFFBOARDED_DECOMMISSIONED",
                    "actor": actor,
                    "timestamp": now_iso,
                    "transfer_owner": transfer_owner,
                    "detail": (
                        f"Phase 7 Offboarding completed by {actor}; access revoked, "
                        f"Agent Identity disabled, ownership transferred to {transfer_owner}."
                    ),
                },
            )
            for dep in self._deployments:
                if dep.get("agent_name") == agent_id or dep.get("template_id") == agent_id:
                    dep["status"] = "DECOMMISSIONED"
            self._persist_locked()
            return rec.model_dump()

    def advance_recertification_timer(
        self,
        agent_id: str,
        *,
        cycle_day: int,
        days_since_activity: int | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            rec = self._recertifications.get(agent_id)
            if rec is None:
                raise KeyError(f"Unknown agent_id for timer update: {agent_id}")
            rec.cycle_day = max(0, int(cycle_day))
            if days_since_activity is not None:
                rec.days_since_last_llm_call = max(0, int(days_since_activity))
                rec.days_since_last_a2a_message = max(0, int(days_since_activity))
            if rec.lifecycle_state == "EXPIRED" and rec.cycle_day < 90:
                rec.lifecycle_state = "CURRENT"
            _derive_recertification_signals(rec)
            self._persist_locked()
            return rec.model_dump()
