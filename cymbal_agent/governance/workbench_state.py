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

from cymbal_agent.tenant import TenantProfile, load_tenant_profile

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
    risk_tier: Literal["AG1", "AG2", "AG3", "AG4"] = "AG2"
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
            "cymbal_stack": {"base_monthly_usd": 140.0, "per_1m_turns_usd": 22.0, "onboarding_usd": 180.0},
            "google_gcp": {"base_monthly_usd": 50.0, "per_1m_turns_usd": 7.0, "onboarding_usd": 65.0},
            "unconfigured": {"base_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
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
            "cymbal_stack": {"base_monthly_usd": 110.0, "per_1m_turns_usd": 10.0, "onboarding_usd": 210.0},
            "google_gcp": {"base_monthly_usd": 45.0, "per_1m_turns_usd": 5.0, "onboarding_usd": 60.0},
            "unconfigured": {"base_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
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
            "cymbal_stack": {"base_monthly_usd": 230.0, "per_1m_turns_usd": 58.0, "onboarding_usd": 200.0},
            "google_gcp": {"base_monthly_usd": 105.0, "per_1m_turns_usd": 26.0, "onboarding_usd": 85.0},
            "unconfigured": {"base_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
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
            "cymbal_stack": {"base_monthly_usd": 180.0, "per_1m_turns_usd": 1000.0, "onboarding_usd": 250.0},
            "google_gcp": {"base_monthly_usd": 45.0, "per_1m_turns_usd": 100.0, "onboarding_usd": 75.0},
            "unconfigured": {"base_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
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
            "cymbal_stack": {"base_monthly_usd": 120.0, "per_1m_turns_usd": 420.0, "onboarding_usd": 110.0},
            "google_gcp": {"base_monthly_usd": 0.0, "per_1m_turns_usd": 240.0, "onboarding_usd": 40.0},
            "unconfigured": {"base_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
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
            "cymbal_stack": {"base_monthly_usd": 260.0, "per_1m_turns_usd": 185.0, "onboarding_usd": 290.0},
            "google_gcp": {"base_monthly_usd": 120.0, "per_1m_turns_usd": 95.0, "onboarding_usd": 90.0},
            "unconfigured": {"base_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
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
            "cymbal_stack": {"base_monthly_usd": 175.0, "per_1m_turns_usd": 52.0, "onboarding_usd": 150.0},
            "google_gcp": {"base_monthly_usd": 65.0, "per_1m_turns_usd": 18.0, "onboarding_usd": 55.0},
            "unconfigured": {"base_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
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
            "cymbal_stack": {"base_monthly_usd": 165.0, "per_1m_turns_usd": 48.0, "onboarding_usd": 140.0},
            "google_gcp": {"base_monthly_usd": 65.0, "per_1m_turns_usd": 20.0, "onboarding_usd": 50.0},
            "unconfigured": {"base_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
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
            "cymbal_stack": {"base_monthly_usd": 150.0, "per_1m_turns_usd": 30.0, "onboarding_usd": 130.0},
            "google_gcp": {"base_monthly_usd": 55.0, "per_1m_turns_usd": 12.0, "onboarding_usd": 45.0},
            "unconfigured": {"base_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
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
            "cymbal_stack": {"base_monthly_usd": 280.0, "per_1m_turns_usd": 92.0, "onboarding_usd": 340.0},
            "google_gcp": {"base_monthly_usd": 85.0, "per_1m_turns_usd": 38.0, "onboarding_usd": 85.0},
            "unconfigured": {"base_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
        },
    },
]

SLOT_SPEC_BY_ID: dict[str, dict[str, Any]] = {s["slot_id"]: s for s in SLOT_CATALOG_SPECS}
ORDERED_SLOT_IDS: list[str] = [s["slot_id"] for s in SLOT_CATALOG_SPECS]
PILLAR_ORDER: list[str] = ["Control", "Intelligence", "Economics", "Experience"]


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _display_timestamp_now() -> str:
    now = datetime.datetime.now()
    hour = now.strftime("%I").lstrip("0") or "12"
    ampm = now.strftime("%p").lower()
    return f"{now.month}/{now.day}/{now.year} {hour}:{now.strftime('%M')}{ampm}"


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
    catalog: list[dict[str, Any]] = []
    for spec in SLOT_CATALOG_SPECS:
        sid = spec["slot_id"]
        cymbal_label = cymbal_names.get(sid, f"Cymbal {spec['functional_name']}")
        item = copy.deepcopy(spec)
        item["capability_name"] = spec["functional_name"]
        item["cymbal_name"] = cymbal_label
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
                remediation_provider="cymbal_stack",
                remediation_summary=f"Assign approved {terms.intake_name} ID and register in {terms.registry_name}.",
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
                remediation_provider="cymbal_stack",
                remediation_summary="Enable OpenTelemetry span export to Langfuse + OpenTelemetry or Google Cloud Trace.",
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
    now_iso = _utc_now_iso()

    # 1. example-agent-1 (matches wireframe row 1, hybrid Cymbal + Google Cloud)
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
        description="Hybrid Cymbal foundation + Google Cloud runtime, guardrails, and evaluation.",
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
        updated_at=now_iso,
        updated_display="11/25/2026 11:50am",
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
        updated_at=now_iso,
        updated_display="11/25/2026 10:15am",
    )

    # 3. subscriber-billing-concierge (Custom template selecting Cymbal components)
    agent_3 = AgentDeploymentTemplate(
        template_id="subscriber-billing-concierge",
        name="subscriber-billing-concierge",
        description="Custom deployment configuration using Cymbal enterprise components.",
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
        updated_at=now_iso,
        updated_display="11/24/2026 4:35pm",
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
        updated_at=now_iso,
        updated_display="11/24/2026 2:10pm",
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
        updated_at=now_iso,
        updated_display="11/23/2026 5:45pm",
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
        updated_at=now_iso,
        updated_display="11/22/2026 9:20am",
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


def calculate_template_component_costs(
    template: AgentDeploymentTemplate,
    months_active: float = 1.0,
    profile: TenantProfile | None = None,
) -> dict[str, Any]:
    prof = profile or load_tenant_profile()
    slot_catalog = {s["slot_id"]: s for s in build_localized_slot_catalog(prof)}
    turns_m = max(0.1, float(template.estimated_monthly_turns_millions))
    months = max(0.25, float(months_active))

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
        rates = spec["pricing"].get(prov, spec["pricing"]["unconfigured"])
        cymbal_rates = spec["pricing"]["cymbal_stack"]

        slot_monthly = round(
            float(rates["base_monthly_usd"]) + float(rates["per_1m_turns_usd"]) * turns_m,
            2,
        )
        slot_onboarding = round(float(rates["onboarding_usd"]), 2)
        slot_historical = round(slot_monthly * months + slot_onboarding, 2)
        slot_cymbal_monthly = round(
            float(cymbal_rates["base_monthly_usd"])
            + float(cymbal_rates["per_1m_turns_usd"]) * turns_m,
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
                "monthly_cost_usd": slot_monthly,
                "onboarding_cost_usd": slot_onboarding,
                "historical_cumulative_usd": slot_historical,
                "baseline_monthly_usd": slot_cymbal_monthly,
                "monthly_savings_usd": round(slot_cymbal_monthly - slot_monthly, 2),
                "consolidates": spec["consolidates"],
            }
        )

    return {
        "estimated_monthly_turns_millions": turns_m,
        "months_active": months,
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
    gw_slot = template.components.get("ai_gateway")
    otlp_slot = template.components.get("observability_tracing")
    guard_slot = template.components.get("safety_guardrails")
    mdl_slot = template.components.get("foundation_model")

    return (
        f'module "{mod_slug}_deployment" {{\n'
        f'  source                  = "./infra/terraform"\n'
        f'  agent_id                = "{template.agent_name}"\n'
        f'  cmdb_app_id             = "{template.app_id}"\n'
        f'  governance_intake_id    = "{template.intake_id or defs.intake_record_id}"\n'
        f'  business_unit           = "{prof.terminology.business_units.get(template.business_unit, template.business_unit)}"\n'
        f'  agency_tier             = "{template.risk_tier}"\n'
        f'  gateway_provider        = "{gw_slot.provider if gw_slot else "google_gcp"}"\n'
        f'  gateway_endpoint        = "{defs.hybrid_gateway_placeholder_url}"\n'
        f'  telemetry_provider      = "{otlp_slot.provider if otlp_slot else "google_gcp"}"\n'
        f'  otlp_collector_endpoint = "{defs.hybrid_otlp_placeholder_url}"\n'
        f'  guardrail_provider      = "{guard_slot.provider if guard_slot else "google_gcp"}"\n'
        f'  sdp_pii_mode            = "{template.sdp_pii_mode}"\n'
        f'  uap_cel_per_tool_authz  = {str(template.uap_cel_per_tool_enforced).lower()}\n'
        f'  foundation_model_slot   = "{mdl_slot.provider if mdl_slot else "google_gcp"}"\n'
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
            "LOW_AND_ABOVE" if template.risk_tier in {"AG3", "AG4"} else "MEDIUM_AND_ABOVE"
        ),
        "malicious_uri_filter": True,
        "sdp_pii_mode": sdp_mode,
        "rai_sensitivity": "MEDIUM_AND_ABOVE",
        "resolved_floor_template": (
            "cymbal-strict-ag3-gpp"
            if template.risk_tier in {"AG3", "AG4"} or template.business_unit == "intl_sky"
            else "cymbal-default-medium-gpp"
        ),
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
            elif prov == "cymbal_stack" and template.risk_tier in {"AG3", "AG4"}:
                passed = False
                gap_reasons.append(
                    "AG3/AG4 workload uses static guardrail templates rather than dynamic per-request Model Armor + Cloud SDP."
                )

        if rule.rule_id in {"RUB-06", "RUB-07"} and prov == "cymbal_stack":
            passed = False
            gap_reasons.append(
                f"Advisory upgrade available: switch {spec['functional_name']} to {spec['gcp_name']}."
            )

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
        status_label: Literal["PASSED", "EXCEPTION_APPROVED", "FAILED"] = "PASSED"
        if passed:
            earned_weight += rule.weight_points
            pillar_totals.setdefault(rule.pillar, [0.0, 0.0])[0] += rule.weight_points
        elif exception_note:
            status_label = "EXCEPTION_APPROVED"
            earned_weight += rule.weight_points * 0.5
            pillar_totals.setdefault(rule.pillar, [0.0, 0.0])[0] += rule.weight_points * 0.5
            if slot_statuses.get(sid) == "PASSED":
                slot_statuses[sid] = "ADVISORY"
        else:
            status_label = "FAILED"
            if rule.mandatory:
                mandatory_blocking_count += 1
                slot_statuses[sid] = "FAILED"
            elif slot_statuses.get(sid) == "PASSED":
                slot_statuses[sid] = "ADVISORY"

        pillar_totals.setdefault(rule.pillar, [0.0, 0.0])[1] += rule.weight_points
        score_uplift = round((rule.weight_points / total_weight) * 100.0, 1)

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

        if status_label == "FAILED":
            target_prov = LEGACY_PROVIDER_ALIAS.get(rule.remediation_provider, "google_gcp")
            hypothetical = copy.deepcopy(template)
            hypothetical.components[sid] = SlotSelectionConfig(
                slot_id=sid,
                provider=target_prov,
                enabled=True,
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
                    "severity": "MANDATORY_GATE" if rule.mandatory else "ADVISORY",
                    "title": rule.title,
                    "finding_detail": " ".join(gap_reasons),
                    "recommendation_summary": rule.remediation_summary,
                    "recommended_provider": target_prov,
                    "recommended_provider_label": spec["provider_labels"][target_prov],
                    "score_uplift_pts": score_uplift,
                    "monthly_cost_delta_usd": cost_delta,
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
    gate_passed = (
        overall_score >= rubric.passing_score_threshold and mandatory_blocking_count == 0
    )

    pillar_summary = {}
    for p_name, (earned, possible) in pillar_totals.items():
        pillar_summary[p_name] = {
            "earned_pts": round(earned, 1),
            "possible_pts": round(possible, 1),
            "pct": round((earned / possible) * 100.0, 1) if possible > 0 else 100.0,
        }

    return {
        "rubric_id": rubric.rubric_id,
        "rubric_name": rubric.name,
        "overall_score": overall_score,
        "passing_threshold": rubric.passing_score_threshold,
        "gate_passed": gate_passed,
        "gate_verdict": "READY_FOR_DEPLOYMENT" if gate_passed else "REMEDIATION_REQUIRED",
        "mandatory_failures_count": mandatory_blocking_count,
        "recommendations_count": len(recommendations),
        "pillar_scores": pillar_summary,
        "slot_statuses": slot_statuses,
        "rule_results": rule_results,
        "recommendations": recommendations,
        "cost_estimate": current_costs,
        "dynamic_guardrail_policy_preview": generate_dynamic_guardrail_policy_preview(template),
        "terraform_paved_path_hcl": generate_terraform_paved_path_preview(template, profile=prof),
    }


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
    updated.components[sid] = SlotSelectionConfig(
        slot_id=sid,
        provider=target_provider,
        enabled=target_provider != "unconfigured",
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

    tpl_payload: dict[str, Any] = {
        "template_id": str(parsed.get("template_id") or agent_id_val),
        "name": str(parsed.get("name") or agent_id_val),
        "description": str(
            parsed.get("description")
            or f"Imported agent manifest ({safe_name}) registered in {prof.terminology.platform_name}."
        ),
        "template_mode": "custom",
        "origin": "imported_manifest",
        "agent_name": agent_id_val,
        "app_id": str(parsed.get("app_id") or "svc-cymbal-imported")[:64],
        "intake_id": str(parsed.get("intake_id") or "")[:64],
        "business_unit": parsed.get("business_unit") or "core_cable",
        "risk_tier": parsed.get("risk_tier") or "AG2",
        "onboarding_path": "Path B: SDK Integration",
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
            "deployed_at": "2026-11-15T16:40:00Z",
            "agent_name": "gateway-firmware-rollout-agent",
            "app_id": "svc-cymbal-812",
            "business_unit": "core_cable",
            "risk_tier": "AG3",
            "origin": "custom_hybrid",
            "months_active": 0.5,
            "turns_m": 5.0,
            "initial_score": 70.0,
            "final_score": 97.2,
            "remediated": True,
            "remediations_count": 3,
            "mix": _hybrid_mix(),
        },
    ]

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
            self._state_dir = Path("/tmp") / "cymbal_platform_workbench_v3"
        self._state_file = self._state_dir / "platform_state_v3.json"

        prof = load_tenant_profile()
        self._rubric: RubricConfig = _build_default_rubric(prof)
        self._agents: dict[str, AgentDeploymentTemplate] = {
            a.template_id: a for a in _seed_agent_inventory(prof)
        }
        self._deployments: list[dict[str, Any]] = _seed_historical_deployments(prof)
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
        except Exception:
            pass

    def _persist_locked(self) -> None:
        try:
            self._state_dir.mkdir(parents=True, exist_ok=True)
            payload = {
                "rubric": self._rubric.model_dump(),
                "agents": [a.model_dump() for a in self._agents.values()],
                "deployments": self._deployments,
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

    def list_templates(self) -> list[dict[str, Any]]:
        prof = load_tenant_profile()
        with self._lock:
            rub = copy.deepcopy(self._rubric)
            out: list[dict[str, Any]] = []
            for tpl in self._agents.values():
                norm_tpl = copy.deepcopy(tpl)
                norm_tpl.components = normalize_template_components(norm_tpl.components)
                ev = evaluate_template_against_rubric(norm_tpl, rub, profile=prof)
                dumped = norm_tpl.model_dump()
                dumped["business_unit_label"] = prof.terminology.business_units.get(
                    norm_tpl.business_unit, norm_tpl.business_unit
                )
                dumped["latest_eval_score"] = ev["overall_score"]
                dumped["gate_passed"] = ev["gate_passed"]
                dumped["monthly_run_rate_usd"] = ev["cost_estimate"]["monthly_run_rate_usd"]
                out.append(dumped)
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
            dumped = template.model_dump()
            dumped["business_unit_label"] = prof.terminology.business_units.get(
                template.business_unit, template.business_unit
            )
            dumped["latest_eval_score"] = ev["overall_score"]
            dumped["gate_passed"] = ev["gate_passed"]
            dumped["monthly_run_rate_usd"] = ev["cost_estimate"]["monthly_run_rate_usd"]
            return dumped

    def record_deployment(
        self,
        *,
        template: AgentDeploymentTemplate,
        initial_score: float,
        approver_principal: str = "platform-governance-lead",
        trace_id: str = "",
    ) -> dict[str, Any]:
        prof = load_tenant_profile()
        with self._lock:
            template.components = normalize_template_components(template.components)
            template.updated_at = _utc_now_iso()
            template.updated_display = _display_timestamp_now()
            self._agents[template.template_id] = copy.deepcopy(template)

            ev = evaluate_template_against_rubric(template, self._rubric, profile=prof)
            costs = calculate_template_component_costs(template, months_active=1.0, profile=prof)
            dep_id = f"DEP-2026-{1000 + len(self._deployments) + 1}"
            remediated = bool(template.applied_remediations) or (
                ev["overall_score"] > initial_score + 0.05
            )
            record = {
                "deployment_id": dep_id,
                "deployed_at": _utc_now_iso(),
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
