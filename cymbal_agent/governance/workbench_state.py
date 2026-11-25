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

"""3-Persona Agent Governance, Rubric, Remediation & FinOps State Engine.

Backs:
- Persona 1 (End User / Agent Builder): Standard Templates (Mocked Enterprise Stack,
  GCP Agent Platform Services, 4-Tier Coexistence), 9-Slot Custom Composer, Safe
  JSON/YAML Manifest Upload & Export, Best-Practices Rubric Evaluation, Per-Item
  Remediation Accept / Manual Override / Exception, and Governed Deployment.
- Persona 2 (Agent Governance Operations): Live Rubric Studio, Standard Template &
  Component Configurator, and Fleet Operational Metrics across all deployments.
- Persona 3 (Executive Management / FinOps): Per-Deployment Cost Attribution and
  Aggregate 9-Component Historical Cost Rollups anchored to benchmark list rates.
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
    "enterprise_mock",
    "gcp_native",
    "coexistence_bridge",
    "unconfigured",
]

TemplateOrigin = Literal[
    "standard_enterprise_mock",
    "standard_gcp_native",
    "custom_composed",
    "uploaded_manifest",
]

MAX_TEMPLATE_UPLOAD_BYTES = 512 * 1024  # 512 KB strict server-side limit
SAFE_SLUG_RE = re.compile(r"[^a-zA-Z0-9_-]+")


class SlotSelectionConfig(BaseModel):
    slot_id: str = Field(..., min_length=2, max_length=64)
    provider: ProviderChoice = "coexistence_bridge"
    enabled: bool = True
    parameters: dict[str, Any] = Field(default_factory=dict)


class AgentDeploymentTemplate(BaseModel):
    template_id: str = Field(..., min_length=3, max_length=80)
    name: str = Field(..., min_length=3, max_length=140)
    description: str = Field(default="", max_length=600)
    template_kind: Literal["standard", "custom", "sample_upload"] = "custom"
    origin: TemplateOrigin = "custom_composed"
    agent_name: str = Field(default="customer-support-specialist", min_length=2, max_length=80)
    app_id: str = Field(default="APP-GOV-1001", min_length=3, max_length=64)
    intake_id: str = Field(default="INT-2026-1001", max_length=64)
    business_unit: Literal[
        "core_cable", "media_studio", "intl_sky", "enterprise_shared"
    ] = "core_cable"
    risk_tier: Literal["AG1", "AG2", "AG3", "AG4"] = "AG2"
    onboarding_path: Literal["Path A: Adapter", "Path B: SDK Migration", "Path C: Greenfield"] = (
        "Path C: Greenfield"
    )
    runtime_cloud: Literal["gcp", "aws", "azure", "hybrid_multicloud"] = "gcp"
    estimated_monthly_turns_millions: float = Field(default=3.0, ge=0.1, le=100.0)
    static_secrets_in_env: list[str] = Field(default_factory=list)
    destructive_mcp_tools_exposed: bool = False
    uap_cel_per_tool_enforced: bool = True
    sdp_pii_mode: Literal["DEIDENTIFY_INLINE", "BLOCK_ON_MATCH", "INSPECT_ONLY", "NONE"] = (
        "DEIDENTIFY_INLINE"
    )
    prompt_version: str = Field(default="v2", max_length=40)
    behavior_score: float = Field(default=96.4, ge=0.0, le=100.0)
    system_instruction: str = Field(
        default=(
            "You are a governed enterprise specialist agent. Enforce policy boundaries, "
            "never echo raw PII, respect active governance freeze windows, and handle "
            "upstream 503 tool degradations gracefully with bounded retries."
        ),
        max_length=8000,
    )
    components: dict[str, SlotSelectionConfig] = Field(default_factory=dict)
    applied_remediations: list[str] = Field(default_factory=list)
    exception_overrides: dict[str, str] = Field(default_factory=dict)
    updated_at: str = ""


class RubricRule(BaseModel):
    rule_id: str = Field(..., min_length=3, max_length=40)
    slot_id: str = Field(..., min_length=2, max_length=64)
    tier: Literal["Tier 1", "Tier 2", "Tier 3 & 4"] = "Tier 1"
    title: str = Field(..., min_length=4, max_length=160)
    description: str = Field(..., min_length=6, max_length=500)
    mandatory: bool = True
    weight_points: int = Field(default=10, ge=1, le=40)
    require_coexistence_or_mock_for_tier1: bool = False
    min_behavior_score: float | None = Field(default=None, ge=0.0, le=100.0)
    remediation_provider: ProviderChoice = "coexistence_bridge"
    remediation_summary: str = Field(default="", max_length=400)
    enabled: bool = True


class RubricConfig(BaseModel):
    rubric_id: str = "enterprise-governance-rubric-v2"
    name: str = "Enterprise Agent Deployment Rubric"
    passing_score_threshold: float = Field(default=85.0, ge=50.0, le=100.0)
    enforce_tier1_coexistence_hooks: bool = True
    updated_by: str = "governance-ops-lead"
    updated_at: str = ""
    rules: list[RubricRule] = Field(default_factory=list)


# Unit pricing & metadata per slot (illustrative list-rate benchmark model; 1,000 tok/turn)
# Notice Slot 6 matches GOOGLE_AGENT_PLATFORM_BENCHMARK.md exactly:
# - enterprise_mock: $1,000 / 1M turns ($365,000/yr at 1M turns/day)
# - gcp_native:      $100 / 1M turns   ($36,500/yr at 1M turns/day -- $0.10/1M tokens)
# - coexistence:     $160 / 1M turns   ($58,400/yr at 1M turns/day -- 100% prefilter + 20% voter)
SLOT_CATALOG_SPECS: list[dict[str, Any]] = [
    {
        "slot_id": "agent_identity",
        "step": 1,
        "tier": "Tier 1",
        "tier_label": "Tier 1: Mandatory Foundation",
        "capability_name": "Identity, SPIFFE & OBO Access",
        "gcp_name": "GCP Agent Identity (SPIFFE SVID + WIF)",
        "coexistence_name": "SPIFFE AGENT_IDENTITY + OIDC WIF (ADR-011 azp)",
        "api_surface": "agentidentity.googleapis.com + sts.googleapis.com (WIF)",
        "consolidates": "Keycard, Custom OBO Sidecars, HashiCorp Vault",
        "pricing": {
            "enterprise_mock": {"base_monthly_usd": 140.0, "per_1m_turns_usd": 22.0, "onboarding_usd": 180.0},
            "gcp_native": {"base_monthly_usd": 45.0, "per_1m_turns_usd": 6.0, "onboarding_usd": 60.0},
            "coexistence_bridge": {"base_monthly_usd": 65.0, "per_1m_turns_usd": 8.0, "onboarding_usd": 75.0},
            "unconfigured": {"base_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
        },
    },
    {
        "slot_id": "agent_registry",
        "step": 2,
        "tier": "Tier 1",
        "tier_label": "Tier 1: Mandatory Foundation",
        "capability_name": "Catalog, Intake & Inventory Graph",
        "gcp_name": "GCP Agent & Tool Registry",
        "coexistence_name": "Dual-Sync Corporate Catalog + Supergraph + GCP Registry",
        "api_surface": "Enterprise Catalog Hook + agentregistry.googleapis.com",
        "consolidates": "Disconnected Multi-Catalog Sync Scripts",
        "pricing": {
            "enterprise_mock": {"base_monthly_usd": 110.0, "per_1m_turns_usd": 10.0, "onboarding_usd": 220.0},
            "gcp_native": {"base_monthly_usd": 40.0, "per_1m_turns_usd": 4.0, "onboarding_usd": 55.0},
            "coexistence_bridge": {"base_monthly_usd": 70.0, "per_1m_turns_usd": 6.0, "onboarding_usd": 90.0},
            "unconfigured": {"base_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
        },
    },
    {
        "slot_id": "agent_gateway",
        "step": 3,
        "tier": "Tier 1",
        "tier_label": "Tier 1: Mandatory Foundation",
        "capability_name": "AI, MCP & A2A Gateway",
        "gcp_name": "GCP Agent Gateway + ACT (/26 PSC-I) + UAP CEL",
        "coexistence_name": "Enterprise AI Gateway Proxy + Inline Per-Tool UAP CEL",
        "api_surface": "networkservices.googleapis.com/agentGateways + UAP Policy V2",
        "consolidates": "Agentgateway, Runlayer, Arcade, Hush",
        "pricing": {
            "enterprise_mock": {"base_monthly_usd": 230.0, "per_1m_turns_usd": 58.0, "onboarding_usd": 210.0},
            "gcp_native": {"base_monthly_usd": 95.0, "per_1m_turns_usd": 24.0, "onboarding_usd": 80.0},
            "coexistence_bridge": {"base_monthly_usd": 135.0, "per_1m_turns_usd": 32.0, "onboarding_usd": 95.0},
            "unconfigured": {"base_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
        },
    },
    {
        "slot_id": "trace_observability",
        "step": 4,
        "tier": "Tier 1",
        "tier_label": "Tier 1: Mandatory Foundation",
        "capability_name": "Observability & OpenTelemetry Tracing",
        "gcp_name": "Cloud Trace + Cloud Logging (W3C Traceparent)",
        "coexistence_name": "Dual-Export W3C Cloud Trace + OTLP v1 resourceSpans",
        "api_surface": "OTLP v1 resourceSpans + cloudtrace.googleapis.com",
        "consolidates": "Custom Trace Joiners, Fragmented Collector Glue",
        "pricing": {
            "enterprise_mock": {"base_monthly_usd": 165.0, "per_1m_turns_usd": 48.0, "onboarding_usd": 140.0},
            "gcp_native": {"base_monthly_usd": 60.0, "per_1m_turns_usd": 19.0, "onboarding_usd": 50.0},
            "coexistence_bridge": {"base_monthly_usd": 95.0, "per_1m_turns_usd": 28.0, "onboarding_usd": 65.0},
            "unconfigured": {"base_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
        },
    },
    {
        "slot_id": "wallet_kill_switch",
        "step": 5,
        "tier": "Tier 1",
        "tier_label": "Tier 1: Mandatory Foundation",
        "capability_name": "Cost Wallet & Emergency Kill Switch",
        "gcp_name": "Firestore Atomic Nano-USD Wallet + BigQuery Ledger",
        "coexistence_name": "Unified 423 Kill Switch + Atomic 403 Budget Preflight",
        "api_surface": "firestore.googleapis.com + bigquery.googleapis.com",
        "consolidates": "Revenium, Ascerta (Pay-i), Faros",
        "pricing": {
            "enterprise_mock": {"base_monthly_usd": 150.0, "per_1m_turns_usd": 30.0, "onboarding_usd": 130.0},
            "gcp_native": {"base_monthly_usd": 50.0, "per_1m_turns_usd": 11.0, "onboarding_usd": 45.0},
            "coexistence_bridge": {"base_monthly_usd": 75.0, "per_1m_turns_usd": 15.0, "onboarding_usd": 60.0},
            "unconfigured": {"base_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
        },
    },
    {
        "slot_id": "safety_guardrails",
        "step": 6,
        "tier": "Tier 2",
        "tier_label": "Tier 2: Enterprise Control & Runtime",
        "capability_name": "Safety, Prompt-Injection & PII Guardrails",
        "gcp_name": "Dynamic Model Armor Router + Inline Cloud SDP ($0.10/1M tok)",
        "coexistence_name": "Tier-0 Model Armor + Cloud SDP Pre-Filter + 20% Ensemble",
        "api_surface": "modelarmor.us-central1.rep.googleapis.com + dlp.googleapis.com",
        "consolidates": "Straiker.ai, Multi-Cloud Static Template Sprawl",
        "pricing": {
            "enterprise_mock": {"base_monthly_usd": 180.0, "per_1m_turns_usd": 1000.0, "onboarding_usd": 260.0},
            "gcp_native": {"base_monthly_usd": 40.0, "per_1m_turns_usd": 100.0, "onboarding_usd": 70.0},
            "coexistence_bridge": {"base_monthly_usd": 65.0, "per_1m_turns_usd": 160.0, "onboarding_usd": 85.0},
            "unconfigured": {"base_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
        },
    },
    {
        "slot_id": "agent_runtime_sandbox",
        "step": 7,
        "tier": "Tier 2",
        "tier_label": "Tier 2: Enterprise Control & Runtime",
        "capability_name": "Agent Runtime, Orchestration & Code Sandbox",
        "gcp_name": "Vertex AI Agent Runtime (ADK 2.0) + Native gVisor Sandbox",
        "coexistence_name": "ADK 2.0 + Native gVisor + Terraform Paved-Path Module",
        "api_surface": "aiplatform.googleapis.com/ReasoningEngine + infra/terraform",
        "consolidates": "E2B MicroVMs, Custom HITL Checkpoint State Glue",
        "pricing": {
            "enterprise_mock": {"base_monthly_usd": 310.0, "per_1m_turns_usd": 410.0, "onboarding_usd": 340.0},
            "gcp_native": {"base_monthly_usd": 125.0, "per_1m_turns_usd": 285.0, "onboarding_usd": 95.0},
            "coexistence_bridge": {"base_monthly_usd": 140.0, "per_1m_turns_usd": 295.0, "onboarding_usd": 110.0},
            "unconfigured": {"base_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
        },
    },
    {
        "slot_id": "session_memory",
        "step": 8,
        "tier": "Tier 2",
        "tier_label": "Tier 2: Enterprise Control & Runtime",
        "capability_name": "Session & Longitudinal Audit Memory",
        "gcp_name": "Vertex AI Memory Bank (Strict JWT Principal Isolation)",
        "coexistence_name": "Vertex AI Memory Bank + Corporate Governance Tagging",
        "api_surface": "aiplatform.googleapis.com/agentEngines.memories",
        "consolidates": "Mem0, Memori, Custom ABAC Memory Wrappers",
        "pricing": {
            "enterprise_mock": {"base_monthly_usd": 175.0, "per_1m_turns_usd": 52.0, "onboarding_usd": 160.0},
            "gcp_native": {"base_monthly_usd": 65.0, "per_1m_turns_usd": 18.0, "onboarding_usd": 55.0},
            "coexistence_bridge": {"base_monthly_usd": 80.0, "per_1m_turns_usd": 22.0, "onboarding_usd": 65.0},
            "unconfigured": {"base_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
        },
    },
    {
        "slot_id": "eval_optimizer",
        "step": 9,
        "tier": "Tier 3 & 4",
        "tier_label": "Tier 3 & 4: Quality, Eval Optimization & Models",
        "capability_name": "Closed-Loop Evaluation, Optimizer & LTA Model",
        "gcp_name": "Gen AI Eval Service + 6-Stage Optimizer (gemini-3.8-flash)",
        "coexistence_name": "Cross-Cloud OTLP -> evals.evaluate() -> Catalog Blueprint Commit",
        "api_surface": "agentplatform.Client.evals + gemini-3.8-flash (12-mo LTA)",
        "consolidates": "Veris Simulation, LangSmith, Manual Prompt Tuning",
        "pricing": {
            "enterprise_mock": {"base_monthly_usd": 290.0, "per_1m_turns_usd": 95.0, "onboarding_usd": 380.0},
            "gcp_native": {"base_monthly_usd": 85.0, "per_1m_turns_usd": 38.0, "onboarding_usd": 90.0},
            "coexistence_bridge": {"base_monthly_usd": 95.0, "per_1m_turns_usd": 42.0, "onboarding_usd": 105.0},
            "unconfigured": {"base_monthly_usd": 0.0, "per_1m_turns_usd": 0.0, "onboarding_usd": 0.0},
        },
    },
]

SLOT_SPEC_BY_ID: dict[str, dict[str, Any]] = {s["slot_id"]: s for s in SLOT_CATALOG_SPECS}
ORDERED_SLOT_IDS: list[str] = [s["slot_id"] for s in SLOT_CATALOG_SPECS]


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _default_slot_map(provider: ProviderChoice) -> dict[str, SlotSelectionConfig]:
    out: dict[str, SlotSelectionConfig] = {}
    for sid in ORDERED_SLOT_IDS:
        params: dict[str, Any] = {}
        if sid == "safety_guardrails":
            params = {
                "sdp_pii_mode": "DEIDENTIFY_INLINE",
                "malicious_uri_filter": True,
                "ensemble_role": (
                    "tier0_prefilter"
                    if provider in {"gcp_native", "coexistence_bridge"}
                    else "standalone_ensemble"
                ),
            }
        elif sid == "agent_gateway":
            params = {
                "uap_cel_per_tool": provider in {"gcp_native", "coexistence_bridge"},
                "a2a_protocol_enabled": True,
            }
        elif sid == "wallet_kill_switch":
            params = {"monthly_cap_usd": 2500.0, "kill_switch_scope": "model_mcp_a2a"}
        elif sid == "eval_optimizer":
            params = {
                "eval_mode": (
                    "closed_loop_6_stage"
                    if provider in {"gcp_native", "coexistence_bridge"}
                    else "static_ci_yaml"
                ),
                "model_id": "gemini-3.8-flash",
            }
        out[sid] = SlotSelectionConfig(
            slot_id=sid,
            provider=provider,
            enabled=provider != "unconfigured",
            parameters=params,
        )
    return out


def build_localized_slot_catalog(profile: TenantProfile | None = None) -> list[dict[str, Any]]:
    prof = profile or load_tenant_profile()
    mock_names = prof.terminology.slot_mock_names
    catalog: list[dict[str, Any]] = []
    for spec in SLOT_CATALOG_SPECS:
        sid = spec["slot_id"]
        mock_label = mock_names.get(sid, f"Mocked {spec['capability_name']}")
        item = copy.deepcopy(spec)
        item["mock_name"] = mock_label
        item["provider_labels"] = {
            "enterprise_mock": mock_label,
            "gcp_native": spec["gcp_name"],
            "coexistence_bridge": spec["coexistence_name"],
            "unconfigured": "Unconfigured / Missing Hook",
        }
        catalog.append(item)
    return catalog


def _build_default_rubric(profile: TenantProfile) -> RubricConfig:
    terms = profile.terminology
    now = _utc_now_iso()
    return RubricConfig(
        rubric_id="scape-aligned-rubric-v2",
        name=terms.best_practices_name,
        passing_score_threshold=85.0,
        enforce_tier1_coexistence_hooks=True,
        updated_by="gov-ops-architect",
        updated_at=now,
        rules=[
            RubricRule(
                rule_id="RUB-01",
                slot_id="agent_identity",
                tier="Tier 1",
                title="Zero Static Secrets & Workload Identity / OBO (ADR-011)",
                description=(
                    "Container environment must contain zero static API keys and bind SPIFFE "
                    "workload identity or corporate OIDC azp correlation."
                ),
                mandatory=True,
                weight_points=12,
                require_coexistence_or_mock_for_tier1=False,
                remediation_provider="coexistence_bridge",
                remediation_summary=(
                    "Strip static env keys and attach SPIFFE AGENT_IDENTITY + OIDC WIF (ADR-011 azp)."
                ),
            ),
            RubricRule(
                rule_id="RUB-02",
                slot_id="agent_registry",
                tier="Tier 1",
                title=f"Approved {terms.intake_name}, {terms.cmdb_name} & {terms.registry_name} Sync",
                description=(
                    "Every agent must declare an approved AI Intake ID, CMDB/Supergraph App ID, "
                    "and synchronize metadata with the corporate registry."
                ),
                mandatory=True,
                weight_points=12,
                require_coexistence_or_mock_for_tier1=True,
                remediation_provider="coexistence_bridge",
                remediation_summary=(
                    f"Enroll intake & App ID and enable Dual-Sync Coexistence Bridge to {terms.registry_name}."
                ),
            ),
            RubricRule(
                rule_id="RUB-03",
                slot_id="agent_gateway",
                tier="Tier 1",
                title=f"Governed Proxy Routing via {terms.gateway_name} & A2A Compliance",
                description=(
                    "All LLM inference, MCP tool calls, and A2A peer invocations must route "
                    "through the governed gateway substrate with zero direct public egress."
                ),
                mandatory=True,
                weight_points=12,
                require_coexistence_or_mock_for_tier1=True,
                remediation_provider="coexistence_bridge",
                remediation_summary=(
                    f"Configure Terraform Paved-Path outbound proxy through {terms.gateway_name}."
                ),
            ),
            RubricRule(
                rule_id="RUB-04",
                slot_id="agent_gateway",
                tier="Tier 2",
                title="Fine-Grained Per-Tool Authorization (UAP Policy V2 CEL)",
                description=(
                    "Agents accessing MCP tool pools with mutating/destructive capabilities must "
                    "enforce per-tool readOnlyHint vs destructiveHint CEL policies."
                ),
                mandatory=True,
                weight_points=10,
                remediation_provider="coexistence_bridge",
                remediation_summary=(
                    "Enable inline UAP Policy V2 CEL rules blocking destructive MCP tools (403)."
                ),
            ),
            RubricRule(
                rule_id="RUB-05",
                slot_id="trace_observability",
                tier="Tier 1",
                title=f"Standardized OpenTelemetry Export to {terms.observability_name}",
                description=(
                    "Agents must emit W3C traceparent + OpenTelemetry gen_ai.* spans for all "
                    "reasoning, guardrail, and MCP tool steps."
                ),
                mandatory=True,
                weight_points=10,
                require_coexistence_or_mock_for_tier1=True,
                remediation_provider="coexistence_bridge",
                remediation_summary=(
                    f"Enable W3C + OTLP resourceSpans dual-export to {terms.observability_name}."
                ),
            ),
            RubricRule(
                rule_id="RUB-06",
                slot_id="wallet_kill_switch",
                tier="Tier 1",
                title=f"{terms.wallet_name} Quota & Unified Kill-Switch Enforcement",
                description=(
                    "Agents must enforce pre-inference spend caps (403) and honor centralized "
                    "ACTIVE/PAUSED/DISABLED kill switches across model, MCP, and A2A paths."
                ),
                mandatory=True,
                weight_points=12,
                remediation_provider="coexistence_bridge",
                remediation_summary=(
                    "Bind Atomic Nano-USD Wallet preflight and unified 423 kill-switch hook."
                ),
            ),
            RubricRule(
                rule_id="RUB-07",
                slot_id="safety_guardrails",
                tier="Tier 2",
                title="Dynamic Multi-BU Guardrail Policy & Inline PII Redaction",
                description=(
                    "Must enforce prompt-injection, malicious URI, and BU-appropriate PII controls "
                    "(DEIDENTIFY_INLINE or BLOCK_ON_MATCH) without static template sprawl."
                ),
                mandatory=True,
                weight_points=12,
                remediation_provider="coexistence_bridge",
                remediation_summary=(
                    "Attach Dynamic Per-Request Model Armor Router ($0.10/1M tok) + Inline Cloud SDP."
                ),
            ),
            RubricRule(
                rule_id="RUB-08",
                slot_id="agent_runtime_sandbox",
                tier="Tier 2",
                title="Isolated Code Execution Sandbox (gVisor) & Paved-Path IaC",
                description=(
                    "Code-executing or high-agency workflows should run inside isolated gVisor "
                    "sandboxes provisioned via standardized Terraform Paved-Path blueprints."
                ),
                mandatory=False,
                weight_points=6,
                remediation_provider="coexistence_bridge",
                remediation_summary=(
                    "Upgrade runtime slot to ADK 2.0 + Native gVisor Sandbox + Terraform Paved Path."
                ),
            ),
            RubricRule(
                rule_id="RUB-09",
                slot_id="session_memory",
                tier="Tier 2",
                title="JWT Principal-Isolated Session & Longitudinal Memory",
                description=(
                    "Stateful session and audit memory should enforce strict cryptographic JWT "
                    "subject isolation with zero cross-tenant leakage."
                ),
                mandatory=False,
                weight_points=6,
                remediation_provider="gcp_native",
                remediation_summary=(
                    "Bind Vertex AI Memory Bank with verified JWT user_id scoping."
                ),
            ),
            RubricRule(
                rule_id="RUB-10",
                slot_id="eval_optimizer",
                tier="Tier 3 & 4",
                title="Closed-Loop Behavioral Evaluation Gate (Score >= 85.0)",
                description=(
                    "Agent system prompt and tool trajectories must pass automated rubric grading, "
                    "adversarial prompt-injection checks, and 503 fault simulations (>= 85.0)."
                ),
                mandatory=True,
                weight_points=8,
                min_behavior_score=85.0,
                remediation_provider="coexistence_bridge",
                remediation_summary=(
                    "Run 6-Stage Closed-Loop Eval & Prompt Optimizer (gemini-3.8-flash v2 + few-shots)."
                ),
            ),
        ],
    )


def _build_default_templates(profile: TenantProfile) -> list[AgentDeploymentTemplate]:
    terms = profile.terminology
    defs = profile.governance_defaults
    now = _utc_now_iso()

    # 1. Standard Template 1: All Mocked Enterprise / SCAPE Components
    tpl_mock = AgentDeploymentTemplate(
        template_id="tpl-enterprise-mock",
        name=terms.mock_template_title,
        description=(
            f"Uses mocked versions of all {terms.platform_name} platform components across "
            "Tier 1 Foundation, Tier 2 Guardrail Ensemble/Runtime, and Tier 3 Static YAML Evals."
        ),
        template_kind="standard",
        origin="standard_enterprise_mock",
        agent_name="subscriber-billing-concierge",
        app_id=defs.cmdb_app_id,
        intake_id=defs.intake_record_id,
        business_unit="core_cable",
        risk_tier="AG2",
        onboarding_path="Path C: Greenfield",
        runtime_cloud="hybrid_multicloud",
        estimated_monthly_turns_millions=4.5,
        static_secrets_in_env=[],
        destructive_mcp_tools_exposed=False,
        uap_cel_per_tool_enforced=False,
        sdp_pii_mode="DEIDENTIFY_INLINE",
        prompt_version="v2-enterprise",
        behavior_score=88.5,
        components=_default_slot_map("enterprise_mock"),
        updated_at=now,
    )

    # 2. Standard Template 2: All GCP Agent Platform Services
    tpl_gcp = AgentDeploymentTemplate(
        template_id="tpl-gcp-native",
        name=terms.gcp_template_title,
        description=(
            "Turnkey greenfield stack using 100% Google Cloud Agent Platform services: "
            "SPIFFE AGENT_IDENTITY, Agent Gateway + ACT/UAP CEL, Model Armor + Cloud SDP, "
            "Vertex AI Agent Runtime (ADK 2.0 + gVisor), Memory Bank, and Gen AI Eval Optimizer."
        ),
        template_kind="standard",
        origin="standard_gcp_native",
        agent_name="network-telemetry-advisor",
        app_id="APP-GCP-2040",
        intake_id=defs.intake_record_id,
        business_unit="enterprise_shared",
        risk_tier="AG2",
        onboarding_path="Path C: Greenfield",
        runtime_cloud="gcp",
        estimated_monthly_turns_millions=5.0,
        static_secrets_in_env=[],
        destructive_mcp_tools_exposed=False,
        uap_cel_per_tool_enforced=True,
        sdp_pii_mode="DEIDENTIFY_INLINE",
        prompt_version="v2-golden-blueprint",
        behavior_score=96.4,
        components=_default_slot_map("gcp_native"),
        updated_at=now,
    )

    # 3. Standard Coexistence Blueprint (convenient preset for Custom Composer too)
    coex_map = _default_slot_map("coexistence_bridge")
    coex_map["session_memory"] = SlotSelectionConfig(
        slot_id="session_memory",
        provider="gcp_native",
        enabled=True,
        parameters={"jwt_principal_isolation": True},
    )
    tpl_coex = AgentDeploymentTemplate(
        template_id="tpl-coexistence-blueprint",
        name=terms.coexistence_template_title,
        description=(
            f"Recommended 4-Tier A-La-Carte Coexistence pattern: honors mandatory Tier-1 "
            f"{terms.platform_name} foundations via dual-sync bridges while plugging in ADK 2.0 "
            "gVisor, Dynamic Model Armor ($0.10/1M), and 6-Stage Closed-Loop Optimization."
        ),
        template_kind="standard",
        origin="custom_composed",
        agent_name="omnichannel-dispatch-coordinator",
        app_id=defs.cmdb_app_id,
        intake_id=defs.intake_record_id,
        business_unit="core_cable",
        risk_tier="AG3",
        onboarding_path="Path C: Greenfield",
        runtime_cloud="hybrid_multicloud",
        estimated_monthly_turns_millions=6.0,
        static_secrets_in_env=[],
        destructive_mcp_tools_exposed=False,
        uap_cel_per_tool_enforced=True,
        sdp_pii_mode="DEIDENTIFY_INLINE",
        prompt_version="v2-golden-blueprint",
        behavior_score=97.2,
        components=coex_map,
        updated_at=now,
    )

    return [tpl_mock, tpl_gcp, tpl_coex]


def _build_sample_upload_templates(profile: TenantProfile) -> list[AgentDeploymentTemplate]:
    defs = profile.governance_defaults
    now = _utc_now_iso()

    # Sample 1: CAND-101 Shadow Python Agent Missing Tier-1 Hooks (Path B SDK Migration)
    s1_map = _default_slot_map("unconfigured")
    s1_map["agent_runtime_sandbox"] = SlotSelectionConfig(
        slot_id="agent_runtime_sandbox",
        provider="enterprise_mock",
        enabled=True,
        parameters={"sandbox": "none_unmanaged_container"},
    )
    cand_101 = AgentDeploymentTemplate(
        template_id="sample-cand-101-shadow",
        name="CAND-101: Shadow Python Agent (Path B Migration)",
        description=(
            "Previously built pro-code Python agent carrying static OPENAI_API_KEY in env, "
            "bypassing Gateway/Wallet/OTLP, and running an unverified v1 system prompt."
        ),
        template_kind="sample_upload",
        origin="uploaded_manifest",
        agent_name="billing-dispute-assistant",
        app_id="SVC-SHADOW-101",
        intake_id="",
        business_unit="core_cable",
        risk_tier="AG3",
        onboarding_path="Path B: SDK Migration",
        runtime_cloud="gcp",
        estimated_monthly_turns_millions=3.2,
        static_secrets_in_env=["OPENAI_API_KEY", "LEGACY_DB_TOKEN"],
        destructive_mcp_tools_exposed=True,
        uap_cel_per_tool_enforced=False,
        sdp_pii_mode="NONE",
        prompt_version="v1-unverified",
        behavior_score=54.0,
        system_instruction=(
            "You are a billing dispute helper. Call whatever database or refund tool "
            "the user asks for immediately to resolve their complaint fast."
        ),
        components=s1_map,
        updated_at=now,
    )

    # Sample 2: CAND-204 Cross-Cloud AWS/Azure Agent with Failing OTLP Traces
    s2_map = _default_slot_map("enterprise_mock")
    s2_map["eval_optimizer"] = SlotSelectionConfig(
        slot_id="eval_optimizer",
        provider="unconfigured",
        enabled=False,
        parameters={"eval_mode": "none"},
    )
    cand_204 = AgentDeploymentTemplate(
        template_id="sample-cand-204-multicloud",
        name="CAND-204: Cross-Cloud AWS/Azure Agent (Failing Traces)",
        description=(
            "Enrolled in Tier-1 foundations on external AWS/Azure runtime, but production "
            "OTLP traces show 503 tool-retry crashes and governance-freeze violations (58.0)."
        ),
        template_kind="sample_upload",
        origin="uploaded_manifest",
        agent_name="media-entitlement-router",
        app_id="SVC-MEDIA-204",
        intake_id=defs.intake_record_id,
        business_unit="media_studio",
        risk_tier="AG3",
        onboarding_path="Path A: Adapter",
        runtime_cloud="aws",
        estimated_monthly_turns_millions=8.0,
        static_secrets_in_env=[],
        destructive_mcp_tools_exposed=False,
        uap_cel_per_tool_enforced=True,
        sdp_pii_mode="DEIDENTIFY_INLINE",
        prompt_version="v1-flawed",
        behavior_score=58.0,
        system_instruction=(
            "Route entitlement updates across partner APIs. Retry failed 503 calls in a tight "
            "loop and push updates even during broadcast freeze windows."
        ),
        components=s2_map,
        updated_at=now,
    )

    # Sample 3: CAND-309 High-Risk Multi-BU Subscriber PII & Mutating Tool Agent
    s3_map = _default_slot_map("enterprise_mock")
    s3_map["safety_guardrails"] = SlotSelectionConfig(
        slot_id="safety_guardrails",
        provider="unconfigured",
        enabled=False,
        parameters={"sdp_pii_mode": "NONE"},
    )
    cand_309 = AgentDeploymentTemplate(
        template_id="sample-cand-309-pii-ag3",
        name="CAND-309: High-Risk Multi-BU PII & Mutating Tool Agent",
        description=(
            "Ingests raw subscriber logs with SSNs and CPE MAC addresses across regional BUs "
            "while exposing an un-gated device factory-reset MCP tool."
        ),
        template_kind="sample_upload",
        origin="uploaded_manifest",
        agent_name="cpe-fleet-provisioning-agent",
        app_id="SVC-CPE-309",
        intake_id=defs.intake_record_id,
        business_unit="intl_sky",
        risk_tier="AG3",
        onboarding_path="Path B: SDK Migration",
        runtime_cloud="hybrid_multicloud",
        estimated_monthly_turns_millions=6.5,
        static_secrets_in_env=[],
        destructive_mcp_tools_exposed=True,
        uap_cel_per_tool_enforced=False,
        sdp_pii_mode="NONE",
        prompt_version="v2-enterprise",
        behavior_score=89.0,
        components=s3_map,
        updated_at=now,
    )

    return [cand_101, cand_204, cand_309]


def calculate_template_component_costs(
    template: AgentDeploymentTemplate,
    months_active: float = 1.0,
    profile: TenantProfile | None = None,
) -> dict[str, Any]:
    """Calculates transparent per-slot and total costs using published benchmark rates."""
    prof = profile or load_tenant_profile()
    slot_catalog = {s["slot_id"]: s for s in build_localized_slot_catalog(prof)}
    turns_m = max(0.1, float(template.estimated_monthly_turns_millions))
    months = max(0.25, float(months_active))

    per_slot: list[dict[str, Any]] = []
    monthly_total = 0.0
    onboarding_total = 0.0
    historical_total = 0.0

    # Also compute pure-mock baseline to highlight platform consolidation savings
    mock_baseline_monthly = 0.0

    for sid in ORDERED_SLOT_IDS:
        spec = slot_catalog[sid]
        sel = template.components.get(sid) or SlotSelectionConfig(
            slot_id=sid, provider="unconfigured", enabled=False
        )
        prov: ProviderChoice = sel.provider if sel.enabled else "unconfigured"
        rates = spec["pricing"].get(prov, spec["pricing"]["unconfigured"])
        mock_rates = spec["pricing"]["enterprise_mock"]

        slot_monthly = round(
            float(rates["base_monthly_usd"]) + float(rates["per_1m_turns_usd"]) * turns_m,
            2,
        )
        slot_onboarding = round(float(rates["onboarding_usd"]), 2)
        slot_historical = round(slot_monthly * months + slot_onboarding, 2)
        slot_mock_monthly = round(
            float(mock_rates["base_monthly_usd"])
            + float(mock_rates["per_1m_turns_usd"]) * turns_m,
            2,
        )

        monthly_total += slot_monthly
        onboarding_total += slot_onboarding
        historical_total += slot_historical
        mock_baseline_monthly += slot_mock_monthly

        per_slot.append(
            {
                "slot_id": sid,
                "step": spec["step"],
                "tier": spec["tier"],
                "capability_name": spec["capability_name"],
                "provider": prov,
                "provider_display_name": spec["provider_labels"][prov],
                "monthly_cost_usd": slot_monthly,
                "onboarding_cost_usd": slot_onboarding,
                "historical_cumulative_usd": slot_historical,
                "mock_baseline_monthly_usd": slot_mock_monthly,
                "monthly_savings_vs_mock_usd": round(slot_mock_monthly - slot_monthly, 2),
                "consolidates": spec["consolidates"],
            }
        )

    return {
        "estimated_monthly_turns_millions": turns_m,
        "months_active": months,
        "onboarding_eval_cost_usd": round(onboarding_total, 2),
        "monthly_run_rate_usd": round(monthly_total, 2),
        "historical_cumulative_usd": round(historical_total, 2),
        "mock_baseline_monthly_usd": round(mock_baseline_monthly, 2),
        "monthly_savings_vs_mock_usd": round(mock_baseline_monthly - monthly_total, 2),
        "component_costs": per_slot,
    }


def generate_terraform_paved_path_preview(
    template: AgentDeploymentTemplate,
    profile: TenantProfile | None = None,
) -> str:
    prof = profile or load_tenant_profile()
    defs = prof.governance_defaults
    mod_slug = SAFE_SLUG_RE.sub("_", template.agent_name.lower()).strip("_") or "governed_agent"
    gw_slot = template.components.get("agent_gateway")
    otlp_slot = template.components.get("trace_observability")
    guard_slot = template.components.get("safety_guardrails")
    gw_mode = gw_slot.provider if gw_slot else "coexistence_bridge"
    otlp_mode = otlp_slot.provider if otlp_slot else "coexistence_bridge"
    guard_mode = guard_slot.provider if guard_slot else "coexistence_bridge"

    return (
        f'module "{mod_slug}_paved_path" {{\n'
        f'  source                  = "./infra/terraform"\n'
        f'  agent_name              = "{template.agent_name}"\n'
        f'  app_id                  = "{template.app_id}"\n'
        f'  ai_intake_id            = "{template.intake_id or defs.intake_record_id}"\n'
        f'  business_unit           = "{template.business_unit}"\n'
        f'  risk_tier               = "{template.risk_tier}"\n'
        f'  gateway_routing_mode    = "{gw_mode}"\n'
        f'  enterprise_gateway_url  = "{defs.hybrid_gateway_placeholder_url}"\n'
        f'  otlp_export_mode        = "{otlp_mode}"\n'
        f'  otlp_collector_endpoint = "{defs.hybrid_otlp_placeholder_url}"\n'
        f'  guardrail_router_mode   = "{guard_mode}"\n'
        f'  sdp_pii_mode            = "{template.sdp_pii_mode}"\n'
        f'  uap_cel_per_tool_authz  = {str(template.uap_cel_per_tool_enforced).lower()}\n'
        f'  spiffe_entra_wif_adr011 = true\n'
        f'  lta_gemini_model        = "gemini-3.8-flash"\n'
        f"}}\n"
    )


def generate_dynamic_guardrail_policy_preview(template: AgentDeploymentTemplate) -> dict[str, Any]:
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
        "ensemble_role": "tier0_prefilter",
        "resolved_floor_pool": (
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
    """Evaluates a fully qualified agent deployment template against the active Rubric."""
    prof = profile or load_tenant_profile()
    slot_catalog = {s["slot_id"]: s for s in build_localized_slot_catalog(prof)}
    active_rules = [r for r in rubric.rules if r.enabled]
    total_weight = sum(r.weight_points for r in active_rules) or 100

    earned_weight = 0.0
    tier_totals: dict[str, list[float]] = {
        "Tier 1": [0.0, 0.0],
        "Tier 2": [0.0, 0.0],
        "Tier 3 & 4": [0.0, 0.0],
    }

    rule_results: list[dict[str, Any]] = []
    recommendations: list[dict[str, Any]] = []
    mandatory_Blocking_count = 0

    current_costs = calculate_template_component_costs(template, months_active=1.0, profile=prof)

    for rule in active_rules:
        sid = rule.slot_id
        spec = slot_catalog.get(sid, SLOT_CATALOG_SPECS[0])
        sel = template.components.get(sid) or SlotSelectionConfig(
            slot_id=sid, provider="unconfigured", enabled=False
        )
        prov: ProviderChoice = sel.provider if sel.enabled else "unconfigured"

        passed = True
        gap_reasons: list[str] = []

        if prov == "unconfigured":
            passed = False
            gap_reasons.append(f"Component slot '{spec['capability_name']}' is unconfigured.")

        if (
            passed
            and rubric.enforce_tier1_coexistence_hooks
            and rule.require_coexistence_or_mock_for_tier1
            and prov == "gcp_native"
        ):
            passed = False
            gap_reasons.append(
                f"Slot uses standalone GCP service without {prof.terminology.platform_name} "
                "Tier-1 dual-sync coexistence hook."
            )

        if rule.rule_id == "RUB-01" and template.static_secrets_in_env:
            passed = False
            gap_reasons.append(
                "Static credentials detected in container env: "
                + ", ".join(template.static_secrets_in_env)
            )

        if rule.rule_id == "RUB-02" and not template.intake_id.strip():
            passed = False
            gap_reasons.append(f"Missing approved {prof.terminology.intake_name} identifier.")

        if (
            rule.rule_id == "RUB-04"
            and template.destructive_mcp_tools_exposed
            and not template.uap_cel_per_tool_enforced
        ):
            passed = False
            gap_reasons.append(
                "Destructive MCP tools are exposed in pool without inline UAP Policy V2 CEL gate."
            )

        if rule.rule_id == "RUB-07":
            if template.sdp_pii_mode == "NONE":
                passed = False
                gap_reasons.append(
                    "Inline PII protection (sdp_pii_mode) is disabled for subscriber/enterprise payloads."
                )
            elif prov == "enterprise_mock" and template.risk_tier in {"AG3", "AG4"}:
                passed = False
                gap_reasons.append(
                    "High-risk AG3/AG4 multi-BU agent uses static guardrail templates instead of Dynamic Per-Request Policy Router."
                )

        if rule.rule_id in {"RUB-08", "RUB-09"} and prov == "enterprise_mock":
            passed = False
            gap_reasons.append(
                f"Slot uses legacy/external specialist wrapper ({spec['provider_labels']['enterprise_mock']}) "
                f"instead of consolidated {spec['gcp_name']}."
            )

        if rule.min_behavior_score is not None and template.behavior_score < rule.min_behavior_score:
            passed = False
            gap_reasons.append(
                f"Behavioral evaluation score {template.behavior_score:.1f}/100 is below "
                f"minimum gate {rule.min_behavior_score:.1f}/100 ({template.prompt_version})."
            )

        exception_note = template.exception_overrides.get(rule.rule_id, "")
        status_label: Literal["PASSED", "EXCEPTION_APPROVED", "FAILED"] = "PASSED"
        if passed:
            earned_weight += rule.weight_points
            tier_totals.setdefault(rule.tier, [0.0, 0.0])[0] += rule.weight_points
        elif exception_note:
            status_label = "EXCEPTION_APPROVED"
            # Exception satisfies gate block and awards 50% advisory credit
            earned_weight += rule.weight_points * 0.5
            tier_totals.setdefault(rule.tier, [0.0, 0.0])[0] += rule.weight_points * 0.5
        else:
            status_label = "FAILED"
            if rule.mandatory:
                mandatory_Blocking_count += 1

        tier_totals.setdefault(rule.tier, [0.0, 0.0])[1] += rule.weight_points
        score_uplift = round((rule.weight_points / total_weight) * 100.0, 1)

        rule_results.append(
            {
                "rule_id": rule.rule_id,
                "slot_id": sid,
                "capability_name": spec["capability_name"],
                "tier": rule.tier,
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
            target_prov = rule.remediation_provider
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
            if rule.rule_id == "RUB-04":
                hypothetical.uap_cel_per_tool_enforced = True
            if rule.rule_id == "RUB-07":
                hypothetical.sdp_pii_mode = (
                    "BLOCK_ON_MATCH"
                    if hypothetical.business_unit == "intl_sky"
                    else "DEIDENTIFY_INLINE"
                )
            if rule.rule_id == "RUB-10":
                hypothetical.prompt_version = "v2-golden-blueprint"
                hypothetical.behavior_score = 96.4

            patched_costs = calculate_template_component_costs(
                hypothetical, months_active=1.0, profile=prof
            )
            cost_delta = round(
                patched_costs["monthly_run_rate_usd"] - current_costs["monthly_run_rate_usd"],
                2,
            )

            before_preview = {
                "slot_id": sid,
                "provider": prov,
                "static_secrets_in_env": template.static_secrets_in_env if rule.rule_id == "RUB-01" else None,
                "intake_id": template.intake_id if rule.rule_id == "RUB-02" else None,
                "uap_cel_per_tool_enforced": (
                    template.uap_cel_per_tool_enforced if rule.rule_id == "RUB-04" else None
                ),
                "sdp_pii_mode": template.sdp_pii_mode if rule.rule_id == "RUB-07" else None,
                "prompt_version": template.prompt_version if rule.rule_id == "RUB-10" else None,
                "behavior_score": template.behavior_score if rule.rule_id == "RUB-10" else None,
            }
            after_preview = {
                "slot_id": sid,
                "provider": target_prov,
                "provider_label": spec["provider_labels"][target_prov],
                "static_secrets_in_env": [] if rule.rule_id == "RUB-01" else None,
                "intake_id": hypothetical.intake_id if rule.rule_id == "RUB-02" else None,
                "uap_cel_per_tool_enforced": True if rule.rule_id == "RUB-04" else None,
                "dynamic_guardrail_policy": (
                    generate_dynamic_guardrail_policy_preview(hypothetical)
                    if rule.rule_id == "RUB-07"
                    else None
                ),
                "prompt_version": "v2-golden-blueprint" if rule.rule_id == "RUB-10" else None,
                "behavior_score": 96.4 if rule.rule_id == "RUB-10" else None,
            }

            recommendations.append(
                {
                    "rec_id": f"REC-{rule.rule_id}",
                    "rule_id": rule.rule_id,
                    "slot_id": sid,
                    "capability_name": spec["capability_name"],
                    "tier": rule.tier,
                    "severity": "MANDATORY_GATE" if rule.mandatory else "BEST_PRACTICE",
                    "title": rule.title,
                    "finding_detail": " ".join(gap_reasons),
                    "recommendation_summary": rule.remediation_summary,
                    "recommended_provider": target_prov,
                    "recommended_provider_label": spec["provider_labels"][target_prov],
                    "score_uplift_pts": score_uplift,
                    "monthly_cost_delta_usd": cost_delta,
                    "supports_closed_loop_eval": rule.rule_id == "RUB-10",
                    "before_config": {k: v for k, v in before_preview.items() if v is not None},
                    "after_config": {k: v for k, v in after_preview.items() if v is not None},
                    "terraform_hcl_preview": generate_terraform_paved_path_preview(
                        hypothetical, profile=prof
                    ),
                }
            )

    overall_score = round((earned_weight / total_weight) * 100.0, 1)
    gate_passed = (
        overall_score >= rubric.passing_score_threshold and mandatory_Blocking_count == 0
    )

    tier_summary = {}
    for t_name, (earned, possible) in tier_totals.items():
        tier_summary[t_name] = {
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
        "mandatory_failures_count": mandatory_Blocking_count,
        "recommendations_count": len(recommendations),
        "tier_scores": tier_summary,
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
    custom_provider: ProviderChoice | None = None,
    custom_parameters: dict[str, Any] | None = None,
    exception_reason: str | None = None,
    profile: TenantProfile | None = None,
) -> AgentDeploymentTemplate:
    """Mutates a working copy of an AgentDeploymentTemplate per user decision in Journey 5."""
    prof = profile or load_tenant_profile()
    updated = copy.deepcopy(template)
    rule_map = {r.rule_id: r for r in rubric.rules}
    rule = rule_map.get(rule_id)
    if rule is None:
        raise ValueError(f"Unknown rubric rule_id: {rule_id}")

    sid = rule.slot_id
    if action == "exception":
        note = (exception_reason or "Approved operational governance exception.").strip()
        updated.exception_overrides[rule_id] = note[:300]
        updated.updated_at = _utc_now_iso()
        return updated

    # Clear any prior exception when accepting or customizing
    updated.exception_overrides.pop(rule_id, None)
    target_provider: ProviderChoice = (
        custom_provider if (action == "customize" and custom_provider) else rule.remediation_provider
    )
    existing_slot = updated.components.get(sid) or SlotSelectionConfig(slot_id=sid)
    merged_params = dict(existing_slot.parameters)
    if custom_parameters:
        merged_params.update(custom_parameters)
    merged_params["last_remediation_action"] = action
    updated.components[sid] = SlotSelectionConfig(
        slot_id=sid,
        provider=target_provider,
        enabled=target_provider != "unconfigured",
        parameters=merged_params,
    )

    if action == "accept":
        if rule_id == "RUB-01":
            updated.static_secrets_in_env = []
        elif rule_id == "RUB-02" and not updated.intake_id.strip():
            updated.intake_id = prof.governance_defaults.intake_record_id
        elif rule_id == "RUB-04":
            updated.uap_cel_per_tool_enforced = True
        elif rule_id == "RUB-07":
            updated.sdp_pii_mode = (
                "BLOCK_ON_MATCH" if updated.business_unit == "intl_sky" else "DEIDENTIFY_INLINE"
            )
        elif rule_id == "RUB-10":
            updated.prompt_version = "v2-golden-blueprint"
            updated.behavior_score = max(updated.behavior_score, 96.4)
            updated.system_instruction = (
                "You are a governed enterprise specialist agent (Golden Blueprint v2). "
                "1) Never echo raw SSN, MAC, or account PII. "
                "2) Respect active governance freeze windows unless a verified VP ticket is supplied. "
                "3) On MCP 503 errors, degrade gracefully using cached telemetry without retry storms."
            )
    elif action == "customize" and custom_parameters:
        if "sdp_pii_mode" in custom_parameters:
            val = str(custom_parameters["sdp_pii_mode"])
            if val in {"DEIDENTIFY_INLINE", "BLOCK_ON_MATCH", "INSPECT_ONLY", "NONE"}:
                updated.sdp_pii_mode = val  # type: ignore[assignment]
        if "uap_cel_per_tool_enforced" in custom_parameters:
            updated.uap_cel_per_tool_enforced = bool(custom_parameters["uap_cel_per_tool_enforced"])
        if "intake_id" in custom_parameters:
            updated.intake_id = str(custom_parameters["intake_id"])[:64]
        if "clear_static_secrets" in custom_parameters and custom_parameters["clear_static_secrets"]:
            updated.static_secrets_in_env = []
        if "system_instruction" in custom_parameters:
            updated.system_instruction = str(custom_parameters["system_instruction"])[:8000]
            updated.prompt_version = "v2-custom-edited"
            updated.behavior_score = max(updated.behavior_score, 91.0)

    if rule_id not in updated.applied_remediations:
        updated.applied_remediations.append(rule_id)
    updated.updated_at = _utc_now_iso()
    return updated


def parse_uploaded_template_manifest(
    raw_content: str,
    filename: str = "uploaded_template.yaml",
    profile: TenantProfile | None = None,
) -> AgentDeploymentTemplate:
    """Safely parses and normalizes a user-uploaded JSON or YAML deployment template."""
    prof = profile or load_tenant_profile()
    encoded = raw_content.encode("utf-8")
    if len(encoded) > MAX_TEMPLATE_UPLOAD_BYTES:
        raise ValueError(
            f"Uploaded manifest exceeds maximum allowed size ({MAX_TEMPLATE_UPLOAD_BYTES} bytes)."
        )
    safe_name = Path(filename).name.lower()
    if not safe_name.endswith((".json", ".yaml", ".yml")):
        raise ValueError("Only .json, .yaml, and .yml deployment template files are permitted.")

    try:
        if safe_name.endswith(".json"):
            parsed = json.loads(raw_content)
        else:
            parsed = yaml.safe_load(raw_content)
    except Exception as exc:
        raise ValueError(f"Malformed template manifest syntax: {exc}") from exc

    if not isinstance(parsed, dict):
        raise ValueError("Template manifest root must be a JSON/YAML object mapping.")

    # Support shorthand or full component maps safely
    raw_components = parsed.get("components") or {}
    norm_components: dict[str, SlotSelectionConfig] = {}
    for sid in ORDERED_SLOT_IDS:
        entry = raw_components.get(sid) if isinstance(raw_components, dict) else None
        if isinstance(entry, str) and entry in {
            "enterprise_mock",
            "gcp_native",
            "coexistence_bridge",
            "unconfigured",
        }:
            norm_components[sid] = SlotSelectionConfig(
                slot_id=sid,
                provider=entry,  # type: ignore[arg-type]
                enabled=entry != "unconfigured",
            )
        elif isinstance(entry, dict):
            prov = str(entry.get("provider", "unconfigured"))
            if prov not in {
                "enterprise_mock",
                "gcp_native",
                "coexistence_bridge",
                "unconfigured",
            }:
                prov = "unconfigured"
            norm_components[sid] = SlotSelectionConfig(
                slot_id=sid,
                provider=prov,  # type: ignore[arg-type]
                enabled=bool(entry.get("enabled", prov != "unconfigured")),
                parameters=dict(entry.get("parameters") or {}),
            )
        else:
            norm_components[sid] = SlotSelectionConfig(
                slot_id=sid, provider="unconfigured", enabled=False
            )

    slug_base = SAFE_SLUG_RE.sub("-", Path(safe_name).stem).strip("-") or "uploaded"
    tpl_payload: dict[str, Any] = {
        "template_id": str(parsed.get("template_id") or f"upl-{slug_base}-{uuid.uuid4().hex[:6]}"),
        "name": str(parsed.get("name") or f"Uploaded: {parsed.get('agent_name', slug_base)}"),
        "description": str(
            parsed.get("description")
            or f"Uploaded deployment manifest ({safe_name}) inspected against {prof.terminology.platform_name}."
        ),
        "template_kind": "custom",
        "origin": "uploaded_manifest",
        "agent_name": str(parsed.get("agent_name") or slug_base)[:80],
        "app_id": str(parsed.get("app_id") or "APP-UPLOADED-01")[:64],
        "intake_id": str(parsed.get("intake_id") or "")[:64],
        "business_unit": parsed.get("business_unit") or "core_cable",
        "risk_tier": parsed.get("risk_tier") or "AG2",
        "onboarding_path": parsed.get("onboarding_path") or "Path B: SDK Migration",
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
        "prompt_version": str(parsed.get("prompt_version") or "v1-uploaded")[:40],
        "behavior_score": float(parsed.get("behavior_score", 62.0)),
        "system_instruction": str(
            parsed.get("system_instruction")
            or "Uploaded agent instruction pending governance evaluation."
        )[:8000],
        "components": norm_components,
        "updated_at": _utc_now_iso(),
    }
    return AgentDeploymentTemplate.model_validate(tpl_payload)


def _seed_historical_deployments(profile: TenantProfile) -> list[dict[str, Any]]:
    """Builds 12 realistic historical enterprise deployments across BUs and templates."""
    defs = profile.governance_defaults

    def _slot_mix(
        tier1: ProviderChoice,
        guard: ProviderChoice,
        runtime: ProviderChoice,
        mem: ProviderChoice,
        eval_p: ProviderChoice,
    ) -> dict[str, SlotSelectionConfig]:
        m = _default_slot_map(tier1)
        m["safety_guardrails"] = SlotSelectionConfig(
            slot_id="safety_guardrails", provider=guard, enabled=True
        )
        m["agent_runtime_sandbox"] = SlotSelectionConfig(
            slot_id="agent_runtime_sandbox", provider=runtime, enabled=True
        )
        m["session_memory"] = SlotSelectionConfig(
            slot_id="session_memory", provider=mem, enabled=True
        )
        m["eval_optimizer"] = SlotSelectionConfig(
            slot_id="eval_optimizer", provider=eval_p, enabled=True
        )
        return m

    specs: list[dict[str, Any]] = [
        {
            "deployment_id": "DEP-2026-0901",
            "deployed_at": "2026-06-12T14:20:00Z",
            "agent_name": "broadband-outage-triage-bot",
            "app_id": "APP-BB-104",
            "business_unit": "core_cable",
            "risk_tier": "AG3",
            "template_id": "tpl-coexistence-blueprint",
            "origin": "custom_composed",
            "months_active": 5.5,
            "turns_m": 9.2,
            "initial_score": 61.0,
            "final_score": 96.8,
            "remediated": True,
            "remediations_count": 4,
            "mix": _slot_mix(
                "coexistence_bridge",
                "coexistence_bridge",
                "gcp_native",
                "gcp_native",
                "coexistence_bridge",
            ),
        },
        {
            "deployment_id": "DEP-2026-0902",
            "deployed_at": "2026-06-28T16:05:00Z",
            "agent_name": "subscriber-billing-concierge",
            "app_id": "APP-BILL-208",
            "business_unit": "core_cable",
            "risk_tier": "AG2",
            "template_id": "tpl-enterprise-mock",
            "origin": "standard_enterprise_mock",
            "months_active": 5.0,
            "turns_m": 6.0,
            "initial_score": 86.0,
            "final_score": 88.5,
            "remediated": False,
            "remediations_count": 0,
            "mix": _default_slot_map("enterprise_mock"),
        },
        {
            "deployment_id": "DEP-2026-0903",
            "deployed_at": "2026-07-14T11:40:00Z",
            "agent_name": "ad-sales-proposal-synthesizer",
            "app_id": "APP-MEDIA-311",
            "business_unit": "media_studio",
            "risk_tier": "AG2",
            "template_id": "tpl-gcp-native",
            "origin": "standard_gcp_native",
            "months_active": 4.5,
            "turns_m": 4.2,
            "initial_score": 76.0,
            "final_score": 98.0,
            "remediated": True,
            "remediations_count": 2,
            "mix": _slot_mix(
                "coexistence_bridge",
                "gcp_native",
                "gcp_native",
                "gcp_native",
                "gcp_native",
            ),
        },
        {
            "deployment_id": "DEP-2026-0904",
            "deployed_at": "2026-07-29T09:15:00Z",
            "agent_name": "sports-highlight-rights-checker",
            "app_id": "APP-MEDIA-349",
            "business_unit": "media_studio",
            "risk_tier": "AG1",
            "template_id": "tpl-enterprise-mock",
            "origin": "standard_enterprise_mock",
            "months_active": 4.0,
            "turns_m": 2.8,
            "initial_score": 88.0,
            "final_score": 88.0,
            "remediated": False,
            "remediations_count": 0,
            "mix": _default_slot_map("enterprise_mock"),
        },
        {
            "deployment_id": "DEP-2026-0905",
            "deployed_at": "2026-08-11T17:30:00Z",
            "agent_name": "eu-gdpr-retention-specialist",
            "app_id": "APP-INTL-402",
            "business_unit": "intl_sky",
            "risk_tier": "AG3",
            "template_id": "sample-cand-309-pii-ag3",
            "origin": "uploaded_manifest",
            "months_active": 3.5,
            "turns_m": 5.5,
            "initial_score": 52.0,
            "final_score": 95.4,
            "remediated": True,
            "remediations_count": 5,
            "mix": _slot_mix(
                "coexistence_bridge",
                "coexistence_bridge",
                "coexistence_bridge",
                "gcp_native",
                "coexistence_bridge",
            ),
        },
        {
            "deployment_id": "DEP-2026-0906",
            "deployed_at": "2026-08-24T13:10:00Z",
            "agent_name": "field-technician-dispatch-copilot",
            "app_id": "APP-FIELD-512",
            "business_unit": "core_cable",
            "risk_tier": "AG3",
            "template_id": "tpl-coexistence-blueprint",
            "origin": "custom_composed",
            "months_active": 3.0,
            "turns_m": 7.4,
            "initial_score": 68.0,
            "final_score": 97.2,
            "remediated": True,
            "remediations_count": 3,
            "mix": _slot_mix(
                "coexistence_bridge",
                "coexistence_bridge",
                "gcp_native",
                "gcp_native",
                "coexistence_bridge",
            ),
        },
        {
            "deployment_id": "DEP-2026-0907",
            "deployed_at": "2026-09-08T10:50:00Z",
            "agent_name": "enterprise-it-access-concierge",
            "app_id": "APP-ENT-601",
            "business_unit": "enterprise_shared",
            "risk_tier": "AG2",
            "template_id": "tpl-enterprise-mock",
            "origin": "standard_enterprise_mock",
            "months_active": 2.6,
            "turns_m": 3.5,
            "initial_score": 74.0,
            "final_score": 91.0,
            "remediated": True,
            "remediations_count": 2,
            "mix": _slot_mix(
                "enterprise_mock",
                "coexistence_bridge",
                "enterprise_mock",
                "enterprise_mock",
                "coexistence_bridge",
            ),
        },
        {
            "deployment_id": "DEP-2026-0908",
            "deployed_at": "2026-09-22T15:45:00Z",
            "agent_name": "ott-stream-qoe-diagnostics",
            "app_id": "APP-INTL-455",
            "business_unit": "intl_sky",
            "risk_tier": "AG2",
            "template_id": "tpl-gcp-native",
            "origin": "standard_gcp_native",
            "months_active": 2.2,
            "turns_m": 8.6,
            "initial_score": 80.0,
            "final_score": 96.4,
            "remediated": True,
            "remediations_count": 2,
            "mix": _slot_mix(
                "coexistence_bridge",
                "gcp_native",
                "gcp_native",
                "gcp_native",
                "gcp_native",
            ),
        },
        {
            "deployment_id": "DEP-2026-0909",
            "deployed_at": "2026-10-05T18:00:00Z",
            "agent_name": "legacy- billing-refund-shadow-v1",
            "app_id": "APP-BB-778",
            "business_unit": "core_cable",
            "risk_tier": "AG3",
            "template_id": "sample-cand-101-shadow",
            "origin": "uploaded_manifest",
            "months_active": 1.7,
            "turns_m": 3.1,
            "initial_score": 32.0,
            "final_score": 94.6,
            "remediated": True,
            "remediations_count": 6,
            "mix": _slot_mix(
                "coexistence_bridge",
                "coexistence_bridge",
                "coexistence_bridge",
                "gcp_native",
                "coexistence_bridge",
            ),
        },
        {
            "deployment_id": "DEP-2026-0910",
            "deployed_at": "2026-10-19T12:25:00Z",
            "agent_name": "supply-chain-contract-auditor",
            "app_id": "APP-ENT-688",
            "business_unit": "enterprise_shared",
            "risk_tier": "AG2",
            "template_id": "tpl-gcp-native",
            "origin": "custom_composed",
            "months_active": 1.3,
            "turns_m": 2.2,
            "initial_score": 92.0,
            "final_score": 98.0,
            "remediated": False,
            "remediations_count": 0,
            "mix": _slot_mix(
                "coexistence_bridge",
                "gcp_native",
                "gcp_native",
                "gcp_native",
                "gcp_native",
            ),
        },
        {
            "deployment_id": "DEP-2026-0911",
            "deployed_at": "2026-11-02T14:10:00Z",
            "agent_name": "multicloud-entitlement-sync",
            "app_id": "APP-MEDIA-390",
            "business_unit": "media_studio",
            "risk_tier": "AG3",
            "template_id": "sample-cand-204-multicloud",
            "origin": "uploaded_manifest",
            "months_active": 0.9,
            "turns_m": 7.8,
            "initial_score": 58.0,
            "final_score": 96.4,
            "remediated": True,
            "remediations_count": 3,
            "mix": _slot_mix(
                "enterprise_mock",
                "coexistence_bridge",
                "enterprise_mock",
                "enterprise_mock",
                "coexistence_bridge",
            ),
        },
        {
            "deployment_id": "DEP-2026-0912",
            "deployed_at": "2026-11-15T16:40:00Z",
            "agent_name": "cpe-firmware-rollout-steward",
            "app_id": "APP-BB-812",
            "business_unit": "core_cable",
            "risk_tier": "AG3",
            "template_id": "tpl-coexistence-blueprint",
            "origin": "custom_composed",
            "months_active": 0.5,
            "turns_m": 5.0,
            "initial_score": 70.0,
            "final_score": 97.2,
            "remediated": True,
            "remediations_count": 3,
            "mix": _slot_mix(
                "coexistence_bridge",
                "coexistence_bridge",
                "coexistence_bridge",
                "gcp_native",
                "coexistence_bridge",
            ),
        },
    ]

    records: list[dict[str, Any]] = []
    for item in specs:
        clean_name = item["agent_name"].replace(" ", "")
        tpl = AgentDeploymentTemplate(
            template_id=item["template_id"],
            name=clean_name,
            agent_name=clean_name,
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
                "agent_name": clean_name,
                "app_id": item["app_id"],
                "intake_id": defs.intake_record_id,
                "business_unit": item["business_unit"],
                "business_unit_label": profile.terminology.business_units.get(
                    item["business_unit"], item["business_unit"]
                ),
                "risk_tier": item["risk_tier"],
                "template_id": item["template_id"],
                "origin": item["origin"],
                "status": "DEPLOYED_ACTIVE",
                "approver_principal": "gov-steward-lead",
                "initial_eval_score": item["initial_score"],
                "final_eval_score": item["final_score"],
                "remediated_prior_to_deploy": item["remediated"],
                "remediations_applied_count": item["remediations_count"],
                "months_active": item["months_active"],
                "estimated_monthly_turns_millions": item["turns_m"],
                "onboarding_eval_cost_usd": cost_bd["onboarding_eval_cost_usd"],
                "monthly_run_rate_usd": cost_bd["monthly_run_rate_usd"],
                "historical_cumulative_usd": cost_bd["historical_cumulative_usd"],
                "monthly_savings_vs_mock_usd": cost_bd["monthly_savings_vs_mock_usd"],
                "component_choices": {
                    sid: tpl.components[sid].provider for sid in ORDERED_SLOT_IDS
                },
                "component_costs": cost_bd["component_costs"],
                "trace_id": f"trc-{item['deployment_id'].lower()}-w3c",
            }
        )
    return records


class WorkbenchGovernanceEngine:
    """Thread-safe state & analytics engine for all 3 Personas."""

    def __init__(self, state_dir: Path | None = None) -> None:
        self._lock = threading.Lock()
        env_dir = os.getenv("CYMBAL_RUNTIME_STATE_DIR")
        if state_dir is not None:
            self._state_dir = state_dir
        elif env_dir:
            self._state_dir = Path(env_dir) / "workbench"
        else:
            self._state_dir = Path("/tmp") / "cymbal_workbench_state"
        self._state_file = self._state_dir / "governance_workbench_state.json"

        prof = load_tenant_profile()
        self._rubric: RubricConfig = _build_default_rubric(prof)
        self._templates: dict[str, AgentDeploymentTemplate] = {
            t.template_id: t for t in _build_default_templates(prof)
        }
        self._sample_uploads: dict[str, AgentDeploymentTemplate] = {
            s.template_id: s for s in _build_sample_upload_templates(prof)
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
            if isinstance(raw.get("templates"), list):
                self._templates = {
                    t["template_id"]: AgentDeploymentTemplate.model_validate(t)
                    for t in raw["templates"]
                }
            if isinstance(raw.get("deployments"), list) and raw["deployments"]:
                self._deployments = list(raw["deployments"])
        except Exception:
            pass

    def _persist_locked(self) -> None:
        try:
            self._state_dir.mkdir(parents=True, exist_ok=True)
            payload = {
                "rubric": self._rubric.model_dump(),
                "templates": [t.model_dump() for t in self._templates.values()],
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
            for tid, tpl in self._templates.items():
                localized = copy.deepcopy(tpl)
                if tid == "tpl-enterprise-mock":
                    localized.name = prof.terminology.mock_template_title
                elif tid == "tpl-gcp-native":
                    localized.name = prof.terminology.gcp_template_title
                elif tid == "tpl-coexistence-blueprint":
                    localized.name = prof.terminology.coexistence_template_title
                ev = evaluate_template_against_rubric(localized, rub, profile=prof)
                dumped = localized.model_dump()
                dumped["latest_eval_score"] = ev["overall_score"]
                dumped["gate_passed"] = ev["gate_passed"]
                dumped["monthly_run_rate_usd"] = ev["cost_estimate"]["monthly_run_rate_usd"]
                out.append(dumped)
            return out

    def list_sample_uploads(self) -> list[dict[str, Any]]:
        prof = load_tenant_profile()
        with self._lock:
            rub = copy.deepcopy(self._rubric)
            out: list[dict[str, Any]] = []
            for tpl in self._sample_uploads.values():
                ev = evaluate_template_against_rubric(tpl, rub, profile=prof)
                dumped = tpl.model_dump()
                dumped["latest_eval_score"] = ev["overall_score"]
                dumped["gate_passed"] = ev["gate_passed"]
                dumped["yaml_export"] = yaml.safe_dump(
                    tpl.model_dump(), sort_keys=False, allow_unicode=True
                )
                out.append(dumped)
            return out

    def upsert_template(self, template: AgentDeploymentTemplate) -> dict[str, Any]:
        prof = load_tenant_profile()
        with self._lock:
            template.updated_at = _utc_now_iso()
            # Ensure all 9 slots exist
            for sid in ORDERED_SLOT_IDS:
                if sid not in template.components:
                    template.components[sid] = SlotSelectionConfig(
                        slot_id=sid, provider="coexistence_bridge", enabled=True
                    )
            self._templates[template.template_id] = copy.deepcopy(template)
            self._persist_locked()
            ev = evaluate_template_against_rubric(template, self._rubric, profile=prof)
            dumped = template.model_dump()
            dumped["latest_eval_score"] = ev["overall_score"]
            dumped["gate_passed"] = ev["gate_passed"]
            dumped["monthly_run_rate_usd"] = ev["cost_estimate"]["monthly_run_rate_usd"]
            return dumped

    def record_deployment(
        self,
        *,
        template: AgentDeploymentTemplate,
        initial_score: float,
        approver_principal: str = "gov-steward-lead",
        trace_id: str = "",
    ) -> dict[str, Any]:
        prof = load_tenant_profile()
        with self._lock:
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
                "status": "DEPLOYED_ACTIVE",
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
                "monthly_savings_vs_mock_usd": costs["monthly_savings_vs_mock_usd"],
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
        """Aggregates Persona 2 operational metrics across all deployments."""
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
            "standard_enterprise_mock": 0,
            "standard_gcp_native": 0,
            "custom_composed": 0,
            "uploaded_manifest": 0,
        }
        bu_counts: dict[str, int] = {}
        slot_adoption: list[dict[str, Any]] = []

        for d in deps:
            orig = str(d.get("origin", "custom_composed"))
            origin_counts[orig] = origin_counts.get(orig, 0) + 1
            bu = str(d.get("business_unit", "core_cable"))
            bu_counts[bu] = bu_counts.get(bu, 0) + 1
            d["business_unit_label"] = prof.terminology.business_units.get(bu, bu)

        for spec in slot_catalog:
            sid = spec["slot_id"]
            counts = {
                "enterprise_mock": 0,
                "gcp_native": 0,
                "coexistence_bridge": 0,
                "unconfigured": 0,
            }
            for d in deps:
                ch = (d.get("component_choices") or {}).get(sid, "coexistence_bridge")
                counts[ch] = counts.get(ch, 0) + 1
            slot_adoption.append(
                {
                    "slot_id": sid,
                    "step": spec["step"],
                    "tier": spec["tier"],
                    "capability_name": spec["capability_name"],
                    "provider_labels": spec["provider_labels"],
                    "counts": counts,
                    "gcp_or_coexistence_pct": round(
                        ((counts["gcp_native"] + counts["coexistence_bridge"]) / total) * 100.0,
                        1,
                    ),
                }
            )

        standard_cnt = (
            origin_counts["standard_enterprise_mock"] + origin_counts["standard_gcp_native"]
        )
        return {
            "total_deployments": len(deps),
            "remediated_prior_to_deploy_count": remediated_cnt,
            "remediated_prior_to_deploy_pct": round((remediated_cnt / total) * 100.0, 1),
            "clean_first_pass_count": len(deps) - remediated_cnt,
            "avg_initial_eval_score": avg_initial,
            "avg_final_eval_score": avg_final,
            "avg_score_uplift": round(avg_final - avg_initial, 1),
            "standard_template_count": standard_cnt,
            "custom_or_uploaded_count": len(deps) - standard_cnt,
            "origin_breakdown": origin_counts,
            "business_unit_breakdown": bu_counts,
            "component_adoption": slot_adoption,
            "deployments": deps,
        }

    def build_executive_cost_summary(
        self,
        *,
        business_unit_filter: str = "all",
        origin_filter: str = "all",
    ) -> dict[str, Any]:
        """Aggregates Persona 3 per-deployment and 9-component historical costs."""
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
            sum(float(d.get("monthly_savings_vs_mock_usd", 0.0)) for d in filtered), 2
        )

        slot_agg: dict[str, dict[str, Any]] = {}
        for sid in ORDERED_SLOT_IDS:
            spec = slot_catalog[sid]
            slot_agg[sid] = {
                "slot_id": sid,
                "step": spec["step"],
                "tier": spec["tier"],
                "capability_name": spec["capability_name"],
                "consolidates": spec["consolidates"],
                "provider_labels": spec["provider_labels"],
                "historical_cumulative_usd": 0.0,
                "monthly_run_rate_usd": 0.0,
                "onboarding_cost_usd": 0.0,
                "monthly_savings_vs_mock_usd": 0.0,
                "spend_by_provider_usd": {
                    "enterprise_mock": 0.0,
                    "gcp_native": 0.0,
                    "coexistence_bridge": 0.0,
                },
                "deployments_by_provider": {
                    "enterprise_mock": 0,
                    "gcp_native": 0,
                    "coexistence_bridge": 0,
                },
                "top_deployments": [],
            }

        for d in filtered:
            for comp in d.get("component_costs") or []:
                sid = comp["slot_id"]
                if sid not in slot_agg:
                    continue
                prov = comp.get("provider", "coexistence_bridge")
                hist_c = float(comp.get("historical_cumulative_usd", 0.0))
                mo_c = float(comp.get("monthly_cost_usd", 0.0))
                onb_c = float(comp.get("onboarding_cost_usd", 0.0))
                sav_c = float(comp.get("monthly_savings_vs_mock_usd", 0.0))

                agg = slot_agg[sid]
                agg["historical_cumulative_usd"] = round(
                    agg["historical_cumulative_usd"] + hist_c, 2
                )
                agg["monthly_run_rate_usd"] = round(agg["monthly_run_rate_usd"] + mo_c, 2)
                agg["onboarding_cost_usd"] = round(agg["onboarding_cost_usd"] + onb_c, 2)
                agg["monthly_savings_vs_mock_usd"] = round(
                    agg["monthly_savings_vs_mock_usd"] + sav_c, 2
                )
                if prov in agg["spend_by_provider_usd"]:
                    agg["spend_by_provider_usd"][prov] = round(
                        agg["spend_by_provider_usd"][prov] + hist_c, 2
                    )
                    agg["deployments_by_provider"][prov] += 1
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
            "component_cost_rollup": component_rollup,
            "deployments": filtered,
        }
