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

"""Configuration loader for Cymbal Core Operations & Release Agent."""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PROFILE_PATH = REPO_ROOT / "config" / "tenant_profile.yaml"
LOCAL_OVERRIDE_PATH = REPO_ROOT / "config" / "tenant_profile.local.yaml"

DEFAULT_SLOT_MOCK_NAMES: dict[str, str] = {
    "agent_identity": "Mocked Corporate SPIFFE + OIDC (ADR-011 OBO)",
    "agent_registry": "Mocked Catalog 360 + ATLAS Intake + Supergraph",
    "agent_gateway": "Mocked Enterprise AI Gateway + A2A Proxy",
    "trace_observability": "Mocked Enterprise OTel & Trace Collector",
    "wallet_kill_switch": "Mocked Enterprise Wallet + Gateway Kill Switch",
    "safety_guardrails": "Mocked 4-5 Model Guardrail Ensemble",
    "agent_runtime_sandbox": "Mocked Managed Container + External MicroVM",
    "session_memory": "Mocked Custom ABAC Session Store",
    "eval_optimizer": "Mocked Static CI YAML Agent Evals",
}

DEFAULT_BUSINESS_UNITS: dict[str, str] = {
    "core_cable": "Core Connectivity & Broadband",
    "media_studio": "Media & Broadcast Studio",
    "intl_sky": "International Broadband (GDPR Strict)",
    "enterprise_shared": "Enterprise Shared Services",
}


class TerminologyMap(BaseModel):
    platform_name: str
    gateway_name: str
    intake_name: str
    cmdb_name: str
    supergraph_name: str = "ServiceAtlas Supergraph"
    runtime_name: str
    risk_framework: str
    registry_name: str
    blueprint_registry_name: str = "Golden Blueprint Registry"
    observability_name: str
    eval_engine_name: str = "Gen AI Eval & Prompt Optimizer"
    paved_path_iac_name: str = "Terraform Paved-Path Blueprints"
    runbook_name: str
    wallet_name: str
    guardrail_policy_name: str
    high_risk_tier: str = "AG3"
    low_risk_tier: str = "AG1"
    mock_stack_short: str = "Mocked Enterprise Stack"
    mock_template_title: str = "Standard Template 1: Mocked Enterprise Components"
    gcp_template_title: str = "Standard Template 2: GCP Agent Platform Services"
    coexistence_template_title: str = "4-Tier A-La-Carte Coexistence Blueprint"
    best_practices_name: str = "Enterprise Platform Best Practices Rubric"
    slot_mock_names: dict[str, str] = Field(
        default_factory=lambda: dict(DEFAULT_SLOT_MOCK_NAMES)
    )
    business_units: dict[str, str] = Field(
        default_factory=lambda: dict(DEFAULT_BUSINESS_UNITS)
    )


class GovernanceDefaults(BaseModel):
    agent_id: str
    intake_record_id: str
    cmdb_app_id: str
    wallet_id: str
    monthly_cap_nano_usd: int
    hybrid_gateway_placeholder_url: str
    hybrid_otlp_placeholder_url: str


class ThemeConfig(BaseModel):
    accent_primary: str = "#0284c7"
    accent_secondary: str = "#0f766e"
    badge_text: str = "Google Agent Platform | ADK 2.0"


class TenantProfile(BaseModel):
    profile_key: str
    organization_display_name: str
    agent_title: str
    steward_console_title: str
    terminology: TerminologyMap
    governance_defaults: GovernanceDefaults
    theme: ThemeConfig


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, val in override.items():
        if isinstance(val, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], val)
        else:
            merged[key] = copy.deepcopy(val)
    return merged


def load_raw_tenant_config(config_path: Path | None = None) -> dict[str, Any]:
    target = config_path or DEFAULT_PROFILE_PATH
    raw = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    if config_path is None:
        if LOCAL_OVERRIDE_PATH.is_file():
            local_raw = (
                yaml.safe_load(LOCAL_OVERRIDE_PATH.read_text(encoding="utf-8")) or {}
            )
            raw = _deep_merge(raw, local_raw)
        else:
            env_override_yaml = os.getenv("CYMBAL_TENANT_OVERRIDE_YAML", "").strip()
            if env_override_yaml:
                env_raw = yaml.safe_load(env_override_yaml) or {}
                if isinstance(env_raw, dict):
                    raw = _deep_merge(raw, env_raw)
    return raw


def load_tenant_profile(
    profile_override: str | None = None,
    config_path: Path | None = None,
) -> TenantProfile:
    raw = load_raw_tenant_config(config_path=config_path)
    profiles = raw.get("profiles", {})
    selected_key = (
        profile_override
        or os.getenv("CYMBAL_TENANT_PROFILE")
        or raw.get("active_profile")
        or "cymbal_core"
    )
    if selected_key not in profiles:
        raise KeyError(
            f"Unknown tenant profile '{selected_key}'. Available: {sorted(profiles.keys())}"
        )
    entry = dict(profiles[selected_key])
    entry["profile_key"] = selected_key
    return TenantProfile.model_validate(entry)


def list_available_profiles(config_path: Path | None = None) -> list[str]:
    raw = load_raw_tenant_config(config_path=config_path)
    return list((raw.get("profiles") or {}).keys())
