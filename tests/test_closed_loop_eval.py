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

"""Unit tests for the 6-Stage Closed-Loop Optimizer and 8-Capability Coexistence Suite."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from evals.run_beyond_scape_proofs import calculate_guardrail_tco, run_all_beyond_scape_proofs
from evals.run_closed_loop_eval import execute_closed_loop_flywheel

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.asyncio
async def test_closed_loop_flywheel_executes_6_stages_blocks_v1_and_promotes_v2_blueprint() -> None:
    report = await execute_closed_loop_flywheel(live_cloud=False, reset_to_v1_first=True)
    assert report["status"] == "PROMOTED_V2"
    assert report["flywheel_stages_count"] == 6
    assert len(report["stages"]) == 6
    assert len(report["few_shot_exemplars"]) >= 2
    assert report["elapsed_seconds"] < 120.0

    v1 = report["v1_baseline"]
    assert v1["behavior_score"] == 58.0
    assert v1["gate_verdict"] == "BLOCKED"
    assert len(v1["failures"]) >= 2

    v2 = report["v2_candidate"]
    assert v2["behavior_score"] >= 90.0
    assert v2["gate_verdict"] == "PASSED"
    assert v2["cases_passed"] == v2["cases_total"] == 8

    pointer = json.loads(
        (REPO_ROOT / "config" / "prompts" / "active_version.json").read_text(encoding="utf-8")
    )
    assert pointer["active_version"] == "v2"
    assert pointer["behavior_score"] >= 90.0

    bp = report["promotion"]["enterprise_golden_blueprint"]
    assert bp["blueprint_id"] == "bp-governance-synthesizer-v2"
    assert "aws_bedrock_otlp" in bp["a_la_carte_trace_sources"]


@pytest.mark.asyncio
async def test_platform_8_capability_suite_and_ensemble_tco_math() -> None:
    tco = calculate_guardrail_tco(daily_turns=10_000_000, tokens_per_turn=1000)
    assert tco["azure_content_safety_annual_usd"] == 3_650_000.0
    assert tco["aws_bedrock_guardrails_annual_usd"] == 1_095_000.0
    assert tco["google_model_armor_annual_usd"] == 365_000.0
    assert tco["ensemble_tier0_hybrid_annual_usd"] == 584_000.0
    assert tco["annual_savings_vs_azure_usd"] == 3_285_000.0
    assert tco["annual_savings_vs_bedrock_usd"] == 730_000.0

    summary = await run_all_beyond_scape_proofs(live_cloud=False)
    assert summary["status"] == "PASS"
    assert summary["passed_count"] == 8
    assert summary["total_count"] == 8

    doc_text = (REPO_ROOT / "docs" / "GOOGLE_AGENT_PLATFORM_BENCHMARK.md").read_text(encoding="utf-8")
    assert "\u2014" not in doc_text
    assert "\u2013" not in doc_text
    assert "Cymbal Agent Governance, Optimization & Deployment Workbench" in doc_text
