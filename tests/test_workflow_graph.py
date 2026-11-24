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

"""Unit & integration tests for the ADK 2.0 Workflow Graph, HITL, A2A, Memory, and BFF."""

from __future__ import annotations

from google.adk.apps.app import App, ResumabilityConfig
from google.adk.code_executors import BuiltInCodeExecutor
from google.adk.runners import InMemoryRunner
from google.adk.workflow import JoinNode
from google.adk.workflow.utils._workflow_hitl_utils import create_request_input_response
from google.genai import types
import httpx
import pytest

from scape_agent.agent import build_scape_workflow, compute_deterministic_anomaly_stats
from scape_agent.governance.model_armor_guard import FailClosedModelArmorGuard
from scape_agent.governance.plugin import ScapeGovernancePlugin
from scape_agent.governance.telemetry_bridge import UnifiedTraceBridge
from scape_agent.governance.wallet_ledger import AtomicWalletAndGovernanceStore
from scape_agent.memory.memory_bank import ScopedMemoryBankClient
from scape_agent.tenant import load_tenant_profile
from web.api import create_bff_app


def _make_offline_app(
    mem: ScopedMemoryBankClient | None = None,
) -> tuple[App, InMemoryRunner, ScopedMemoryBankClient]:
    memory_client = mem or ScopedMemoryBankClient(in_memory_only=True)
    store = AtomicWalletAndGovernanceStore(in_memory_only=True)
    guard = FailClosedModelArmorGuard(live_api_enabled=False)
    tracer = UnifiedTraceBridge(cloud_trace_enabled=False)
    wf = build_scape_workflow(memory_bank=memory_client, use_live_llm=False)
    adk_app = App(
        name="pytest_scape_copilot",
        root_agent=wf,
        resumability_config=ResumabilityConfig(is_resumable=True),
        plugins=[ScapeGovernancePlugin(store=store, guard=guard, tracer=tracer)],
    )
    return adk_app, InMemoryRunner(app=adk_app), memory_client


def test_workflow_graph_structure_uses_join_node_and_builtin_gvisor_executor() -> None:
    live_wf = build_scape_workflow(
        memory_bank=ScopedMemoryBankClient(in_memory_only=True),
        use_live_llm=True,
    )
    assert live_wf.graph is not None
    node_map = {n.name: n for n in live_wf.graph.nodes}

    assert "correlate_incident_signals" in node_map
    assert isinstance(node_map["correlate_incident_signals"], JoinNode)

    assert "gvisor_code_sandbox_agent" in node_map
    gvisor_agent = node_map["gvisor_code_sandbox_agent"]
    assert isinstance(getattr(gvisor_agent, "code_executor", None), BuiltInCodeExecutor)

    z_score, mult = compute_deterministic_anomaly_stats(
        [305, 318, 299, 312, 325, 4610, 4790, 4820, 4755, 4840]
    )
    assert z_score > 100.0
    assert mult > 14.0


@pytest.mark.asyncio
async def test_ag3_incident_fanout_join_hitl_pause_and_approved_a2a_rollback() -> None:
    _, runner, mem = _make_offline_app()
    session = await runner.session_service.create_session(
        app_name="pytest_scape_copilot",
        user_id="sre-alice",
        state={"prompt_version_override": "v2"},
    )

    interrupt_id = None
    async for ev in runner.run_async(
        user_id="sre-alice",
        session_id=session.id,
        new_message=types.Content(
            role="user", parts=[types.Part(text="Investigate INC-4092 on flow-intel-api")]
        ),
    ):
        if ev.long_running_tool_ids:
            interrupt_id = next(iter(ev.long_running_tool_ids))

    assert interrupt_id == "ag3_rollback_1"

    resume_part = create_request_input_response(
        interrupt_id,
        {
            "approved": True,
            "approver_principal": "sre-director-01",
            "reason": "Verified p99 spike and clear change window.",
        },
    )
    async for _ in runner.run_async(
        user_id="sre-alice",
        session_id=session.id,
        new_message=types.Content(role="user", parts=[resume_part]),
    ):
        pass

    final_sess = await runner.session_service.get_session(
        app_name="pytest_scape_copilot", user_id="sre-alice", session_id=session.id
    )
    assert final_sess is not None
    outcome = final_sess.state.get("remediation_outcome") or {}
    assert outcome["status"] == "ROLLED_BACK"
    assert outcome["slo_recovered"] is True
    assert outcome["post_rollback_p99_ms"] == 298.0

    # Verify longitudinal Memory Bank persistence & zero cross-user leak
    alice_memories = mem.retrieve_memories(
        verified_user_id="sre-alice", service_name="flow-intel-api"
    )
    bob_memories = mem.retrieve_memories(
        verified_user_id="sre-bob", service_name="flow-intel-api"
    )
    assert any("INC-4092" in m["fact"] for m in alice_memories)
    assert not any(m["user_id"] == "sre-alice" for m in bob_memories)


@pytest.mark.asyncio
async def test_ag3_hitl_rejection_routes_to_manual_hold() -> None:
    _, runner, _ = _make_offline_app()
    session = await runner.session_service.create_session(
        app_name="pytest_scape_copilot",
        user_id="sre-oncall-01",
        state={"prompt_version_override": "v2"},
    )

    interrupt_id = None
    async for ev in runner.run_async(
        user_id="sre-oncall-01",
        session_id=session.id,
        new_message=types.Content(
            role="user", parts=[types.Part(text="Triage INC-4095 on billing-webhook-router")]
        ),
    ):
        if ev.long_running_tool_ids:
            interrupt_id = next(iter(ev.long_running_tool_ids))

    assert interrupt_id is not None

    hold_part = create_request_input_response(
        interrupt_id,
        {
            "approved": False,
            "approver_principal": "sre-oncall-01",
            "reason": "Holding pending VP Peak Holiday Change-Freeze Exception.",
        },
    )
    async for _ in runner.run_async(
        user_id="sre-oncall-01",
        session_id=session.id,
        new_message=types.Content(role="user", parts=[hold_part]),
    ):
        pass

    final_sess = await runner.session_service.get_session(
        app_name="pytest_scape_copilot", user_id="sre-oncall-01", session_id=session.id
    )
    assert final_sess is not None
    assert final_sess.state["remediation_outcome"]["status"] == "HELD_FOR_MANUAL_EXCEPTION"


@pytest.mark.asyncio
async def test_ag1_low_risk_incident_masks_pii_and_publishes_advisory_without_interrupt() -> None:
    _, runner, _ = _make_offline_app()
    session = await runner.session_service.create_session(
        app_name="pytest_scape_copilot",
        user_id="sre-oncall-01",
        state={"prompt_version_override": "v2"},
    )

    interrupted = False
    async for ev in runner.run_async(
        user_id="sre-oncall-01",
        session_id=session.id,
        new_message=types.Content(
            role="user",
            parts=[
                types.Part(
                    text="Triage INC-4099 on edge-session-ingestor: customer SSN 123-45-6789"
                )
            ],
        ),
    ):
        if ev.long_running_tool_ids:
            interrupted = True

    assert interrupted is False
    final_sess = await runner.session_service.get_session(
        app_name="pytest_scape_copilot", user_id="sre-oncall-01", session_id=session.id
    )
    assert final_sess is not None
    assert final_sess.state["pii_masked_inline"] is True
    assert "123-45-6789" not in final_sess.state["sanitized_operator_prompt"]
    assert final_sess.state["remediation_outcome"]["status"] == "ADVISORY_ONLY"


@pytest.mark.asyncio
async def test_white_label_tenant_swap_and_bff_security_headers() -> None:
    comcast_p = load_tenant_profile("comcast_devx")
    cymbal_p = load_tenant_profile("cymbal_telco")
    assert comcast_p.terminology.platform_name == "SCAPE"
    assert cymbal_p.terminology.platform_name == "Cymbal Mesh"
    assert cymbal_p.terminology.risk_framework == "SENTINEL"

    bff = create_bff_app(offline_mode=True)
    transport = httpx.ASGITransport(app=bff)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8080") as client:
        boot = await client.get("/api/bootstrap")
        assert boot.status_code == 200
        assert "default-src 'self'" in boot.headers["Content-Security-Policy"]
        assert boot.headers["X-Content-Type-Options"] == "nosniff"
        assert boot.headers["X-Frame-Options"] == "DENY"
        assert boot.headers["Cache-Control"] == "no-store"

        # POST without CSRF token must fail 403
        no_csrf = await client.post(
            "/api/config/mode",
            json={"scape_mode": "comcast_hybrid", "tenant_profile": "cymbal_telco"},
        )
        assert no_csrf.status_code == 403

        # POST with valid CSRF token succeeds and swaps white-label profile
        csrf = boot.json()["csrf_token"]
        swapped = await client.post(
            "/api/config/mode",
            headers={"X-CSRF-Token": csrf},
            json={"scape_mode": "comcast_hybrid", "tenant_profile": "cymbal_telco"},
        )
        assert swapped.status_code == 200
        assert swapped.json()["tenant"]["terminology"]["platform_name"] == "Cymbal Mesh"
