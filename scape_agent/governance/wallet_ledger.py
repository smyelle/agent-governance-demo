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

"""Atomic nano-USD Wallet preflight guard & BigQuery cost-per-outcome ledger.

Eliminates post-response budget overshoot (`FLOW Wallet` Valkey/Celery lag) via
atomic Firestore pre-flight reservations and records business-outcome ROI
(`cost_per_resolved_incident_nano_usd`) in BigQuery `scape_governance.wallet_ledger`.
"""

from __future__ import annotations

import datetime
import os
import threading
from typing import Any
import uuid

from google.cloud import bigquery
from google.cloud import firestore

from scape_agent.governance.gcp_auth import get_gcp_credentials
from scape_agent.governance.model_armor_guard import GuardrailVerdict

# Public list-rate illustrative nano-USD constants (1 USD = 1,000,000,000 nano-USD)
GEMINI_INPUT_TOKEN_NANO_USD = 150       # $0.15 / 1M input tokens
GEMINI_OUTPUT_TOKEN_NANO_USD = 600      # $0.60 / 1M output tokens
MODEL_ARMOR_TOKEN_NANO_USD = 100        # $0.10 / 1M tokens
DEFAULT_PREFLIGHT_RESERVATION_NANO_USD = 3_500_000  # $0.0035 conservative max per turn


class WalletBudgetExceededError(PermissionError):
    """HTTP 403 equivalent raised before inference when wallet ceiling is reached."""

    def __init__(self, wallet_id: str, cap_nano_usd: int, projected_nano_usd: int) -> None:
        self.status_code = 403
        self.error_code = "budget_exceeded"
        self.wallet_id = wallet_id
        self.cap_nano_usd = cap_nano_usd
        self.projected_nano_usd = projected_nano_usd
        super().__init__(
            f"HTTP 403 budget_exceeded: Wallet '{wallet_id}' atomic preflight rejected "
            f"(projected={projected_nano_usd} nano-USD > cap={cap_nano_usd} nano-USD)."
        )


class KillSwitchHaltedError(PermissionError):
    """Raised immediately across model, MCP, and A2A paths when agent is PAUSED/DISABLED."""

    def __init__(self, agent_id: str, status: str) -> None:
        self.status_code = 423
        self.agent_id = agent_id
        self.agent_status = status
        super().__init__(
            f"Kill Switch enforced: Agent '{agent_id}' is {status}; all model, MCP, and A2A execution halted."
        )


class AtomicWalletAndGovernanceStore:
    """Manages Firestore kill-switch/wallet state and BigQuery governance tables."""

    def __init__(
        self,
        project_id: str | None = None,
        dataset_id: str | None = None,
        in_memory_only: bool = False,
    ) -> None:
        self.project_id = project_id or os.getenv("GOOGLE_CLOUD_PROJECT", "comcast-scape")
        self.dataset_id = dataset_id or os.getenv("SCAPE_BQ_DATASET", "scape_governance")
        self.in_memory_only = in_memory_only
        self._lock = threading.Lock()
        self._mem_agents: dict[str, dict[str, Any]] = {
            "devx-incident-copilot": {
                "agent_id": "devx-incident-copilot",
                "status": "ACTIVE",
                "aegis_level": "AG3",
                "clara_intake_id": "CLARA-2026-0841",
                "devhub_app_id": "DEVHUB-SCAPE-992",
                "behavior_score": 96.0,
                "active_prompt_version": "v2",
            }
        }
        self._mem_wallets: dict[str, dict[str, Any]] = {
            "wallet-devx-ops": {
                "wallet_id": "wallet-devx-ops",
                "org": "enterprise-devx",
                "account": "incident-ops-sandbox",
                "monthly_cap_nano_usd": 15_000_000_000,
                "spent_nano_usd": 0,
                "reserved_nano_usd": 0,
                "resolved_incidents_count": 0,
                "status": "ACTIVE",
            }
        }
        self._mem_ledger: list[dict[str, Any]] = []
        self._mem_audits: list[dict[str, Any]] = []
        self._fs_client: firestore.Client | None = None
        self._bq_client: bigquery.Client | None = None

    def __getstate__(self) -> dict[str, Any]:
        state = dict(self.__dict__)
        state["_lock"] = None
        state["_fs_client"] = None
        state["_bq_client"] = None
        return state

    def __setstate__(self, state: dict[str, Any]) -> None:
        self.__dict__.update(state)
        self._lock = threading.Lock()
        self._fs_client = None
        self._bq_client = None

    def _fs(self) -> firestore.Client:
        if self._fs_client is None:
            creds, _ = get_gcp_credentials(self.project_id)
            self._fs_client = firestore.Client(
                project=self.project_id,
                database=os.getenv("SCAPE_FIRESTORE_DATABASE", "(default)"),
                credentials=creds,
            )
        return self._fs_client

    def _bq(self) -> bigquery.Client:
        if self._bq_client is None:
            creds, _ = get_gcp_credentials(self.project_id)
            self._bq_client = bigquery.Client(project=self.project_id, credentials=creds)
        return self._bq_client

    def get_agent_state(self, agent_id: str = "devx-incident-copilot") -> dict[str, Any]:
        if self.in_memory_only:
            with self._lock:
                return dict(self._mem_agents.get(agent_id, self._mem_agents["devx-incident-copilot"]))
        try:
            snap = self._fs().collection("scape_agents").document(agent_id).get()
            if snap.exists:
                return snap.to_dict() or {}
        except Exception:
            if os.getenv("GOOGLE_CLOUD_AGENT_ENGINE_ID"):
                self.in_memory_only = True
                return dict(self._mem_agents.get(agent_id, self._mem_agents["devx-incident-copilot"]))
            raise
        return dict(self._mem_agents["devx-incident-copilot"])

    def set_agent_status(
        self,
        agent_id: str,
        status: str,
        extra_fields: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        normalized = status.strip().upper()
        if normalized not in {"ACTIVE", "PAUSED", "DISABLED"}:
            raise ValueError(f"Invalid agent status: {status}")
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        updates: dict[str, Any] = {"status": normalized, "updated_at": now_iso}
        if extra_fields:
            updates.update(extra_fields)
        if self.in_memory_only:
            with self._lock:
                cur = self._mem_agents.setdefault(agent_id, {"agent_id": agent_id})
                cur.update(updates)
                return dict(cur)
        ref = self._fs().collection("scape_agents").document(agent_id)
        ref.set(updates, merge=True)
        return ref.get().to_dict() or updates

    def assert_agent_active(self, agent_id: str = "devx-incident-copilot") -> dict[str, Any]:
        state = self.get_agent_state(agent_id)
        status = str(state.get("status", "ACTIVE")).upper()
        if status != "ACTIVE":
            raise KillSwitchHaltedError(agent_id=agent_id, status=status)
        return state

    def get_wallet_state(self, wallet_id: str = "wallet-devx-ops") -> dict[str, Any]:
        if self.in_memory_only:
            with self._lock:
                return dict(self._mem_wallets.get(wallet_id, self._mem_wallets["wallet-devx-ops"]))
        snap = self._fs().collection("scape_wallets").document(wallet_id).get()
        if snap.exists:
            return snap.to_dict() or {}
        return dict(self._mem_wallets["wallet-devx-ops"])

    def update_wallet_cap(
        self,
        wallet_id: str,
        monthly_cap_nano_usd: int,
        reset_spend: bool = False,
    ) -> dict[str, Any]:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        updates: dict[str, Any] = {
            "monthly_cap_nano_usd": int(monthly_cap_nano_usd),
            "updated_at": now_iso,
        }
        if reset_spend:
            updates["spent_nano_usd"] = 0
            updates["reserved_nano_usd"] = 0
        if self.in_memory_only:
            with self._lock:
                w = self._mem_wallets.setdefault(wallet_id, dict(self._mem_wallets["wallet-devx-ops"]))
                w.update(updates)
                return dict(w)
        ref = self._fs().collection("scape_wallets").document(wallet_id)
        ref.set(updates, merge=True)
        return ref.get().to_dict() or updates

    def reserve_preflight_budget(
        self,
        wallet_id: str = "wallet-devx-ops",
        reserve_nano_usd: int = DEFAULT_PREFLIGHT_RESERVATION_NANO_USD,
    ) -> str:
        reservation_id = f"resv-{uuid.uuid4().hex[:12]}"
        if self.in_memory_only:
            with self._lock:
                w = self._mem_wallets.setdefault(wallet_id, dict(self._mem_wallets["wallet-devx-ops"]))
                cap = int(w.get("monthly_cap_nano_usd", 15_000_000_000))
                spent = int(w.get("spent_nano_usd", 0))
                reserved = int(w.get("reserved_nano_usd", 0))
                projected = spent + reserved + reserve_nano_usd
                if projected > cap:
                    raise WalletBudgetExceededError(wallet_id, cap, projected)
                w["reserved_nano_usd"] = reserved + reserve_nano_usd
                return reservation_id

        db = self._fs()
        doc_ref = db.collection("scape_wallets").document(wallet_id)

        @firestore.transactional
        def _txn_reserve(transaction: firestore.Transaction) -> None:
            snap = doc_ref.get(transaction=transaction)
            data = snap.to_dict() if snap.exists else {"monthly_cap_nano_usd": 15_000_000_000}
            cap = int(data.get("monthly_cap_nano_usd", 15_000_000_000))
            spent = int(data.get("spent_nano_usd", 0))
            reserved = int(data.get("reserved_nano_usd", 0))
            projected = spent + reserved + reserve_nano_usd
            if projected > cap:
                raise WalletBudgetExceededError(wallet_id, cap, projected)
            transaction.set(
                doc_ref,
                {
                    "reserved_nano_usd": reserved + reserve_nano_usd,
                    "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                },
                merge=True,
            )

        _txn_reserve(db.transaction())
        return reservation_id

    def settle_turn_spend(
        self,
        *,
        wallet_id: str = "wallet-devx-ops",
        agent_id: str = "devx-incident-copilot",
        session_id: str,
        trace_id: str,
        scape_mode: str = "google_native",
        model_id: str = "gemini-3.8-flash",
        input_tokens: int,
        output_tokens: int,
        reserved_nano_usd: int = DEFAULT_PREFLIGHT_RESERVATION_NANO_USD,
        outcome: str = "TRIAGE_STEP_COMPLETED",
        incident_id: str = "INC-4092",
        incident_resolved: bool = False,
    ) -> dict[str, Any]:
        model_cost = (
            max(input_tokens, 0) * GEMINI_INPUT_TOKEN_NANO_USD
            + max(output_tokens, 0) * GEMINI_OUTPUT_TOKEN_NANO_USD
        )
        guardrail_cost = max(input_tokens + output_tokens, 1) * MODEL_ARMOR_TOKEN_NANO_USD
        total_cost = model_cost + guardrail_cost
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        if self.in_memory_only:
            with self._lock:
                w = self._mem_wallets.setdefault(wallet_id, dict(self._mem_wallets["wallet-devx-ops"]))
                w["reserved_nano_usd"] = max(0, int(w.get("reserved_nano_usd", 0)) - reserved_nano_usd)
                w["spent_nano_usd"] = int(w.get("spent_nano_usd", 0)) + total_cost
                if incident_resolved:
                    w["resolved_incidents_count"] = int(w.get("resolved_incidents_count", 0)) + 1
                resolved_cnt = max(1, int(w.get("resolved_incidents_count", 0)) or 1)
                cpri = int(w["spent_nano_usd"] // resolved_cnt)
        else:
            db = self._fs()
            doc_ref = db.collection("scape_wallets").document(wallet_id)

            @firestore.transactional
            def _txn_settle(transaction: firestore.Transaction) -> tuple[int, int]:
                snap = doc_ref.get(transaction=transaction)
                data = snap.to_dict() if snap.exists else {}
                new_resv = max(0, int(data.get("reserved_nano_usd", 0)) - reserved_nano_usd)
                new_spent = int(data.get("spent_nano_usd", 0)) + total_cost
                resolved_cnt = int(data.get("resolved_incidents_count", 0)) + (
                    1 if incident_resolved else 0
                )
                transaction.set(
                    doc_ref,
                    {
                        "reserved_nano_usd": new_resv,
                        "spent_nano_usd": new_spent,
                        "resolved_incidents_count": resolved_cnt,
                        "updated_at": now_iso,
                    },
                    merge=True,
                )
                return new_spent, max(1, resolved_cnt)

            spent_total, resolved_denom = _txn_settle(db.transaction())
            cpri = int(spent_total // resolved_denom)

        row = {
            "event_id": f"wlt-{uuid.uuid4().hex[:14]}",
            "created_at": now_iso,
            "org": "enterprise-devx",
            "account": "incident-ops-sandbox",
            "agent_id": agent_id,
            "wallet_id": wallet_id,
            "session_id": session_id,
            "trace_id": trace_id,
            "scape_mode": scape_mode,
            "model_id": model_id,
            "input_tokens": int(input_tokens),
            "output_tokens": int(output_tokens),
            "model_cost_nano_usd": int(model_cost),
            "guardrail_cost_nano_usd": int(guardrail_cost),
            "total_cost_nano_usd": int(total_cost),
            "outcome": outcome,
            "incident_id": incident_id,
            "cost_per_resolved_incident_nano_usd": int(cpri),
        }
        with self._lock:
            self._mem_ledger.append(row)
        if not self.in_memory_only:
            table_id = f"{self.project_id}.{self.dataset_id}.wallet_ledger"
            errors = self._bq().insert_rows_json(table_id, [row])
            if errors:
                raise RuntimeError(f"BigQuery wallet_ledger insert failed: {errors}")
        return row

    def record_guardrail_audit(
        self,
        *,
        trace_id: str,
        session_id: str,
        agent_id: str,
        direction: str,
        verdict: GuardrailVerdict,
    ) -> dict[str, Any]:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        row = {
            "audit_id": f"grd-{uuid.uuid4().hex[:14]}",
            "created_at": now_iso,
            "trace_id": trace_id,
            "session_id": session_id,
            "agent_id": agent_id,
            "direction": direction,
            "template_id": verdict.template_id,
            "filter_match_state": verdict.filter_match_state,
            "invocation_result": verdict.invocation_result,
            "action_taken": verdict.action_taken,
            "pii_masked": bool(verdict.pii_masked),
            "malicious_uri_detected": bool(verdict.malicious_uri_detected),
            "injection_detected": bool(verdict.injection_detected),
            "latency_ms": float(verdict.latency_ms),
            "summary": verdict.summary[:1000],
        }
        with self._lock:
            self._mem_audits.append(row)
        if not self.in_memory_only:
            try:
                table_id = f"{self.project_id}.{self.dataset_id}.guardrail_audit_logs"
                self._bq().insert_rows_json(table_id, [row])
            except Exception:
                pass
        return row

    def recent_ledger_rows(self, limit: int = 20) -> list[dict[str, Any]]:
        if self.in_memory_only:
            with self._lock:
                return list(reversed(self._mem_ledger[-limit:]))
        query = (
            f"SELECT event_id, created_at, agent_id, session_id, trace_id, scape_mode, "
            f"model_id, input_tokens, output_tokens, model_cost_nano_usd, "
            f"guardrail_cost_nano_usd, total_cost_nano_usd, outcome, incident_id, "
            f"cost_per_resolved_incident_nano_usd "
            f"FROM `{self.project_id}.{self.dataset_id}.wallet_ledger` "
            f"ORDER BY created_at DESC LIMIT @row_limit"
        )
        job_config = bigquery.QueryJobConfig(
            query_parameters=[bigquery.ScalarQueryParameter("row_limit", "INT64", int(limit))],
            labels={"datacloud": "antigravity"},
        )
        rows = self._bq().query(query, job_config=job_config).result()
        out = []
        for r in rows:
            item = dict(r.items())
            if hasattr(item.get("created_at"), "isoformat"):
                item["created_at"] = item["created_at"].isoformat()
            out.append(item)
        return out

    def recent_guardrail_audits(self, limit: int = 20) -> list[dict[str, Any]]:
        if self.in_memory_only:
            with self._lock:
                return list(reversed(self._mem_audits[-limit:]))
        query = (
            f"SELECT audit_id, created_at, trace_id, session_id, agent_id, direction, "
            f"template_id, filter_match_state, invocation_result, action_taken, "
            f"pii_masked, malicious_uri_detected, injection_detected, latency_ms, summary "
            f"FROM `{self.project_id}.{self.dataset_id}.guardrail_audit_logs` "
            f"ORDER BY created_at DESC LIMIT @row_limit"
        )
        job_config = bigquery.QueryJobConfig(
            query_parameters=[bigquery.ScalarQueryParameter("row_limit", "INT64", int(limit))],
            labels={"datacloud": "antigravity"},
        )
        rows = self._bq().query(query, job_config=job_config).result()
        out = []
        for r in rows:
            item = dict(r.items())
            if hasattr(item.get("created_at"), "isoformat"):
                item["created_at"] = item["created_at"].isoformat()
            out.append(item)
        return out
