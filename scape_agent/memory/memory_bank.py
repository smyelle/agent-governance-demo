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

"""JWT-scoped Vertex AI Memory Bank & longitudinal service memory manager.

Strictly binds every `generate` / `create`, `retrieve`, and `forget` call to the
authenticated session `user_id` (never an LLM-supplied string), providing zero
cross-user leakage alongside longitudinal cross-session recall.
"""

from __future__ import annotations

import datetime
import os
import threading
from typing import Any
import uuid

from google.cloud import firestore
import vertexai

from scape_agent.governance.gcp_auth import get_gcp_credentials


class ScopedMemoryBankClient:
    """Manages cross-session user & service incident memories with strict JWT scoping."""

    def __init__(
        self,
        project_id: str | None = None,
        location: str | None = None,
        reasoning_engine_name: str | None = None,
        in_memory_only: bool = False,
    ) -> None:
        self.project_id = project_id or os.getenv("GOOGLE_CLOUD_PROJECT", "comcast-scape")
        self.location = location or os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1")
        self.reasoning_engine_name = reasoning_engine_name or os.getenv(
            "SCAPE_REASONING_ENGINE_NAME", ""
        )
        self.in_memory_only = in_memory_only
        self._lock = threading.Lock()
        self._mem_records: list[dict[str, Any]] = [
            {
                "memory_id": "mem-seed-4092",
                "user_id": "sre-oncall-01",
                "service_name": "flow-intel-api",
                "incident_id": "INC-3980",
                "fact": (
                    "Prior incident INC-3980 on flow-intel-api showed synchronous Valkey usage:0 "
                    "XADD flushes above 90% memory trigger Bifrost p99 spikes >4,500ms; rolling "
                    "back to the prior stable minor release restored SLO in under 90 seconds."
                ),
                "created_at": "2026-11-18T14:20:00+00:00",
                "backend": "vertex_memory_bank",
            }
        ]
        self._fs_client: firestore.Client | None = None
        self._vx_client: Any = None

    def __getstate__(self) -> dict[str, Any]:
        state = dict(self.__dict__)
        state["_lock"] = None
        state["_fs_client"] = None
        state["_vx_client"] = None
        return state

    def __setstate__(self, state: dict[str, Any]) -> None:
        self.__dict__.update(state)
        self._lock = threading.Lock()
        self._fs_client = None
        self._vx_client = None

    def _fs(self) -> firestore.Client:
        if self._fs_client is None:
            creds, _ = get_gcp_credentials(self.project_id)
            self._fs_client = firestore.Client(
                project=self.project_id,
                database=os.getenv("SCAPE_FIRESTORE_DATABASE", "(default)"),
                credentials=creds,
            )
        return self._fs_client

    def _vx(self) -> Any:
        if self._vx_client is None:
            creds, _ = get_gcp_credentials(self.project_id)
            self._vx_client = vertexai.Client(
                project=self.project_id,
                location=self.location,
                credentials=creds,
            )
        return self._vx_client

    @staticmethod
    def _validate_principal_user_id(verified_user_id: str) -> str:
        clean = (verified_user_id or "").strip()
        if not clean or "/" in clean or ".." in clean:
            raise ValueError("Invalid authenticated principal user_id for Memory Bank scope.")
        return clean

    def retrieve_memories(
        self,
        *,
        verified_user_id: str,
        service_name: str | None = None,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        uid = self._validate_principal_user_id(verified_user_id)
        results: list[dict[str, Any]] = []

        # 1. Include newest in-session / freshly persisted records matching uid first
        with self._lock:
            for rec in reversed(self._mem_records):
                if rec.get("user_id") != uid:
                    continue
                if service_name and rec.get("service_name") not in {service_name, "all", None}:
                    continue
                if not any(existing.get("memory_id") == rec.get("memory_id") for existing in results):
                    results.append(dict(rec))

        # 2. Query Vertex AI Agent Engine Memory Bank when ReasoningEngine is bound
        if not self.in_memory_only and self.reasoning_engine_name:
            try:
                vx_memories = self._vx().agent_engines.memories.retrieve(
                    name=self.reasoning_engine_name,
                    scope={"user_id": uid},
                )
                for item in list(vx_memories)[:limit]:
                    mem_obj = getattr(item, "memory", item)
                    fact_txt = getattr(mem_obj, "fact", None) or str(mem_obj)
                    results.append(
                        {
                            "memory_id": getattr(mem_obj, "name", "vx-memory").split("/")[-1],
                            "user_id": uid,
                            "service_name": service_name or "general",
                            "fact": fact_txt,
                            "backend": "vertex_ai_memory_bank",
                        }
                    )
            except Exception:
                pass

        # 3. Query Firestore strict user_id-scoped longitudinal index
        if not self.in_memory_only:
            try:
                docs = (
                    self._fs()
                    .collection("scape_memories")
                    .where(filter=firestore.FieldFilter("user_id", "==", uid))
                    .limit(limit * 2)
                    .stream()
                )
                for d in docs:
                    rec = d.to_dict() or {}
                    if service_name and rec.get("service_name") not in {service_name, "all", None}:
                        continue
                    if not any(existing.get("memory_id") == rec.get("memory_id") for existing in results):
                        results.append(rec)
            except Exception:
                pass

        return results[:limit]

    def persist_memory(
        self,
        *,
        verified_user_id: str,
        service_name: str,
        fact: str,
        incident_id: str,
    ) -> dict[str, Any]:
        uid = self._validate_principal_user_id(verified_user_id)
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        mem_id = f"mem-{uuid.uuid4().hex[:10]}"
        backend = "vertex_ai_memory_bank_and_firestore"

        if not self.in_memory_only and self.reasoning_engine_name:
            try:
                created = self._vx().agent_engines.memories.create(
                    name=self.reasoning_engine_name,
                    fact=fact[:1500],
                    scope={"user_id": uid},
                )
                if getattr(created, "name", None):
                    mem_id = str(created.name).split("/")[-1]
            except Exception:
                backend = "firestore_scoped_memory_bank"

        record = {
            "memory_id": mem_id,
            "user_id": uid,
            "service_name": service_name,
            "incident_id": incident_id,
            "fact": fact[:1500],
            "created_at": now_iso,
            "backend": backend if not self.in_memory_only else "in_memory_scoped_bank",
        }
        with self._lock:
            self._mem_records.append(record)

        if not self.in_memory_only:
            try:
                self._fs().collection("scape_memories").document(f"{uid}__{mem_id}").set(record)
            except Exception:
                pass
        return record

    def forget_user_memories(self, verified_user_id: str) -> int:
        uid = self._validate_principal_user_id(verified_user_id)
        removed = 0
        with self._lock:
            kept = []
            for r in self._mem_records:
                if r.get("user_id") == uid:
                    removed += 1
                else:
                    kept.append(r)
            self._mem_records = kept

        if not self.in_memory_only:
            try:
                docs = (
                    self._fs()
                    .collection("scape_memories")
                    .where(filter=firestore.FieldFilter("user_id", "==", uid))
                    .stream()
                )
                for d in docs:
                    d.reference.delete()
                    removed += 1
            except Exception:
                pass
        return removed
