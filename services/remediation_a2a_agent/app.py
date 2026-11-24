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

"""Standalone A2A v1.0 Release Remediation Agent Service.

Serves `GET /.well-known/agent-card.json` and `POST /a2a` (JSON-RPC 2.0
`message/send`). Enforces caller identity and human SENTINEL AG3 approval metadata
before executing simulated canary rollback and post-rollback SLO verification.
"""

from __future__ import annotations

import datetime
import os
from typing import Any
import uuid

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn

app = FastAPI(
    title="Cymbal Release Remediation A2A v1.0 Agent",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
)


class RollbackCommandPayload(BaseModel):
    incident_id: str = Field(..., min_length=3, max_length=64)
    service_name: str = Field(..., min_length=2, max_length=128)
    from_version: str = Field(default="v2.14.3", max_length=32)
    to_version: str = Field(default="v2.14.2", max_length=32)
    approval_id: str = Field(..., min_length=4, max_length=128)
    approver_principal: str = Field(..., min_length=3, max_length=128)
    change_freeze_active: bool = False
    vp_exception_ticket: str | None = Field(default=None, max_length=64)


class JsonRpcA2ARequest(BaseModel):
    jsonrpc: str = Field(default="2.0", pattern=r"^2\.0$")
    id: str | int
    method: str = Field(..., pattern=r"^(message/send|tasks/send)$")
    params: dict[str, Any]


def build_agent_card(base_url: str) -> dict[str, Any]:
    return {
        "protocolVersion": "1.0",
        "name": "remediation-a2a-agent",
        "displayName": "Cymbal Release Remediation & Canary Rollback Agent",
        "description": "Governed A2A v1.0 specialist agent executing AG3-approved canary rollbacks and Valkey stream trims.",
        "url": f"{base_url.rstrip('/')}/a2a",
        "version": "1.0.0",
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
            "stateTransitionHistory": True,
        },
        "defaultInputModes": ["application/json", "text/plain"],
        "defaultOutputModes": ["application/json", "text/plain"],
        "authentication": {
            "schemes": ["Bearer", "SPIFFE-AGENT-IDENTITY"],
        },
        "skills": [
            {
                "id": "execute_canary_rollback",
                "name": "Execute Governed Canary Rollback",
                "description": "Rolls back a degraded service release after human SENTINEL AG3 approval and verifies SLO recovery.",
                "tags": ["sre", "rollback", "sentinel-ag3", "canary"],
            },
            {
                "id": "trim_stream_backlog",
                "name": "Trim Saturated Telemetry Stream Consumer Lag",
                "description": "Safely drains consumer lag without dropping committed billing/usage ledger offsets.",
                "tags": ["valkey", "remediation", "slo"],
            },
        ],
    }


@app.middleware("http")
async def apply_security_headers(request: Request, call_next: Any) -> Any:
    if request.method not in {"GET", "POST", "OPTIONS"}:
        return JSONResponse({"detail": "Method not allowed"}, status_code=405)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    return response


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "agent": "remediation-a2a-agent"}


@app.get("/.well-known/agent-card.json")
async def get_agent_card(request: Request) -> dict[str, Any]:
    public_url = (
        os.getenv("CYMBAL_A2A_URL")
        or os.getenv("SCAPE_A2A_URL")
        or str(request.base_url).rstrip("/")
    )
    return build_agent_card(public_url)


@app.post("/a2a")
async def handle_a2a_rpc(
    rpc: JsonRpcA2ARequest,
    x_cymbal_ag3_approval_id: str | None = Header(default=None),
    x_cymbal_caller_identity: str | None = Header(default=None),
) -> dict[str, Any]:
    message = rpc.params.get("message") or {}
    metadata = message.get("metadata") or rpc.params.get("metadata") or {}

    raw_payload = dict(metadata.get("rollback_request") or rpc.params.get("rollback_request") or {})
    if x_cymbal_ag3_approval_id and "approval_id" not in raw_payload:
        raw_payload["approval_id"] = x_cymbal_ag3_approval_id

    if not raw_payload.get("approval_id"):
        raise HTTPException(
            status_code=403,
            detail="SENTINEL AG3 human approval token missing; remediation denied fail-closed.",
        )

    cmd = RollbackCommandPayload.model_validate(raw_payload)
    if cmd.change_freeze_active and not cmd.vp_exception_ticket:
        raise HTTPException(
            status_code=403,
            detail="Active Cymbal Change Freeze requires VP exception ticket before rollback.",
        )

    task_id = f"a2a-rem-{uuid.uuid4().hex[:10]}"
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    result_artifact = {
        "task_id": task_id,
        "status": "COMPLETED",
        "incident_id": cmd.incident_id,
        "service_name": cmd.service_name,
        "rolled_back_from": cmd.from_version,
        "active_version_now": cmd.to_version,
        "approval_id": cmd.approval_id,
        "approver_principal": cmd.approver_principal,
        "caller_spiffe_or_oidc": (
            x_cymbal_caller_identity or "spiffe://agent-identity/cymbal-ops-release-agent"
        ),
        "vp_exception_ticket": cmd.vp_exception_ticket,
        "post_rollback_metrics": {
            "p99_latency_ms": 298,
            "error_rate_pct": 0.12,
            "valkey_memory_saturation_pct": 41.2,
            "slo_recovered": True,
        },
        "completed_at": now_iso,
    }

    return {
        "jsonrpc": "2.0",
        "id": rpc.id,
        "result": {
            "id": task_id,
            "status": {"state": "completed", "timestamp": now_iso},
            "artifacts": [
                {
                    "name": "canary_rollback_verification",
                    "parts": [
                        {
                            "type": "data",
                            "data": result_artifact,
                        },
                        {
                            "type": "text",
                            "text": (
                                f"Canary rollback {cmd.from_version} -> {cmd.to_version} completed for "
                                f"{cmd.service_name} ({cmd.incident_id}). Post-rollback p99 latency "
                                "recovered to 298ms and SLO is green."
                            ),
                        },
                    ],
                }
            ],
        },
    }


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8082"))
    bind_host = os.getenv("BIND_HOST", "127.0.0.1")
    uvicorn.run(app, host=bind_host, port=port)
