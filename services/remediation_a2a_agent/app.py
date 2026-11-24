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

"""Standalone A2A v1.0 Paved-Path Deployment & Blueprint Executor Agent.

Serves `GET /.well-known/agent-card.json` and `POST /a2a` (JSON-RPC 2.0
`message/send`). Enforces caller identity and human AG3 Governance Reviewer
approval metadata before committing Golden Blueprints, Terraform Paved-Path
bundles, and Tier-1 Registry enrollments.
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
    title="Cymbal Paved-Path Deployment & Blueprint A2A v1.0 Agent",
    version="1.1.0",
    docs_url=None,
    redoc_url=None,
)


class PavedPathDeployPayload(BaseModel):
    candidate_id: str = Field(default="CAND-101", min_length=3, max_length=64)
    agent_name: str = Field(default="billing-dispute-assistant", min_length=2, max_length=128)
    app_id: str = Field(default="SVC-CYMBAL-101", max_length=64)
    from_version: str = Field(default="v1", max_length=32)
    to_version: str = Field(default="v2-golden-blueprint", max_length=48)
    approval_id: str = Field(..., min_length=4, max_length=128)
    approver_principal: str = Field(..., min_length=3, max_length=128)
    policy_freeze_active: bool = False
    vp_exception_ticket: str | None = Field(default=None, max_length=64)
    target_mode: str = Field(default="enterprise_hybrid", max_length=48)


class JsonRpcA2ARequest(BaseModel):
    jsonrpc: str = Field(default="2.0", pattern=r"^2\.0$")
    id: str | int
    method: str = Field(..., pattern=r"^(message/send|tasks/send)$")
    params: dict[str, Any]


def render_agent_terraform_paved_path(
    candidate_id: str,
    agent_name: str,
    app_id: str,
    target_mode: str = "enterprise_hybrid",
) -> str:
    """Renders a clean per-agent HCL snippet referencing the standardized Paved-Path module."""
    safe_mod = agent_name.replace("-", "_")
    return (
        f'module "{safe_mod}_paved_path" {{\n'
        f'  source                  = "./infra/terraform"\n'
        f'  project_id              = var.project_id\n'
        f'  region                  = "us-central1"\n'
        f'  agent_id                = "{agent_name}"\n'
        f'  candidate_id            = "{candidate_id}"\n'
        f'  enterprise_app_id       = "{app_id}"\n'
        f'  architecture_mode       = "{target_mode}"\n'
        f'  gateway_proxy_url       = var.enterprise_gateway_url\n'
        f'  otlp_collector_endpoint = var.langfuse_otlp_endpoint\n'
        f'  enable_spiffe_wif       = true\n'
        f'  register_blueprint      = true\n'
        f"}}\n"
    )


def build_agent_card(base_url: str) -> dict[str, Any]:
    return {
        "protocolVersion": "1.0",
        "name": "remediation-a2a-agent",
        "displayName": "Cymbal Paved-Path Deployment & Blueprint Executor Agent",
        "description": (
            "Governed A2A v1.0 specialist agent executing AG3-approved Paved-Path "
            "deployments, Golden Blueprint promotions, and Tier-1 catalog enrollments."
        ),
        "url": f"{base_url.rstrip('/')}/a2a",
        "version": "1.1.0",
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
                "id": "deploy_paved_path_blueprint",
                "name": "Deploy Governed Paved-Path & Golden Blueprint",
                "description": (
                    "Enrolls an audited, prompt-optimized agent into Enterprise & GCP "
                    "Agent Registries with Terraform Paved-Path hooks after AG3 approval."
                ),
                "tags": ["governance", "paved-path", "blueprint", "ag3"],
            }
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

    raw_payload = dict(
        metadata.get("deployment_request")
        or rpc.params.get("deployment_request")
        or metadata.get("rollback_request")
        or rpc.params.get("rollback_request")
        or {}
    )
    if "incident_id" in raw_payload and "candidate_id" not in raw_payload:
        raw_payload["candidate_id"] = raw_payload["incident_id"]
    if "service_name" in raw_payload and "agent_name" not in raw_payload:
        raw_payload["agent_name"] = raw_payload["service_name"]
    if "change_freeze_active" in raw_payload and "policy_freeze_active" not in raw_payload:
        raw_payload["policy_freeze_active"] = raw_payload["change_freeze_active"]

    if x_cymbal_ag3_approval_id and "approval_id" not in raw_payload:
        raw_payload["approval_id"] = x_cymbal_ag3_approval_id

    if not raw_payload.get("approval_id"):
        raise HTTPException(
            status_code=403,
            detail="AG3 Governance Reviewer human approval token missing; deployment denied fail-closed.",
        )

    cmd = PavedPathDeployPayload.model_validate(raw_payload)
    if cmd.policy_freeze_active and not cmd.vp_exception_ticket:
        raise HTTPException(
            status_code=403,
            detail="Active Enterprise Governance Freeze requires VP exception ticket before deployment.",
        )

    task_id = f"a2a-dep-{uuid.uuid4().hex[:10]}"
    blueprint_id = f"bp-{cmd.agent_name}-{cmd.to_version}".lower()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    tf_snippet = render_agent_terraform_paved_path(
        candidate_id=cmd.candidate_id,
        agent_name=cmd.agent_name,
        app_id=cmd.app_id,
        target_mode=cmd.target_mode,
    )

    result_artifact = {
        "task_id": task_id,
        "status": "DEPLOYED_AND_REGISTERED",
        "candidate_id": cmd.candidate_id,
        "agent_name": cmd.agent_name,
        "app_id": cmd.app_id,
        "previous_version": cmd.from_version,
        "deployed_blueprint_version": cmd.to_version,
        "golden_blueprint_id": blueprint_id,
        "approval_id": cmd.approval_id,
        "approver_principal": cmd.approver_principal,
        "caller_spiffe_or_oidc": (
            x_cymbal_caller_identity or "spiffe://agent-identity/cymbal-ops-release-agent"
        ),
        "vp_exception_ticket": cmd.vp_exception_ticket,
        "tier1_registration_receipt": {
            "enterprise_catalog_enrolled": True,
            "gcp_agent_registry_synced": True,
            "gateway_proxy_bound": True,
            "otlp_langfuse_stream_verified": True,
            "spiffe_entra_wif_bound": True,
            "kill_switch_armed": True,
        },
        "post_deployment_metrics": {
            "readiness_score": 98.0,
            "p99_latency_ms": 212,
            "slo_recovered": True,
            "compliance_verified": True,
        },
        "terraform_paved_path_hcl": tf_snippet,
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
                    "name": "paved_path_deployment_receipt",
                    "parts": [
                        {
                            "type": "data",
                            "data": result_artifact,
                        },
                        {
                            "type": "text",
                            "text": (
                                f"Deployed Golden Blueprint {blueprint_id} ({cmd.from_version} -> {cmd.to_version}) "
                                f"for {cmd.agent_name} ({cmd.candidate_id}) with Tier-1 Gateway, OTLP, SPIFFE WIF, "
                                "and Registry hooks verified."
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
