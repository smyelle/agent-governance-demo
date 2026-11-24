#!/usr/bin/env bash
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

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ -f "${REPO_ROOT}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${REPO_ROOT}/.env"
  set +a
fi

export CLOUDSDK_METRICS_ENVIRONMENT="${CLOUDSDK_METRICS_ENVIRONMENT:+$CLOUDSDK_METRICS_ENVIRONMENT }datacloud.antigravity"

PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
REGION="${GOOGLE_CLOUD_LOCATION:-us-central1}"
PROJECT_NUMBER="$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')"
ACTIVE_ACCOUNT="$(gcloud auth list --filter=status:ACTIVE --format='value(account)' | head -n 1)"
COMPUTE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"

echo "[0/4] Ensuring least-privilege Cloud Build & Agent Runtime IAM roles on ${COMPUTE_SA}..."
for sa_role in \
  roles/storage.objectAdmin \
  roles/logging.logWriter \
  roles/artifactregistry.writer \
  roles/cloudbuild.builds.builder \
  roles/aiplatform.user \
  roles/datastore.user \
  roles/bigquery.dataEditor \
  roles/bigquery.jobUser \
  roles/modelarmor.user \
  roles/cloudtrace.agent; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${COMPUTE_SA}" \
    --role="${sa_role}" \
    --condition=None \
    --quiet >/dev/null
done

echo "[1/4] Deploying IAM-authenticated DevX Domain MCP Server (devx-mcp-server) to Cloud Run..."
gcloud run deploy devx-mcp-server \
  --source="${REPO_ROOT}/services/devx_mcp_server" \
  --region="${REGION}" \
  --project="${PROJECT_ID}" \
  --no-allow-unauthenticated \
  --cpu=1 \
  --memory=512Mi \
  --min-instances=0 \
  --max-instances=5 \
  --quiet

MCP_BASE_URL="$(gcloud run services describe devx-mcp-server --region="${REGION}" --project="${PROJECT_ID}" --format='value(status.url)')"
MCP_URL="${MCP_BASE_URL}/mcp"
echo "[OK] DevX MCP Server deployed at ${MCP_URL}"

echo "[2/4] Deploying IAM-authenticated Release Remediation A2A v1.0 Agent (remediation-a2a-agent) to Cloud Run..."
gcloud run deploy remediation-a2a-agent \
  --source="${REPO_ROOT}/services/remediation_a2a_agent" \
  --region="${REGION}" \
  --project="${PROJECT_ID}" \
  --no-allow-unauthenticated \
  --cpu=1 \
  --memory=512Mi \
  --min-instances=0 \
  --max-instances=5 \
  --quiet

A2A_BASE_URL="$(gcloud run services describe remediation-a2a-agent --region="${REGION}" --project="${PROJECT_ID}" --format='value(status.url)')"
gcloud run services update remediation-a2a-agent \
  --region="${REGION}" \
  --project="${PROJECT_ID}" \
  --set-env-vars="SCAPE_A2A_URL=${A2A_BASE_URL}" \
  --quiet >/dev/null
echo "[OK] Remediation A2A Agent deployed at ${A2A_BASE_URL}"

echo "[3/4] Granting least-privilege roles/run.invoker bindings (no public allUsers)..."
COMPUTE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
AIPLATFORM_SA="service-${PROJECT_NUMBER}@gcp-sa-aiplatform-re.iam.gserviceaccount.com"

for svc in devx-mcp-server remediation-a2a-agent; do
  gcloud run services add-iam-policy-binding "${svc}" \
    --region="${REGION}" \
    --project="${PROJECT_ID}" \
    --member="user:${ACTIVE_ACCOUNT}" \
    --role="roles/run.invoker" \
    --quiet >/dev/null
  gcloud run services add-iam-policy-binding "${svc}" \
    --region="${REGION}" \
    --project="${PROJECT_ID}" \
    --member="serviceAccount:${COMPUTE_SA}" \
    --role="roles/run.invoker" \
    --quiet >/dev/null || true
  gcloud run services add-iam-policy-binding "${svc}" \
    --region="${REGION}" \
    --project="${PROJECT_ID}" \
    --member="serviceAccount:${AIPLATFORM_SA}" \
    --role="roles/run.invoker" \
    --quiet >/dev/null || true
done

echo "[4/4] Registering MCP Server & A2A Agent in Agent Registry (${REGION})..."
MCP_TOOL_SPEC_JSON="$(python3 - <<'PY'
import json
spec = {
    "tools": [
        {
            "name": "query_conduit_metrics",
            "description": "Read-only query of golden-signal p99 latency, error rate, and stream saturation metrics.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "service_name": {"type": "string"},
                    "window_minutes": {"type": "integer"}
                },
                "required": ["service_name"]
            },
            "annotations": {
                "title": "Query Conduit Metrics",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        },
        {
            "name": "check_jira_and_change_freeze",
            "description": "Read-only lookup of recent deployments, PRs, and active enterprise change-freeze windows.",
            "inputSchema": {
                "type": "object",
                "properties": {"service_name": {"type": "string"}},
                "required": ["service_name"]
            },
            "annotations": {
                "title": "Check Jira and Change Freeze",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        },
        {
            "name": "lookup_devhub_and_runbook",
            "description": "Read-only lookup of service ownership, blast radius, AEGIS risk tier, and runbook.",
            "inputSchema": {
                "type": "object",
                "properties": {"app_id": {"type": "string"}},
                "required": ["app_id"]
            },
            "annotations": {
                "title": "Lookup DevHub CMDB and Runbook",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        },
        {
            "name": "annotate_incident_ticket",
            "description": "Non-destructive mutating tool that appends structured triage findings to an incident ticket.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "incident_id": {"type": "string"},
                    "note": {"type": "string"}
                },
                "required": ["incident_id", "note"]
            },
            "annotations": {
                "title": "Annotate Incident Ticket",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": False,
                "openWorldHint": False
            }
        },
        {
            "name": "purge_production_valkey_stream",
            "description": "Destructive administrative operation blocked by UAP Policy V2 CEL.",
            "inputSchema": {
                "type": "object",
                "properties": {"stream_key": {"type": "string"}},
                "required": ["stream_key"]
            },
            "annotations": {
                "title": "Purge Production Valkey Stream",
                "readOnlyHint": False,
                "destructiveHint": True,
                "idempotentHint": False,
                "openWorldHint": False
            }
        }
    ]
}
print(json.dumps(spec))
PY
)"

if gcloud agent-registry services describe scape-devx-mcp-server --location="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud agent-registry services update scape-devx-mcp-server \
    --location="${REGION}" \
    --project="${PROJECT_ID}" \
    --display-name="SCAPE DevX Domain MCP Server" \
    --description="Governed MCP StreamableHTTP server exposing Conduit, Jira Change-Freeze, and DevHub CMDB tools with explicit readOnlyHint/destructiveHint annotations." \
    --interfaces="protocolBinding=JSONRPC,url=${MCP_URL}" \
    --mcp-server-spec-type=tool-spec \
    --mcp-server-spec-content="${MCP_TOOL_SPEC_JSON}" \
    --quiet >/dev/null
else
  gcloud agent-registry services create scape-devx-mcp-server \
    --location="${REGION}" \
    --project="${PROJECT_ID}" \
    --display-name="SCAPE DevX Domain MCP Server" \
    --description="Governed MCP StreamableHTTP server exposing Conduit, Jira Change-Freeze, and DevHub CMDB tools with explicit readOnlyHint/destructiveHint annotations." \
    --interfaces="protocolBinding=JSONRPC,url=${MCP_URL}" \
    --mcp-server-spec-type=tool-spec \
    --mcp-server-spec-content="${MCP_TOOL_SPEC_JSON}" \
    --quiet >/dev/null
fi
echo "[OK] Registered scape-devx-mcp-server in Agent Registry."

A2A_CARD_JSON="$(A2A_BASE_URL="${A2A_BASE_URL}" python3 - <<'PY'
import json
import os
base = os.environ["A2A_BASE_URL"].rstrip("/")
card = {
    "protocolVersion": "0.3.0",
    "name": "remediation-a2a-agent",
    "description": "Governed A2A Release Remediation Agent executing AG3-approved canary rollbacks and SLO verification.",
    "url": f"{base}/a2a",
    "version": "1.0.0",
    "capabilities": {
        "streaming": False,
        "pushNotifications": False,
        "stateTransitionHistory": True,
    },
    "defaultInputModes": ["application/json", "text/plain"],
    "defaultOutputModes": ["application/json", "text/plain"],
    "skills": [
        {
            "id": "execute_canary_rollback",
            "name": "Execute Governed Canary Rollback",
            "description": "Rolls back degraded service release after human AEGIS AG3 approval.",
            "tags": ["sre", "rollback", "aegis-ag3"],
        }
    ],
}
print(json.dumps(card))
PY
)"

if gcloud agent-registry services describe remediation-a2a-agent --location="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud agent-registry services delete remediation-a2a-agent \
    --location="${REGION}" --project="${PROJECT_ID}" --quiet >/dev/null 2>&1 || true
fi

gcloud agent-registry services create remediation-a2a-agent \
  --location="${REGION}" \
  --project="${PROJECT_ID}" \
  --display-name="Release Remediation A2A Agent" \
  --description="A2A specialist agent executing AEGIS AG3-approved canary rollbacks." \
  --agent-spec-type=a2a-agent-card \
  --agent-spec-content="${A2A_CARD_JSON}" \
  --quiet >/dev/null 2>&1 || \
gcloud agent-registry services create remediation-a2a-agent \
  --location="${REGION}" \
  --project="${PROJECT_ID}" \
  --display-name="Release Remediation A2A Agent" \
  --description="A2A specialist agent executing AEGIS AG3-approved canary rollbacks." \
  --agent-spec-type=no-spec \
  --interfaces="protocolBinding=HTTP_JSON,url=${A2A_BASE_URL}/a2a" \
  --quiet >/dev/null

echo "[OK] Registered remediation-a2a-agent in Agent Registry."

if [[ -f "${REPO_ROOT}/.env" ]]; then
  MCP_URL="${MCP_URL}" A2A_BASE_URL="${A2A_BASE_URL}" REPO_ROOT="${REPO_ROOT}" python3 - <<'PY'
import os
from pathlib import Path

env_path = Path(os.environ["REPO_ROOT"]) / ".env"
lines = env_path.read_text(encoding="utf-8").splitlines()
kv = {}
out = []
for line in lines:
    if "=" in line and not line.strip().startswith("#"):
        k, _ = line.split("=", 1)
        if k in {"SCAPE_MCP_URL", "SCAPE_A2A_URL"}:
            continue
    out.append(line)
out.append(f"SCAPE_MCP_URL={os.environ['MCP_URL']}")
out.append(f"SCAPE_A2A_URL={os.environ['A2A_BASE_URL']}")
env_path.write_text("\n".join(out) + "\n", encoding="utf-8")
PY
fi

echo "[OK] Phase 2 Cloud Run services deployed & registered in Agent Registry."
