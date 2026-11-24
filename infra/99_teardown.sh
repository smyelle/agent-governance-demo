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
TOKEN="$(gcloud auth print-access-token --quiet)"

echo "[1/5] Deleting ReasoningEngine instances (with ?force=true to clean child sessions & memories)..."
RE_NAMES="$(curl -sS -H "Authorization: Bearer ${TOKEN}" \
  "https://${REGION}-aiplatform.googleapis.com/v1beta1/projects/${PROJECT_ID}/locations/${REGION}/reasoningEngines" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); [print(x['name']) for x in d.get('reasoningEngines',[]) if 'scape' in x.get('displayName','').lower() or 'devx' in x.get('displayName','').lower()]" || true)"

for re_name in ${RE_NAMES}; do
  echo "  Deleting ${re_name}?force=true ..."
  curl -sS -X DELETE -H "Authorization: Bearer ${TOKEN}" \
    "https://${REGION}-aiplatform.googleapis.com/v1beta1/${re_name}?force=true" >/dev/null || true
done

echo "[2/5] Deleting Agent Gateway & AgentConnectivityTemplate (reverse dependency order)..."
curl -sS -X DELETE -H "Authorization: Bearer ${TOKEN}" \
  "https://networkservices.googleapis.com/v1alpha1/projects/${PROJECT_NUMBER}/locations/${REGION}/agentGateways/scape-agent-gateway" >/dev/null 2>&1 || true
curl -sS -X DELETE -H "Authorization: Bearer ${TOKEN}" \
  "https://networkservices.googleapis.com/v1alpha1/projects/${PROJECT_NUMBER}/locations/${REGION}/agentConnectivityTemplates/scape-act-private" >/dev/null 2>&1 || true

echo "[3/5] Deleting Agent Registry services..."
for svc_id in scape-devx-mcp-server remediation-a2a-agent scape-devx-incident-copilot; do
  gcloud agent-registry services delete "${svc_id}" \
    --location="${REGION}" \
    --project="${PROJECT_ID}" \
    --quiet >/dev/null 2>&1 || true
done

echo "[4/5] Deleting Cloud Run services..."
for run_svc in devx-mcp-server remediation-a2a-agent scape-steward-web; do
  gcloud run services delete "${run_svc}" \
    --region="${REGION}" \
    --project="${PROJECT_ID}" \
    --quiet >/dev/null 2>&1 || true
done

echo "[5/5] Deleting NetworkAttachment, PSC-I Subnet, VPC, and Model Armor templates..."
gcloud compute network-attachments delete scape-psci-attachment \
  --region="${REGION}" --project="${PROJECT_ID}" --quiet >/dev/null 2>&1 || true
gcloud compute networks subnets delete scape-psci-subnet \
  --region="${REGION}" --project="${PROJECT_ID}" --quiet >/dev/null 2>&1 || true
gcloud compute networks delete scape-vpc \
  --project="${PROJECT_ID}" --quiet >/dev/null 2>&1 || true

export CLOUDSDK_API_ENDPOINT_OVERRIDES_MODELARMOR="https://modelarmor.${REGION}.rep.googleapis.com/"
for tpl in scape-default-medium-gpp scape-strict-ag3-gpp scape-devx-default-gpp; do
  gcloud model-armor templates delete "${tpl}" \
    --location="${REGION}" --project="${PROJECT_ID}" --quiet >/dev/null 2>&1 || true
done

echo "[OK] Reverse-dependency teardown complete for ${PROJECT_ID}."
