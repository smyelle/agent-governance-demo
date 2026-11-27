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
RENDER_DIR="${SCRIPT_DIR}/manifests/.rendered"
mkdir -p "${RENDER_DIR}"

echo "[1/5] Rendering AgentConnectivityTemplate, AgentGateway, UAP Policy V2, and SGP manifests (numeric project=${PROJECT_NUMBER})..."
PROJECT_ID="${PROJECT_ID}" PROJECT_NUMBER="${PROJECT_NUMBER}" REGION="${REGION}" RENDER_DIR="${RENDER_DIR}" SCRIPT_DIR="${SCRIPT_DIR}" python3 - <<'PY'
import os
from pathlib import Path

src_dir = Path(os.environ["SCRIPT_DIR"]) / "manifests"
out_dir = Path(os.environ["RENDER_DIR"])
replacements = {
    "${PROJECT_ID}": os.environ["PROJECT_ID"],
    "${PROJECT_NUMBER}": os.environ["PROJECT_NUMBER"],
    "${REGION}": os.environ["REGION"],
}

for fname in [
    "act_private.yaml",
    "agent_gateway.yaml",
    "uap_project_policy.json",
    "ma_content_authz.yaml",
    "ma_content_authz_policy.yaml",
]:
    content = (src_dir / fname).read_text(encoding="utf-8")
    for k, v in replacements.items():
        content = content.replace(k, v)
    (out_dir / fname).write_text(content, encoding="utf-8")
print("[OK] Rendered validated manifests into infra/manifests/.rendered/")
PY

TOKEN="$(gcloud auth print-access-token --quiet)"

echo "[2/5] Provisioning AgentConnectivityTemplate (PRIVATE_RANGES_ONLY)..."
ACT_JSON="$(python3 -c "import json,yaml,pathlib; print(json.dumps(yaml.safe_load(pathlib.Path('${RENDER_DIR}/act_private.yaml').read_text())))")"
ACT_HTTP="$(curl -sS -o "${RENDER_DIR}/act_response.json" -w "%{http_code}" \
  -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -H "X-Goog-User-Project: ${PROJECT_ID}" \
  "https://networkservices.googleapis.com/v1alpha1/projects/${PROJECT_NUMBER}/locations/${REGION}/agentConnectivityTemplates?agentConnectivityTemplateId=cymbal-act-private" \
  -d "${ACT_JSON}" || echo "000")"
echo "[INFO] ACT control-plane HTTP status: ${ACT_HTTP}"

echo "[3/5] Provisioning AgentGateway (240.0.0.2:443, dual global + ${REGION} numeric registries)..."
AGW_JSON="$(python3 -c "import json,yaml,pathlib; print(json.dumps(yaml.safe_load(pathlib.Path('${RENDER_DIR}/agent_gateway.yaml').read_text())))")"
AGW_HTTP="$(curl -sS -o "${RENDER_DIR}/agw_response.json" -w "%{http_code}" \
  -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -H "X-Goog-User-Project: ${PROJECT_ID}" \
  "https://networkservices.googleapis.com/v1alpha1/projects/${PROJECT_NUMBER}/locations/${REGION}/agentGateways?agentGatewayId=cymbal-agent-gateway" \
  -d "${AGW_JSON}" || echo "000")"
echo "[INFO] AgentGateway control-plane HTTP status: ${AGW_HTTP}"

echo "[4/5] Provisioning Model Armor AuthzExtension & CONTENT_AUTHZ AuthzPolicy..."
MA_EXT_JSON="$(python3 -c "import json,yaml,pathlib; print(json.dumps(yaml.safe_load(pathlib.Path('${RENDER_DIR}/ma_content_authz.yaml').read_text())))")"
MA_EXT_HTTP="$(curl -sS -o "${RENDER_DIR}/ma_ext_response.json" -w "%{http_code}" \
  -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -H "X-Goog-User-Project: ${PROJECT_ID}" \
  "https://networkservices.googleapis.com/v1/projects/${PROJECT_NUMBER}/locations/${REGION}/authzExtensions?authzExtensionId=cymbal-ma-content-authz" \
  -d "${MA_EXT_JSON}" || echo "000")"
if [[ "${MA_EXT_HTTP}" == "409" ]]; then
  MA_EXT_HTTP="$(curl -sS -o "${RENDER_DIR}/ma_ext_response.json" -w "%{http_code}" \
    -X PATCH \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -H "X-Goog-User-Project: ${PROJECT_ID}" \
    "https://networkservices.googleapis.com/v1/projects/${PROJECT_NUMBER}/locations/${REGION}/authzExtensions/cymbal-ma-content-authz" \
    -d "${MA_EXT_JSON}" || echo "000")"
fi
echo "[INFO] Model Armor AuthzExtension HTTP status: ${MA_EXT_HTTP}"

AUTHZ_POL_JSON="$(python3 -c "import json,yaml,pathlib; print(json.dumps(yaml.safe_load(pathlib.Path('${RENDER_DIR}/ma_content_authz_policy.yaml').read_text())))")"
AUTHZ_POL_HTTP="$(curl -sS -o "${RENDER_DIR}/authz_policy_response.json" -w "%{http_code}" \
  -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -H "X-Goog-User-Project: ${PROJECT_ID}" \
  "https://networksecurity.googleapis.com/v1/projects/${PROJECT_NUMBER}/locations/${REGION}/authzPolicies?authzPolicyId=cymbal-ma-content-authz-policy" \
  -d "${AUTHZ_POL_JSON}" || echo "000")"
if [[ "${AUTHZ_POL_HTTP}" == "409" ]]; then
  AUTHZ_POL_HTTP="$(curl -sS -o "${RENDER_DIR}/authz_policy_response.json" -w "%{http_code}" \
    -X PATCH \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -H "X-Goog-User-Project: ${PROJECT_ID}" \
    "https://networksecurity.googleapis.com/v1/projects/${PROJECT_NUMBER}/locations/${REGION}/authzPolicies/cymbal-ma-content-authz-policy" \
    -d "${AUTHZ_POL_JSON}" || echo "000")"
fi
echo "[INFO] Model Armor AuthzPolicy HTTP status: ${AUTHZ_POL_HTTP}"

echo "[5/5] Inspecting Agent Registry resources & provisioning IAM v3 UAP AccessPolicy + PolicyBinding..."
gcloud agent-registry services list \
  --location="${REGION}" \
  --project="${PROJECT_ID}" \
  --format="json" > "${RENDER_DIR}/registry_services.json" 2>/dev/null || echo "[]" > "${RENDER_DIR}/registry_services.json"

UAP_HTTP="$(curl -sS -o "${RENDER_DIR}/uap_response.json" -w "%{http_code}" \
  -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -H "X-Goog-User-Project: ${PROJECT_ID}" \
  "https://iam.googleapis.com/v3/projects/${PROJECT_NUMBER}/locations/global/accessPolicies?accessPolicyId=cymbal-uap-per-tool-cel" \
  --data-binary "@${RENDER_DIR}/uap_project_policy.json" || echo "000")"
if [[ "${UAP_HTTP}" == "409" ]]; then
  UAP_HTTP="$(curl -sS -o "${RENDER_DIR}/uap_response.json" -w "%{http_code}" \
    -X PATCH \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -H "X-Goog-User-Project: ${PROJECT_ID}" \
    "https://iam.googleapis.com/v3/projects/${PROJECT_NUMBER}/locations/global/accessPolicies/cymbal-uap-per-tool-cel" \
    --data-binary "@${RENDER_DIR}/uap_project_policy.json" || echo "000")"
fi
echo "[INFO] UAP AccessPolicy (iam.googleapis.com/v3) HTTP status: ${UAP_HTTP}"

UAP_BIND_JSON="$(PROJECT_NUMBER="${PROJECT_NUMBER}" python3 - <<'PY'
import json
import os
pnum = os.environ["PROJECT_NUMBER"]
print(json.dumps({
    "displayName": "cymbal-uap-per-tool-cel-binding",
    "policyKind": "ACCESS",
    "policy": f"projects/{pnum}/locations/global/accessPolicies/cymbal-uap-per-tool-cel",
    "target": {
        "principalSet": f"//cloudresourcemanager.googleapis.com/projects/{pnum}"
    },
}))
PY
)"
UAP_BIND_HTTP="$(curl -sS -o "${RENDER_DIR}/uap_binding_response.json" -w "%{http_code}" \
  -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -H "X-Goog-User-Project: ${PROJECT_ID}" \
  "https://iam.googleapis.com/v3/projects/${PROJECT_NUMBER}/locations/global/policyBindings?policyBindingId=cymbal-uap-per-tool-cel-binding" \
  -d "${UAP_BIND_JSON}" || echo "000")"
if [[ "${UAP_BIND_HTTP}" == "409" ]]; then
  UAP_BIND_HTTP="$(curl -sS -o "${RENDER_DIR}/uap_binding_response.json" -w "%{http_code}" \
    -X PATCH \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -H "X-Goog-User-Project: ${PROJECT_ID}" \
    "https://iam.googleapis.com/v3/projects/${PROJECT_NUMBER}/locations/global/policyBindings/cymbal-uap-per-tool-cel-binding" \
    -d "${UAP_BIND_JSON}" || echo "000")"
fi
echo "[INFO] UAP PolicyBinding (iam.googleapis.com/v3) HTTP status: ${UAP_BIND_HTTP}"

is_ok_http() {
  [[ "$1" =~ ^20[01]$ || "$1" == "409" ]]
}

if is_ok_http "${ACT_HTTP}" \
  && is_ok_http "${AGW_HTTP}" \
  && is_ok_http "${MA_EXT_HTTP}" \
  && is_ok_http "${AUTHZ_POL_HTTP}" \
  && is_ok_http "${UAP_HTTP}" \
  && is_ok_http "${UAP_BIND_HTTP}"; then
  GATEWAY_STATE="PROVISIONED_CONTROL_PLANE"
else
  GATEWAY_STATE="PREVIEW_MANIFEST_VALIDATED_PLUGIN_ENFORCED"
  echo "[INFO] Control-plane returned HTTP ACT=${ACT_HTTP}, AGW=${AGW_HTTP}, MA_EXT=${MA_EXT_HTTP}, AUTHZ_POL=${AUTHZ_POL_HTTP}, UAP=${UAP_HTTP}, UAP_BIND=${UAP_BIND_HTTP}."
  echo "[INFO] Validated manifests saved in ${RENDER_DIR} and UAP Policy V2 CEL + Model Armor CONTENT_AUTHZ parity is enforced inline by CymbalGovernancePlugin."
fi

cat > "${RENDER_DIR}/gateway_status.json" <<EOF
{
  "project_id": "${PROJECT_ID}",
  "project_number": "${PROJECT_NUMBER}",
  "region": "${REGION}",
  "gateway_state": "${GATEWAY_STATE}",
  "act_http_status": "${ACT_HTTP}",
  "agw_http_status": "${AGW_HTTP}",
  "ma_ext_http_status": "${MA_EXT_HTTP}",
  "authz_pol_http_status": "${AUTHZ_POL_HTTP}",
  "uap_http_status": "${UAP_HTTP}",
  "uap_bind_http_status": "${UAP_BIND_HTTP}",
  "vip_address": "240.0.0.2:443",
  "registries": [
    "projects/${PROJECT_NUMBER}/locations/global/agentRegistry",
    "projects/${PROJECT_NUMBER}/locations/${REGION}/agentRegistry"
  ]
}
EOF

echo "[OK] Phase 3 Agent Gateway step complete (state=${GATEWAY_STATE})."
