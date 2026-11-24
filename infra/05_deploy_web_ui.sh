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

export CLOUDSDK_CORE_DISABLE_PROMPTS=1
export CLOUDSDK_METRICS_ENVIRONMENT="${CLOUDSDK_METRICS_ENVIRONMENT:+$CLOUDSDK_METRICS_ENVIRONMENT }datacloud.antigravity"

PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
REGION="${GOOGLE_CLOUD_LOCATION:-us-central1}"
PROJECT_NUMBER="$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')"
ACTIVE_ACCOUNT="$(gcloud auth list --filter=status:ACTIVE --format='value(account)' | head -n 1)"

WEB_SERVICE="cymbal-ops-release-web"
WEB_SA_NAME="cymbal-web-ui-sa"
WEB_SA_EMAIL="${WEB_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
SESSION_SECRET_NAME="cymbal-web-session-secret"

PYTHON_BIN="${REPO_ROOT}/.venv/bin/python"
if [[ ! -x "${PYTHON_BIN}" ]]; then
  PYTHON_BIN="python3"
fi

echo "[1/6] Running pre-deploy local smoke & compliance gate on 127.0.0.1..."
"${PYTHON_BIN}" "${REPO_ROOT}/scripts/smoke_test_web_ui.py" --local --offline

echo "[2/6] Provisioning dedicated least-privilege service account (${WEB_SA_EMAIL})..."
gcloud services enable secretmanager.googleapis.com iap.googleapis.com --project="${PROJECT_ID}" --quiet

if ! gcloud iam service-accounts describe "${WEB_SA_EMAIL}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud iam service-accounts create "${WEB_SA_NAME}" \
    --display-name="Cymbal Operations & Release Web UI Service Account" \
    --project="${PROJECT_ID}" \
    --quiet
  sleep 5
fi

for role in \
  roles/aiplatform.user \
  roles/datastore.user \
  roles/bigquery.dataEditor \
  roles/bigquery.jobUser \
  roles/modelarmor.user \
  roles/cloudtrace.agent \
  roles/logging.logWriter; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${WEB_SA_EMAIL}" \
    --role="${role}" \
    --condition=None \
    --quiet >/dev/null
done

for downstream_svc in cymbal-ops-mcp-server remediation-a2a-agent; do
  if gcloud run services describe "${downstream_svc}" --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    gcloud run services add-iam-policy-binding "${downstream_svc}" \
      --region="${REGION}" \
      --project="${PROJECT_ID}" \
      --member="serviceAccount:${WEB_SA_EMAIL}" \
      --role="roles/run.invoker" \
      --quiet >/dev/null
  fi
done

echo "[3/6] Ensuring Secret Manager HMAC session key (${SESSION_SECRET_NAME})..."
if ! gcloud secrets describe "${SESSION_SECRET_NAME}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  python3 -c "import secrets; print(secrets.token_hex(32), end='')" | \
    gcloud secrets create "${SESSION_SECRET_NAME}" \
      --replication-policy="automatic" \
      --data-file=- \
      --project="${PROJECT_ID}" \
      --quiet
fi

gcloud secrets add-iam-policy-binding "${SESSION_SECRET_NAME}" \
  --project="${PROJECT_ID}" \
  --member="serviceAccount:${WEB_SA_EMAIL}" \
  --role="roles/secretmanager.secretAccessor" \
  --quiet >/dev/null

MCP_URL="${CYMBAL_MCP_URL:-}"
if [[ -z "${MCP_URL}" ]] && gcloud run services describe cymbal-ops-mcp-server --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  MCP_URL="$(gcloud run services describe cymbal-ops-mcp-server --region="${REGION}" --project="${PROJECT_ID}" --format='value(status.url)')/mcp"
fi

A2A_URL="${CYMBAL_A2A_URL:-}"
if [[ -z "${A2A_URL}" ]] && gcloud run services describe remediation-a2a-agent --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  A2A_URL="$(gcloud run services describe remediation-a2a-agent --region="${REGION}" --project="${PROJECT_ID}" --format='value(status.url)')"
fi

MA_DEFAULT="${CYMBAL_MODEL_ARMOR_DEFAULT_TEMPLATE:-projects/${PROJECT_ID}/locations/${REGION}/templates/cymbal-default-medium-gpp}"
MA_STRICT="${CYMBAL_MODEL_ARMOR_STRICT_TEMPLATE:-projects/${PROJECT_ID}/locations/${REGION}/templates/cymbal-strict-ag3-gpp}"
GEMINI_MDL="${GEMINI_MODEL:-gemini-3.8-flash}"
GEMINI_LITE="${GEMINI_LITE_MODEL:-gemini-3.5-flash-lite}"

echo "[4/6] Deploying ${WEB_SERVICE} to Cloud Run (${REGION}) with IAP & Zero-Secret posture..."
IAP_FLAG="--iap"
if ! gcloud run deploy "${WEB_SERVICE}" \
  --source="${REPO_ROOT}" \
  --region="${REGION}" \
  --project="${PROJECT_ID}" \
  --service-account="${WEB_SA_EMAIL}" \
  --no-allow-unauthenticated \
  "${IAP_FLAG}" \
  --ingress=all \
  --cpu=1 \
  --memory=1Gi \
  --min-instances=0 \
  --max-instances=5 \
  --set-secrets="CYMBAL_BFF_SESSION_SECRET=${SESSION_SECRET_NAME}:latest" \
  --set-env-vars="GOOGLE_CLOUD_PROJECT=${PROJECT_ID},GOOGLE_CLOUD_LOCATION=${REGION},GOOGLE_GENAI_USE_ENTERPRISE=TRUE,GOOGLE_GENAI_API_TRANSPORT=rest,GEMINI_MODEL=${GEMINI_MDL},GEMINI_LITE_MODEL=${GEMINI_LITE},CYMBAL_PLATFORM_MODE=google_native,CYMBAL_BQ_DATASET=cymbal_governance,CYMBAL_FIRESTORE_DATABASE=(default),CYMBAL_MODEL_ARMOR_DEFAULT_TEMPLATE=${MA_DEFAULT},CYMBAL_MODEL_ARMOR_STRICT_TEMPLATE=${MA_STRICT},CYMBAL_MCP_URL=${MCP_URL},CYMBAL_A2A_URL=${A2A_URL}" \
  --quiet; then
  echo "[WARN] Direct --iap flag unavailable on this project configuration; deploying with --no-allow-unauthenticated IAM enforcement..."
  gcloud run deploy "${WEB_SERVICE}" \
    --source="${REPO_ROOT}" \
    --region="${REGION}" \
    --project="${PROJECT_ID}" \
    --service-account="${WEB_SA_EMAIL}" \
    --no-allow-unauthenticated \
    --ingress=all \
    --cpu=1 \
    --memory=1Gi \
    --min-instances=0 \
    --max-instances=5 \
    --set-secrets="CYMBAL_BFF_SESSION_SECRET=${SESSION_SECRET_NAME}:latest" \
    --set-env-vars="GOOGLE_CLOUD_PROJECT=${PROJECT_ID},GOOGLE_CLOUD_LOCATION=${REGION},GOOGLE_GENAI_USE_ENTERPRISE=TRUE,GOOGLE_GENAI_API_TRANSPORT=rest,GEMINI_MODEL=${GEMINI_MDL},GEMINI_LITE_MODEL=${GEMINI_LITE},CYMBAL_PLATFORM_MODE=google_native,CYMBAL_BQ_DATASET=cymbal_governance,CYMBAL_FIRESTORE_DATABASE=(default),CYMBAL_MODEL_ARMOR_DEFAULT_TEMPLATE=${MA_DEFAULT},CYMBAL_MODEL_ARMOR_STRICT_TEMPLATE=${MA_STRICT},CYMBAL_MCP_URL=${MCP_URL},CYMBAL_A2A_URL=${A2A_URL}" \
    --quiet
fi

echo "[5/6] Configuring least-privilege Cloud Run Invoker & IAP Web Accessor bindings..."
ACCESS_TOKEN="$(gcloud auth print-access-token --quiet)"
curl -sS -X POST \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  "https://serviceusage.googleapis.com/v1beta1/projects/${PROJECT_NUMBER}/services/iap.googleapis.com:generateServiceIdentity" >/dev/null 2>&1 || true
IAP_SA="service-${PROJECT_NUMBER}@gcp-sa-iap.iam.gserviceaccount.com"

gcloud run services add-iam-policy-binding "${WEB_SERVICE}" \
  --region="${REGION}" \
  --project="${PROJECT_ID}" \
  --member="user:${ACTIVE_ACCOUNT}" \
  --role="roles/run.invoker" \
  --quiet </dev/null >/dev/null

gcloud run services add-iam-policy-binding "${WEB_SERVICE}" \
  --region="${REGION}" \
  --project="${PROJECT_ID}" \
  --member="serviceAccount:${IAP_SA}" \
  --role="roles/run.invoker" \
  --quiet </dev/null >/dev/null || true

gcloud iap web add-iam-policy-binding \
  --project="${PROJECT_ID}" \
  --resource-type=cloud-run \
  --service="${WEB_SERVICE}" \
  --region="${REGION}" \
  --member="user:${ACTIVE_ACCOUNT}" \
  --role="roles/iap.httpsResourceAccessor" \
  --condition=None \
  --quiet </dev/null >/dev/null 2>&1 || true

WEB_URL="$(gcloud run services describe "${WEB_SERVICE}" --region="${REGION}" --project="${PROJECT_ID}" --format='value(status.url)')"

if [[ -f "${REPO_ROOT}/.env" ]]; then
  WEB_URL="${WEB_URL}" REPO_ROOT="${REPO_ROOT}" python3 - <<'PY'
import os
from pathlib import Path

env_path = Path(os.environ["REPO_ROOT"]) / ".env"
lines = env_path.read_text(encoding="utf-8").splitlines()
out = [ln for ln in lines if not ln.startswith("CYMBAL_WEB_UI_URL=")]
out.append(f"CYMBAL_WEB_UI_URL={os.environ['WEB_URL']}")
env_path.write_text("\n".join(out) + "\n", encoding="utf-8")
PY
fi

echo "[6/6] Running post-deploy Cloud Run smoke & security verification..."
"${PYTHON_BIN}" "${REPO_ROOT}/scripts/smoke_test_web_ui.py" \
  --cloud-run-url="${WEB_URL}" \
  --service-name="${WEB_SERVICE}" \
  --region="${REGION}" \
  --project="${PROJECT_ID}"

echo "[OK] Cymbal Web UI deployed & verified at: ${WEB_URL}"
