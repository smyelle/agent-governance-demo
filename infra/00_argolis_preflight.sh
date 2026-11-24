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

PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-$(gcloud config get-value project 2>/dev/null || true)}"
REGION="${GOOGLE_CLOUD_LOCATION:-us-central1}"

if [[ -z "${PROJECT_ID}" || "${PROJECT_ID}" == "(unset)" ]]; then
  echo "[ERROR] GOOGLE_CLOUD_PROJECT is not set. Configure .env or run gcloud config set project <PROJECT_ID>." >&2
  exit 1
fi

ACTIVE_ACCOUNT="$(gcloud auth list --filter=status:ACTIVE --format='value(account)' | head -n 1)"
if [[ -z "${ACTIVE_ACCOUNT}" ]]; then
  echo "[ERROR] No active gcloud account detected. Run gcloud auth login first." >&2
  exit 1
fi
echo "[INFO] Authenticated gcloud principal verified: ${ACTIVE_ACCOUNT}"

if ! gcloud projects describe "${PROJECT_ID}" >/dev/null 2>&1; then
  echo "[INFO] Creating GCP project ${PROJECT_ID}..."
  gcloud projects create "${PROJECT_ID}" --name="${PROJECT_ID}" --quiet
fi

gcloud config set project "${PROJECT_ID}" --quiet >/dev/null
gcloud config set api_endpoint_overrides/modelarmor "https://modelarmor.${REGION}.rep.googleapis.com/" --quiet >/dev/null

BILLING_ENABLED="$(gcloud billing projects describe "${PROJECT_ID}" --format='value(billingEnabled)' 2>/dev/null || echo 'False')"
if [[ "${BILLING_ENABLED}" != "True" && "${BILLING_ENABLED}" != "true" ]]; then
  OPEN_BILLING_ACCOUNT="$(gcloud billing accounts list --filter='open=true' --format='value(ACCOUNT_ID)' | head -n 1)"
  if [[ -n "${OPEN_BILLING_ACCOUNT}" ]]; then
    echo "[INFO] Linking billing account ${OPEN_BILLING_ACCOUNT} to ${PROJECT_ID}..."
    gcloud billing projects link "${PROJECT_ID}" --billing-account="${OPEN_BILLING_ACCOUNT}" --quiet
  else
    echo "[WARN] Billing is not enabled on ${PROJECT_ID} and no open billing account was found automatically." >&2
  fi
else
  echo "[INFO] Billing already enabled on ${PROJECT_ID}."
fi

PROJECT_NUMBER="$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')"
ORG_ID="$(gcloud projects get-ancestors "${PROJECT_ID}" --format='json' | python3 -c "import json,sys; data=json.load(sys.stdin); orgs=[x['id'] for x in data if x.get('type')=='organization']; print(orgs[0] if orgs else '')")"

echo "[INFO] Enabling required Google Cloud & Agent Platform APIs on ${PROJECT_ID} (${REGION})..."
gcloud services enable \
  cloudresourcemanager.googleapis.com \
  serviceusage.googleapis.com \
  aiplatform.googleapis.com \
  agentregistry.googleapis.com \
  agentidentity.googleapis.com \
  networkservices.googleapis.com \
  networksecurity.googleapis.com \
  iap.googleapis.com \
  modelarmor.googleapis.com \
  dlp.googleapis.com \
  compute.googleapis.com \
  dns.googleapis.com \
  --project="${PROJECT_ID}" \
  --quiet

gcloud services enable \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  bigquery.googleapis.com \
  firestore.googleapis.com \
  cloudtrace.googleapis.com \
  logging.googleapis.com \
  sts.googleapis.com \
  iamcredentials.googleapis.com \
  orgpolicy.googleapis.com \
  storage.googleapis.com \
  --project="${PROJECT_ID}" \
  --quiet

gcloud auth application-default set-quota-project "${PROJECT_ID}" --quiet >/dev/null 2>&1 || true

echo "[INFO] Checking project-level Cloud Run ingress policy (IAM authentication stays enforced)..."
if gcloud org-policies describe run.allowedIngress --project="${PROJECT_ID}" --effective >/dev/null 2>&1; then
  INGRESS_RESTRICTED="$(gcloud org-policies describe run.allowedIngress --project="${PROJECT_ID}" --effective --format='json' | python3 -c "import json,sys; d=json.load(sys.stdin); vals=[]; [vals.extend(r.get('values',{}).get('allowedValues',[])) for r in d.get('spec',{}).get('rules',[])]; print('restricted' if vals and 'all' not in [v.lower() for v in vals] else 'ok')")"
  if [[ "${INGRESS_RESTRICTED}" == "restricted" ]]; then
    echo "[INFO] Relaxing run.allowedIngress at project scope so IAM-authenticated Cloud Run endpoints are reachable..."
    cat > /tmp/scape_run_ingress_policy.yaml <<EOF
name: projects/${PROJECT_ID}/policies/run.allowedIngress
spec:
  rules:
  - allowAll: true
EOF
    gcloud org-policies set-policy /tmp/scape_run_ingress_policy.yaml --project="${PROJECT_ID}" >/dev/null 2>&1 || true
    rm -f /tmp/scape_run_ingress_policy.yaml
  fi
fi

cat > "${SCRIPT_DIR}/.runtime_state.env" <<EOF
PROJECT_ID=${PROJECT_ID}
PROJECT_NUMBER=${PROJECT_NUMBER}
ORG_ID=${ORG_ID}
REGION=${REGION}
EOF

echo "[OK] Preflight complete for project=${PROJECT_ID} (region=${REGION})."
