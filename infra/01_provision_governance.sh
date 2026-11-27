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

if [[ -f "${SCRIPT_DIR}/.runtime_state.env" ]]; then
  # shellcheck disable=SC1091
  source "${SCRIPT_DIR}/.runtime_state.env"
fi

export CLOUDSDK_METRICS_ENVIRONMENT="${CLOUDSDK_METRICS_ENVIRONMENT:+$CLOUDSDK_METRICS_ENVIRONMENT }datacloud.antigravity"

PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}}"
REGION="${GOOGLE_CLOUD_LOCATION:-${REGION:-us-central1}}"
BUCKET_URI="${CYMBAL_STAGING_BUCKET:-gs://${PROJECT_ID}-${REGION}}"
BQ_DATASET="${CYMBAL_BQ_DATASET:-cymbal_governance}"
PYTHON_BIN="${REPO_ROOT}/.venv/bin/python"
if [[ ! -x "${PYTHON_BIN}" ]]; then
  PYTHON_BIN="python3"
fi

echo "[1/5] Provisioning secure Cloud Storage staging bucket ${BUCKET_URI}..."
if ! gcloud storage buckets describe "${BUCKET_URI}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud storage buckets create "${BUCKET_URI}" \
    --project="${PROJECT_ID}" \
    --location="${REGION}" \
    --uniform-bucket-level-access \
    --public-access-prevention \
    --soft-delete-duration=7d
fi
gcloud storage buckets update "${BUCKET_URI}" \
  --project="${PROJECT_ID}" \
  --uniform-bucket-level-access \
  --public-access-prevention \
  --versioning >/dev/null

echo "[2/5] Provisioning Firestore Native (default) database & seeding Cymbal governance state..."
if ! gcloud firestore databases describe --database="(default)" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud firestore databases create \
    --database="(default)" \
    --location="${REGION}" \
    --type=firestore-native \
    --project="${PROJECT_ID}" \
    --quiet
fi

PYTHONPATH="${REPO_ROOT}" GOOGLE_CLOUD_PROJECT="${PROJECT_ID}" CYMBAL_USE_GCLOUD_CLI_AUTH=true "${PYTHON_BIN}" - <<'PY'
import datetime
import os
from google.cloud import firestore
from cymbal_agent.governance.gcp_auth import get_gcp_credentials

project_id = os.environ["GOOGLE_CLOUD_PROJECT"]
creds, _ = get_gcp_credentials(project_id)
db = firestore.Client(project=project_id, database="(default)", credentials=creds)
now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

agents_ref = db.collection("cymbal_agents")
agent_doc = agents_ref.document("agent-governance-demo")
if not agent_doc.get().exists:
    agent_doc.set(
        {
            "agent_id": "agent-governance-demo",
            "display_name": "Cymbal Core Operations & Release Agent",
            "status": "ACTIVE",
            "risk_tier": "AG3",
            "intake_id": "ATLAS-2026-0841",
            "cmdb_app_id": "SVC-CYMBAL-992",
            "behavior_score": 96.2,
            "active_prompt_version": "v2",
            "eval_gate": "passed",
            "updated_at": now_iso,
        }
    )

wallets_ref = db.collection("cymbal_wallets")
wallet_doc = wallets_ref.document("wallet-cymbal-ops")
if not wallet_doc.get().exists:
    wallet_doc.set(
        {
            "wallet_id": "wallet-cymbal-ops",
            "org": "cymbal-communications",
            "account": "core-ops-release",
            "monthly_cap_nano_usd": 15_000_000_000,
            "spent_nano_usd": 0,
            "reserved_nano_usd": 0,
            "resolved_incidents_count": 0,
            "currency": "NANO_USD",
            "status": "ACTIVE",
            "updated_at": now_iso,
        }
    )
print("[OK] Firestore cymbal_agents and cymbal_wallets verified.")
PY

echo "[3/5] Provisioning BigQuery dataset ${PROJECT_ID}:${BQ_DATASET} and governance tables..."
PYTHONPATH="${REPO_ROOT}" GOOGLE_CLOUD_PROJECT="${PROJECT_ID}" CYMBAL_BQ_DATASET="${BQ_DATASET}" CYMBAL_REGION="${REGION}" CYMBAL_USE_GCLOUD_CLI_AUTH=true "${PYTHON_BIN}" - <<'PY'
import os
from google.cloud import bigquery
from cymbal_agent.governance.gcp_auth import get_gcp_credentials

project_id = os.environ["GOOGLE_CLOUD_PROJECT"]
dataset_id = os.environ["CYMBAL_BQ_DATASET"]
region = os.environ["CYMBAL_REGION"]

creds, _ = get_gcp_credentials(project_id)
client = bigquery.Client(project=project_id, credentials=creds)
ds_ref = bigquery.Dataset(f"{project_id}.{dataset_id}")
ds_ref.location = region
ds_ref.labels = {"datacloud": "antigravity", "component": "cymbal_governance"}
client.create_dataset(ds_ref, exists_ok=True)

wallet_schema = [
    bigquery.SchemaField("event_id", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("created_at", "TIMESTAMP", mode="REQUIRED"),
    bigquery.SchemaField("org", "STRING"),
    bigquery.SchemaField("account", "STRING"),
    bigquery.SchemaField("agent_id", "STRING"),
    bigquery.SchemaField("wallet_id", "STRING"),
    bigquery.SchemaField("session_id", "STRING"),
    bigquery.SchemaField("trace_id", "STRING"),
    bigquery.SchemaField("architecture_mode", "STRING"),
    bigquery.SchemaField("model_id", "STRING"),
    bigquery.SchemaField("input_tokens", "INT64"),
    bigquery.SchemaField("output_tokens", "INT64"),
    bigquery.SchemaField("model_cost_nano_usd", "INT64"),
    bigquery.SchemaField("guardrail_cost_nano_usd", "INT64"),
    bigquery.SchemaField("total_cost_nano_usd", "INT64"),
    bigquery.SchemaField("outcome", "STRING"),
    bigquery.SchemaField("incident_id", "STRING"),
    bigquery.SchemaField("cost_per_resolved_incident_nano_usd", "INT64"),
]
wallet_table = bigquery.Table(f"{project_id}.{dataset_id}.wallet_ledger", schema=wallet_schema)
wallet_table.labels = {"datacloud": "antigravity"}
client.create_table(wallet_table, exists_ok=True)

audit_schema = [
    bigquery.SchemaField("audit_id", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("created_at", "TIMESTAMP", mode="REQUIRED"),
    bigquery.SchemaField("trace_id", "STRING"),
    bigquery.SchemaField("session_id", "STRING"),
    bigquery.SchemaField("agent_id", "STRING"),
    bigquery.SchemaField("direction", "STRING"),
    bigquery.SchemaField("template_id", "STRING"),
    bigquery.SchemaField("filter_match_state", "STRING"),
    bigquery.SchemaField("invocation_result", "STRING"),
    bigquery.SchemaField("action_taken", "STRING"),
    bigquery.SchemaField("pii_masked", "BOOL"),
    bigquery.SchemaField("malicious_uri_detected", "BOOL"),
    bigquery.SchemaField("injection_detected", "BOOL"),
    bigquery.SchemaField("latency_ms", "FLOAT64"),
    bigquery.SchemaField("summary", "STRING"),
]
audit_table = bigquery.Table(f"{project_id}.{dataset_id}.guardrail_audit_logs", schema=audit_schema)
audit_table.labels = {"datacloud": "antigravity"}
client.create_table(audit_table, exists_ok=True)
print("[OK] BigQuery tables wallet_ledger and guardrail_audit_logs verified.")
PY

echo "[4/5] Provisioning fail-closed Model Armor GPP templates & Global Floor Settings in ${REGION}..."
export CLOUDSDK_API_ENDPOINT_OVERRIDES_MODELARMOR="https://modelarmor.${REGION}.rep.googleapis.com/"
create_or_update_ma_template() {
  local tpl_id="$1"
  local confidence="$2"
  local dangerous_conf="${3:-HIGH}"
  local rai_json="[{\"filterType\":\"HATE_SPEECH\",\"confidenceLevel\":\"${confidence}\"},{\"filterType\":\"HARASSMENT\",\"confidenceLevel\":\"${confidence}\"},{\"filterType\":\"SEXUALLY_EXPLICIT\",\"confidenceLevel\":\"${confidence}\"},{\"filterType\":\"DANGEROUS\",\"confidenceLevel\":\"${dangerous_conf}\"}]"

  if gcloud model-armor templates describe "${tpl_id}" --location="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    gcloud model-armor templates update "${tpl_id}" \
      --location="${REGION}" \
      --project="${PROJECT_ID}" \
      --malicious-uri-filter-settings-enforcement=enabled \
      --basic-config-filter-enforcement=enabled \
      --pi-and-jailbreak-filter-settings-enforcement=enabled \
      --pi-and-jailbreak-filter-settings-confidence-level="${confidence}" \
      --rai-settings-filters="${rai_json}" \
      --template-metadata-log-operations \
      --template-metadata-log-sanitize-operations \
      --quiet >/dev/null
  else
    gcloud model-armor templates create "${tpl_id}" \
      --location="${REGION}" \
      --project="${PROJECT_ID}" \
      --malicious-uri-filter-settings-enforcement=enabled \
      --basic-config-filter-enforcement=enabled \
      --pi-and-jailbreak-filter-settings-enforcement=enabled \
      --pi-and-jailbreak-filter-settings-confidence-level="${confidence}" \
      --rai-settings-filters="${rai_json}" \
      --template-metadata-log-operations \
      --template-metadata-log-sanitize-operations \
      --labels="policy_tier=gpp,managed_by=cymbal_reference" \
      --quiet >/dev/null
  fi
  echo "[OK] Model Armor template ${tpl_id} (${confidence}, fail-closed) ready."
}

create_or_update_ma_template "cymbal-low-baseline-gpp" "MEDIUM_AND_ABOVE" "HIGH"
create_or_update_ma_template "cymbal-default-medium-gpp" "MEDIUM_AND_ABOVE" "MEDIUM_AND_ABOVE"
create_or_update_ma_template "cymbal-strict-ag3-gpp" "LOW_AND_ABOVE" "MEDIUM_AND_ABOVE"

if [[ -f "${REPO_ROOT}/.env" ]]; then
  PROJECT_ID="${PROJECT_ID}" REGION="${REGION}" REPO_ROOT="${REPO_ROOT}" "${PYTHON_BIN}" - <<'PY'
import os
from pathlib import Path

env_path = Path(os.environ["REPO_ROOT"]) / ".env"
low_tpl = (
    f"projects/{os.environ['PROJECT_ID']}/locations/{os.environ['REGION']}/"
    "templates/cymbal-low-baseline-gpp"
)
lines = env_path.read_text(encoding="utf-8").splitlines()
out = [
    ln
    for ln in lines
    if not (ln.startswith("CYMBAL_MODEL_ARMOR_LOW_TEMPLATE=") and not ln.strip().startswith("#"))
]
out.append(f"CYMBAL_MODEL_ARMOR_LOW_TEMPLATE={low_tpl}")
env_path.write_text("\n".join(out) + "\n", encoding="utf-8")
PY
fi

CLOUDSDK_API_ENDPOINT_OVERRIDES_MODELARMOR="https://modelarmor.googleapis.com/" gcloud model-armor floorsettings update \
  --full-uri="projects/${PROJECT_ID}/locations/global/floorSetting" \
  --enable-floor-setting-enforcement=TRUE \
  --malicious-uri-filter-settings-enforcement=enabled \
  --basic-config-filter-enforcement=enabled \
  --pi-and-jailbreak-filter-settings-enforcement=enabled \
  --pi-and-jailbreak-filter-settings-confidence-level=MEDIUM_AND_ABOVE \
  --rai-settings-filters='[{"filterType":"HATE_SPEECH","confidenceLevel":"MEDIUM_AND_ABOVE"},{"filterType":"HARASSMENT","confidenceLevel":"MEDIUM_AND_ABOVE"},{"filterType":"SEXUALLY_EXPLICIT","confidenceLevel":"MEDIUM_AND_ABOVE"},{"filterType":"DANGEROUS","confidenceLevel":"HIGH"}]' \
  --project="${PROJECT_ID}" \
  --quiet >/dev/null

echo "[OK] Model Armor Global Floor Settings enforced on ${PROJECT_ID}."

echo "[5/5] Provisioning cymbal-vpc, /26 PSC-I subnet (10.10.1.0/26), and NetworkAttachment..."
if ! gcloud compute networks describe cymbal-vpc --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud compute networks create cymbal-vpc \
    --project="${PROJECT_ID}" \
    --subnet-mode=custom \
    --quiet
fi

if ! gcloud compute networks subnets describe cymbal-psci-subnet --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud compute networks subnets create cymbal-psci-subnet \
    --project="${PROJECT_ID}" \
    --network=cymbal-vpc \
    --region="${REGION}" \
    --range="10.10.1.0/26" \
    --purpose=PRIVATE \
    --enable-private-ip-google-access \
    --quiet
fi

if ! gcloud compute network-attachments describe cymbal-psci-attachment --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud compute network-attachments create cymbal-psci-attachment \
    --project="${PROJECT_ID}" \
    --region="${REGION}" \
    --connection-preference=ACCEPT_AUTOMATIC \
    --subnets=cymbal-psci-subnet \
    --description="PSC-Interface attachment for Agent Runtime & Agent Gateway" \
    --quiet
fi

echo "[OK] Phase 1 Core Governance Infrastructure provisioned in ${PROJECT_ID} (${REGION})."
