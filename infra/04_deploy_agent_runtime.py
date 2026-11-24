#!/usr/bin/env python3
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

"""Packages and deploys the ADK 2.0 `App` to Vertex AI Agent Runtime (`ReasoningEngine`).

Configures:
- `identity_type="AGENT_IDENTITY"` (SPIFFE SVID hardware/platform identity, zero static keys)
- `GOOGLE_GENAI_USE_ENTERPRISE="TRUE"` & `GOOGLE_GENAI_API_TRANSPORT="rest"`
- `GOOGLE_CLOUD_AGENT_ENGINE_ENABLE_TELEMETRY="true"`
- Registers / synchronizes `scape-devx-incident-copilot` in Agent Registry (`us-central1`).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

from dotenv import load_dotenv
import vertexai
from vertexai import agent_engines
from vertexai._genai.types import common as ae_types

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

load_dotenv(REPO_ROOT / ".env")

from scape_agent.agent import app as scape_adk_app  # noqa: E402
from scape_agent.governance.gcp_auth import (  # noqa: E402
    get_gcp_credentials,
    install_local_gcloud_auth_bridge,
)

RUNTIME_REQUIREMENTS = [
    "google-adk>=2.14.0",
    "google-genai>=1.40.0",
    "google-cloud-aiplatform[adk,agent_engines]>=1.95.0",
    "google-cloud-modelarmor>=0.2.0",
    "google-cloud-firestore>=2.19.0",
    "google-cloud-bigquery>=3.27.0",
    "google-cloud-trace>=1.14.0",
    "google-auth>=2.36.0",
    "fastapi>=0.115.0",
    "httpx>=0.28.0",
    "mcp>=2.0.0",
    "pydantic>=2.10.0",
    "pyyaml>=6.0.2",
    "PyJWT>=2.10.0",
]


def _upsert_env_var(env_path: Path, key: str, value: str) -> None:
    if not env_path.is_file():
        return
    lines = env_path.read_text(encoding="utf-8").splitlines()
    filtered = [
        ln for ln in lines if not (ln.startswith(f"{key}=") and not ln.strip().startswith("#"))
    ]
    filtered.append(f"{key}={value}")
    env_path.write_text("\n".join(filtered) + "\n", encoding="utf-8")


def _register_copilot_in_agent_registry(
    project_id: str,
    location: str,
    reasoning_engine_name: str,
) -> None:
    env = dict(os.environ)
    existing_metrics = env.get("CLOUDSDK_METRICS_ENVIRONMENT", "")
    env["CLOUDSDK_METRICS_ENVIRONMENT"] = f"{existing_metrics} datacloud.antigravity".strip()

    re_url = (
        f"https://{location}-aiplatform.googleapis.com/v1beta1/{reasoning_engine_name}:streamQuery"
    )
    svc_id = "scape-devx-incident-copilot"
    subprocess.run(
        [
            "gcloud",
            "agent-registry",
            "services",
            "delete",
            svc_id,
            f"--location={location}",
            f"--project={project_id}",
            "--quiet",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    subprocess.run(
        [
            "gcloud",
            "agent-registry",
            "services",
            "create",
            svc_id,
            f"--location={location}",
            f"--project={project_id}",
            "--display-name=SCAPE DevX Incident Operations Copilot (ADK 2.0)",
            (
                "--description=ADK 2.0 Workflow copilot on Agent Runtime with SPIFFE "
                "AGENT_IDENTITY, parallel MCP fan-out, gVisor sandbox, resumable AG3 HITL, "
                "and Vertex Memory Bank."
            ),
            "--agent-spec-type=no-spec",
            f"--interfaces=protocolBinding=HTTP_JSON,url={re_url}",
            "--quiet",
        ],
        env=env,
        check=True,
    )
    print(f"[OK] Registered {svc_id} in Agent Registry ({location}).")


def main() -> int:
    project_id = os.getenv("GOOGLE_CLOUD_PROJECT", "comcast-scape")
    location = os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1")
    staging_bucket = os.getenv("SCAPE_STAGING_BUCKET", f"gs://{project_id}-{location}")
    if "<PROJECT_ID>" in staging_bucket:
        staging_bucket = f"gs://{project_id}-{location}"

    install_local_gcloud_auth_bridge(project_id)
    creds, _ = get_gcp_credentials(project_id)
    client = vertexai.Client(project=project_id, location=location, credentials=creds)

    deployable_app = agent_engines.AdkApp(
        app=scape_adk_app,
        enable_tracing=True,
    )

    env_vars = {
        "GOOGLE_GENAI_USE_ENTERPRISE": "TRUE",
        "GOOGLE_GENAI_API_TRANSPORT": "rest",
        "GOOGLE_CLOUD_AGENT_ENGINE_ENABLE_TELEMETRY": "true",
        "GEMINI_MODEL": os.getenv("GEMINI_MODEL", "gemini-3.8-flash"),
        "SCAPE_MODE": os.getenv("SCAPE_MODE", "google_native"),
        "SCAPE_BQ_DATASET": os.getenv("SCAPE_BQ_DATASET", "scape_governance"),
        "SCAPE_MCP_URL": os.getenv("SCAPE_MCP_URL", ""),
        "SCAPE_A2A_URL": os.getenv("SCAPE_A2A_URL", ""),
    }

    existing_name = ""
    for item in client.agent_engines.list():
        api_res = getattr(item, "api_resource", item)
        disp = getattr(api_res, "display_name", "") or ""
        if disp == "scape-devx-incident-copilot":
            existing_name = getattr(api_res, "name", "")
            break

    config_kwargs = {
        "display_name": "scape-devx-incident-copilot",
        "description": "ADK 2.0 DevX Platform & Incident Operations Copilot (SPIFFE AGENT_IDENTITY)",
        "staging_bucket": staging_bucket,
        "requirements": RUNTIME_REQUIREMENTS,
        "extra_packages": ["scape_agent", "services", "config"],
        "env_vars": env_vars,
        "identity_type": ae_types.IdentityType.AGENT_IDENTITY,
        "labels": {
            "platform": "scape_reference",
            "prompt_version": "v1",
            "eval_gate": "pending_optimization",
        },
    }

    os.chdir(REPO_ROOT)
    if existing_name:
        print(f"[INFO] Updating existing ReasoningEngine: {existing_name} ...")
        update_cfg = dict(config_kwargs)
        update_cfg.pop("identity_type", None)
        remote_engine = client.agent_engines.update(
            name=existing_name,
            agent=deployable_app,
            config=update_cfg,
        )
    else:
        print(
            f"[INFO] Creating ReasoningEngine in {project_id}/{location} with identity_type=AGENT_IDENTITY..."
        )
        remote_engine = client.agent_engines.create(
            agent=deployable_app,
            config=config_kwargs,
        )

    re_api = getattr(remote_engine, "api_resource", remote_engine)
    re_name = str(getattr(re_api, "name", ""))
    spec_obj = getattr(re_api, "spec", None)
    identity_val = str(
        getattr(spec_obj, "identity_type", None)
        or getattr(re_api, "identity_type", "AGENT_IDENTITY")
    )
    effective_identity = str(getattr(spec_obj, "effective_identity", "") or "")
    print(f"[OK] Deployed ReasoningEngine: {re_name} (identity_type={identity_val})")

    if effective_identity:
        principal_member = f"principal://{effective_identity}"
        env = dict(os.environ)
        existing_metrics = env.get("CLOUDSDK_METRICS_ENVIRONMENT", "")
        env["CLOUDSDK_METRICS_ENVIRONMENT"] = f"{existing_metrics} datacloud.antigravity".strip()
        for role in (
            "roles/aiplatform.user",
            "roles/datastore.user",
            "roles/bigquery.dataEditor",
            "roles/bigquery.jobUser",
            "roles/modelarmor.user",
            "roles/cloudtrace.agent",
        ):
            subprocess.run(
                [
                    "gcloud",
                    "projects",
                    "add-iam-policy-binding",
                    project_id,
                    f"--member={principal_member}",
                    f"--role={role}",
                    "--condition=None",
                    "--quiet",
                ],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
        print(f"[OK] Granted least-privilege IAM roles to SPIFFE {principal_member}.")

    _upsert_env_var(REPO_ROOT / ".env", "SCAPE_REASONING_ENGINE_NAME", re_name)
    _register_copilot_in_agent_registry(project_id, location, re_name)

    state_out = REPO_ROOT / "infra" / "manifests" / ".rendered"
    state_out.mkdir(parents=True, exist_ok=True)
    (state_out / "reasoning_engine.json").write_text(
        json.dumps(
            {
                "reasoning_engine_name": re_name,
                "identity_type": identity_val,
                "project_id": project_id,
                "location": location,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
