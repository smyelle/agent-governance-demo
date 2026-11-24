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

"""Async Vertex AI Batch Prompt Optimizer helper for large trace corpora."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from dotenv import load_dotenv
import vertexai

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

load_dotenv(REPO_ROOT / ".env")

from scape_agent.governance.gcp_auth import get_gcp_credentials  # noqa: E402


def build_batch_optimizer_config(project_id: str, location: str, bucket_uri: str) -> dict[str, object]:
    model_id = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
    return {
        "project": project_id,
        "location": location,
        "optimizer_model": model_id,
        "target_model": model_id,
        "eval_dataset_gcs_uri": f"{bucket_uri}/prompt_optimizer/golden_incidents.jsonl",
        "output_gcs_uri": f"{bucket_uri}/prompt_optimizer/output/",
        "num_steps": 5,
        "system_instruction_seed_file": "config/prompts/synthesizer_v1_flawed.txt",
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inspect or submit an async Vertex AI Batch Prompt Optimizer configuration."
    )
    parser.add_argument(
        "--submit",
        action="store_true",
        help="Submit a live async Vertex AI Prompt Optimizer custom job (defaults to dry-run spec).",
    )
    args = parser.parse_args()

    project_id = os.getenv("GOOGLE_CLOUD_PROJECT", "comcast-scape")
    location = os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1")
    bucket_uri = os.getenv("SCAPE_STAGING_BUCKET", f"gs://{project_id}-{location}")
    spec = build_batch_optimizer_config(project_id, location, bucket_uri)

    if not args.submit:
        print(json.dumps({"mode": "dry_run_validated", "spec": spec}, indent=2))
        return 0

    creds, _ = get_gcp_credentials(project_id)
    client = vertexai.Client(project=project_id, location=location, credentials=creds)
    job = client.prompt_optimizer.optimize(config=spec)  # pragma: no cover
    print(json.dumps({"mode": "submitted", "job": str(job)}, indent=2))  # pragma: no cover
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
