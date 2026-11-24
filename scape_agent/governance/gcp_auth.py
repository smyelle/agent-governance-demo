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

"""Zero-secret Google Cloud credential resolver.

In Cloud Run and Vertex AI Agent Runtime (`AGENT_IDENTITY` SPIFFE / metadata
server), `google.auth.default()` resolves hardware/platform-minted credentials
automatically with zero static keys.

On developer workstations where Application Default Credentials (`ADC`) may be
bound to a separate corporate identity while the active `gcloud` CLI session is
authenticated to the target sandbox project, this module provides an in-memory
refreshing `google.auth.credentials.Credentials` implementation backed by
`gcloud auth print-access-token` without modifying any files on disk.
"""

from __future__ import annotations

import datetime
import os
import shutil
import subprocess
from typing import Any

import google.auth
from google.auth.credentials import Credentials

_PATCHED_DEFAULT = False
_ORIG_GOOGLE_AUTH_DEFAULT = google.auth.default


def is_cloud_managed_runtime() -> bool:
    """Returns True when executing inside Cloud Run, Agent Engine, or GCE."""
    return bool(
        os.getenv("K_SERVICE")
        or os.getenv("GOOGLE_CLOUD_AGENT_ENGINE_ID")
        or os.getenv("CLOUD_RUN_JOB")
    )


class GcloudCliRefreshingCredentials(Credentials):
    """In-memory credentials refreshed dynamically via the active gcloud CLI."""

    def __init__(self, quota_project_id: str | None = None) -> None:
        super().__init__()
        self._quota_project_id = quota_project_id
        self.refresh(None)

    @property
    def quota_project_id(self) -> str | None:
        return self._quota_project_id

    def with_quota_project(self, quota_project_id: str | None) -> GcloudCliRefreshingCredentials:
        clone = GcloudCliRefreshingCredentials(quota_project_id=quota_project_id)
        return clone

    def refresh(self, request: Any) -> None:
        gcloud_bin = shutil.which("gcloud")
        if not gcloud_bin:
            raise RuntimeError("gcloud CLI binary not found in PATH.")
        env = dict(os.environ)
        existing_metrics = env.get("CLOUDSDK_METRICS_ENVIRONMENT", "")
        env["CLOUDSDK_METRICS_ENVIRONMENT"] = (
            f"{existing_metrics} datacloud.antigravity".strip()
        )
        proc = subprocess.run(
            [gcloud_bin, "auth", "print-access-token", "--quiet"],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
            env=env,
        )
        token = proc.stdout.strip()
        if not token:
            raise RuntimeError("Empty access token returned by gcloud CLI.")
        self.token = token
        self.expiry = datetime.datetime.now(datetime.timezone.utc).replace(
            tzinfo=None
        ) + datetime.timedelta(minutes=45)


def get_gcp_credentials(project_id: str | None = None) -> tuple[Credentials, str]:
    """Resolves credentials safely across managed cloud runtimes and local CLI."""
    resolved_project = (
        project_id
        or os.getenv("GOOGLE_CLOUD_PROJECT")
        or os.getenv("GCLOUD_PROJECT")
        or ""
    )

    if is_cloud_managed_runtime():
        creds, adc_project = _ORIG_GOOGLE_AUTH_DEFAULT(
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
            quota_project_id=resolved_project or None,
        )
        return creds, resolved_project or (adc_project or "")

    force_cli = os.getenv("SCAPE_USE_GCLOUD_CLI_AUTH", "").lower() in {
        "1",
        "true",
        "yes",
    }
    if not force_cli:
        try:
            creds, adc_project = _ORIG_GOOGLE_AUTH_DEFAULT()
            adc_quota = getattr(creds, "quota_project_id", None)
            if (
                not resolved_project
                or adc_quota == resolved_project
                or adc_project == resolved_project
            ):
                return creds, resolved_project or (adc_project or "")
        except Exception:
            pass

    if shutil.which("gcloud"):
        try:
            cli_creds = GcloudCliRefreshingCredentials(
                quota_project_id=resolved_project or None
            )
            return cli_creds, resolved_project
        except Exception:
            pass

    creds, adc_project = _ORIG_GOOGLE_AUTH_DEFAULT(
        quota_project_id=resolved_project or None
    )
    return creds, resolved_project or (adc_project or "")


def install_local_gcloud_auth_bridge(project_id: str | None = None) -> None:
    """Installs an in-process google.auth.default bridge for local CLI runs only."""
    global _PATCHED_DEFAULT
    if _PATCHED_DEFAULT or is_cloud_managed_runtime():
        return

    target_project = project_id or os.getenv("GOOGLE_CLOUD_PROJECT")

    def _patched_default(
        scopes: Any = None,
        request: Any = None,
        quota_project_id: str | None = None,
        default_scopes: Any = None,
    ) -> tuple[Credentials, str | None]:
        try:
            creds, proj = get_gcp_credentials(quota_project_id or target_project)
            if scopes and hasattr(creds, "with_scopes_if_required"):
                creds = creds.with_scopes_if_required(scopes)
            return creds, proj or target_project
        except Exception:
            return _ORIG_GOOGLE_AUTH_DEFAULT(
                scopes=scopes,
                request=request,
                quota_project_id=quota_project_id,
                default_scopes=default_scopes,
            )

    google.auth.default = _patched_default
    _PATCHED_DEFAULT = True
