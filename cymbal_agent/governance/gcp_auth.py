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

"""Zero-secret Google Cloud credential resolver with in-memory token caching.

In Cloud Run and Vertex AI Agent Runtime (`AGENT_IDENTITY` SPIFFE / metadata
server), `google.auth.default()` resolves hardware/platform-minted credentials
automatically with zero static keys.

On developer workstations where Application Default Credentials (`ADC`) may be
bound to a separate corporate identity while the active `gcloud` CLI session is
authenticated to the target sandbox project, this module caches an in-memory
`google.auth.credentials.Credentials` token refreshed via `gcloud` before gRPC
channels open, avoiding repeated subprocess forks during server requests.
"""

from __future__ import annotations

import datetime
import os
import shutil
import subprocess
from typing import Any

os.environ.setdefault("GRPC_VERBOSITY", "ERROR")
os.environ.setdefault("GRPC_ENABLE_FORK_SUPPORT", "0")

import google.auth  # noqa: E402
from google.auth.credentials import Credentials  # noqa: E402

_PATCHED_DEFAULT = False
_ORIG_GOOGLE_AUTH_DEFAULT = google.auth.default
_SHARED_TOKEN_STATE: dict[str, Any] = {
    "token": None,
    "expiry": None,
}
_CREDENTIAL_CACHE: dict[str, GcloudCliRefreshingCredentials] = {}


def is_cloud_managed_runtime() -> bool:
    """Returns True when executing inside Cloud Run, Agent Engine, or GCE."""
    return bool(
        os.getenv("K_SERVICE")
        or os.getenv("GOOGLE_CLOUD_AGENT_ENGINE_ID")
        or os.getenv("CLOUD_RUN_JOB")
    )


def _token_still_fresh() -> bool:
    tok = _SHARED_TOKEN_STATE.get("token")
    exp = _SHARED_TOKEN_STATE.get("expiry")
    if not tok or not isinstance(exp, datetime.datetime):
        return False
    now_naive_utc = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    return (exp - now_naive_utc) > datetime.timedelta(minutes=5)


class GcloudCliRefreshingCredentials(Credentials):
    """In-memory credentials sharing a cached gcloud OAuth access token."""

    def __init__(
        self,
        quota_project_id: str | None = None,
        *,
        token: str | None = None,
        expiry: datetime.datetime | None = None,
    ) -> None:
        super().__init__()
        self._quota_project_id = quota_project_id
        if token and expiry:
            self.token = token
            self.expiry = expiry
        elif _token_still_fresh():
            self.token = _SHARED_TOKEN_STATE["token"]
            self.expiry = _SHARED_TOKEN_STATE["expiry"]
        else:
            self.refresh(None)

    @property
    def quota_project_id(self) -> str | None:
        return self._quota_project_id

    def with_quota_project(self, quota_project_id: str | None) -> GcloudCliRefreshingCredentials:
        return GcloudCliRefreshingCredentials(
            quota_project_id=quota_project_id,
            token=self.token,
            expiry=self.expiry,
        )

    def with_scopes_if_required(self, scopes: Any) -> GcloudCliRefreshingCredentials:
        del scopes
        return self

    def refresh(self, request: Any) -> None:
        del request
        if _token_still_fresh():
            self.token = _SHARED_TOKEN_STATE["token"]
            self.expiry = _SHARED_TOKEN_STATE["expiry"]
            return

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
        expiry = datetime.datetime.now(datetime.timezone.utc).replace(
            tzinfo=None
        ) + datetime.timedelta(minutes=45)
        _SHARED_TOKEN_STATE["token"] = token
        _SHARED_TOKEN_STATE["expiry"] = expiry
        self.token = token
        self.expiry = expiry


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

    force_cli = (
        os.getenv("CYMBAL_USE_GCLOUD_CLI_AUTH")
        or os.getenv("SCAPE_USE_GCLOUD_CLI_AUTH")
        or ""
    ).lower() in {"1", "true", "yes"}
    if not force_cli:
        try:
            creds, adc_project = _ORIG_GOOGLE_AUTH_DEFAULT()
            adc_quota = getattr(creds, "quota_project_id", None)
            if not resolved_project or (adc_quota and adc_quota == resolved_project):
                return creds, resolved_project or (adc_project or "")
        except Exception:
            pass

    cache_key = resolved_project or "__default__"
    cached = _CREDENTIAL_CACHE.get(cache_key)
    if cached is not None and _token_still_fresh():
        cached.token = _SHARED_TOKEN_STATE["token"]
        cached.expiry = _SHARED_TOKEN_STATE["expiry"]
        return cached, resolved_project

    if shutil.which("gcloud"):
        cli_creds = GcloudCliRefreshingCredentials(
            quota_project_id=resolved_project or None
        )
        _CREDENTIAL_CACHE[cache_key] = cli_creds
        return cli_creds, resolved_project

    creds, adc_project = _ORIG_GOOGLE_AUTH_DEFAULT(
        quota_project_id=resolved_project or None
    )
    return creds, resolved_project or (adc_project or "")


def probe_local_gcp_credentials(project_id: str | None = None) -> tuple[bool, str]:
    """Verifies whether usable GCP credentials exist before binding live gRPC clients."""
    if is_cloud_managed_runtime():
        return True, "cloud_managed_iam"
    resolved_project = (
        project_id
        or os.getenv("GOOGLE_CLOUD_PROJECT")
        or os.getenv("GCLOUD_PROJECT")
        or ""
    )
    try:
        creds, _ = get_gcp_credentials(resolved_project or None)
        if getattr(creds, "token", None):
            return True, "gcloud_cli_token"
        adc_quota = getattr(creds, "quota_project_id", None)
        if adc_quota and (not resolved_project or adc_quota == resolved_project):
            return True, "adc_matching_project"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    return False, "No active gcloud token or matching ADC quota_project_id"


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
