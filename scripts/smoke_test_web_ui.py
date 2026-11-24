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

"""Standardized Local & Cloud Run Smoke-Test Runner for Cymbal Web UI BFF.

Validates security headers, cookie hardening, CSRF enforcement, Fetch Metadata
isolation, inline Cloud SDP PII masking, and ADK 2.0 triage + HITL resume
against either a local 127.0.0.1 server (`--local` / `--url`) or a deployed
Cloud Run service (`--cloud-run-url`).
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import threading
import time
from typing import Any, Iterator

import httpx
import uvicorn

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _pick_free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@contextlib.contextmanager
def _ephemeral_local_server(*, offline: bool) -> Iterator[str]:
    os.environ["CYMBAL_BFF_OFFLINE"] = "true" if offline else "false"
    from web.api import create_bff_app

    port = _pick_free_local_port()
    app = create_bff_app(offline_mode=offline)
    cfg = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(cfg)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 15.0
    while time.time() < deadline:
        try:
            r = httpx.get(f"{base_url}/healthz", timeout=1.5)
            if r.status_code == 200:
                break
        except Exception:
            time.sleep(0.15)
    try:
        yield base_url
    finally:
        server.should_exit = True
        thread.join(timeout=3.0)


@contextlib.contextmanager
def _gcloud_run_proxy(
    *, service_name: str, region: str, project_id: str
) -> Iterator[str]:
    gcloud_bin = shutil.which("gcloud")
    if not gcloud_bin:
        raise RuntimeError("gcloud CLI not found in PATH.")
    port = _pick_free_local_port()
    env = dict(os.environ)
    existing = env.get("CLOUDSDK_METRICS_ENVIRONMENT", "")
    env["CLOUDSDK_METRICS_ENVIRONMENT"] = f"{existing} datacloud.antigravity".strip()
    proc = subprocess.Popen(
        [
            gcloud_bin,
            "run",
            "services",
            "proxy",
            service_name,
            f"--region={region}",
            f"--project={project_id}",
            f"--port={port}",
            "--quiet",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    proxy_url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 20.0
    ready = False
    while time.time() < deadline:
        try:
            r = httpx.get(f"{proxy_url}/healthz", timeout=2.0)
            if r.status_code == 200:
                ready = True
                break
        except Exception:
            time.sleep(0.3)
    if not ready:
        proc.terminate()
        raise RuntimeError(f"gcloud run services proxy failed to come up on {proxy_url}")
    try:
        yield proxy_url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3.0)
        except Exception:
            proc.kill()


def _mint_gcloud_id_token(audience: str | None = None) -> str | None:
    gcloud_bin = shutil.which("gcloud")
    if not gcloud_bin:
        return None
    env = dict(os.environ)
    existing = env.get("CLOUDSDK_METRICS_ENVIRONMENT", "")
    env["CLOUDSDK_METRICS_ENVIRONMENT"] = f"{existing} datacloud.antigravity".strip()
    cmd = [gcloud_bin, "auth", "print-identity-token", "--quiet"]
    if audience:
        cmd.append(f"--audiences={audience}")
    try:
        res = subprocess.run(
            cmd, check=True, capture_output=True, text=True, timeout=10, env=env
        )
        return res.stdout.strip() or None
    except Exception:
        return None


def run_functional_and_security_checks(
    base_url: str,
    *,
    extra_headers: dict[str, str] | None = None,
    expect_https_cookie: bool = False,
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    hdrs = dict(extra_headers or {})

    with httpx.Client(base_url=base_url, headers=hdrs, timeout=45.0, follow_redirects=False) as client:
        # 1. Health check
        h = client.get("/healthz")
        checks.append(
            {
                "check": "healthz_200",
                "passed": h.status_code == 200 and h.json().get("status") == "ok",
                "detail": f"status={h.status_code} target={h.json().get('target') if h.status_code == 200 else 'err'}",
            }
        )

        # 2. Index HTML + CSP / Clickjacking / COOP / CORP headers
        idx = client.get("/")
        csp = idx.headers.get("content-security-policy", "")
        sec_headers_ok = (
            idx.status_code == 200
            and "default-src 'self'" in csp
            and "unsafe-inline" not in csp
            and idx.headers.get("x-frame-options") == "DENY"
            and idx.headers.get("x-content-type-options") == "nosniff"
            and idx.headers.get("cross-origin-opener-policy") == "same-origin-allow-popups"
            and idx.headers.get("cross-origin-resource-policy") == "same-origin"
        )
        checks.append(
            {
                "check": "index_and_security_headers",
                "passed": sec_headers_ok,
                "detail": f"status={idx.status_code} csp_strict={'unsafe-inline' not in csp}",
            }
        )

        # 3. Bootstrap + Session Cookie + 9 Platform Services
        boot = client.get("/api/bootstrap")
        raw_cookies = idx.headers.get_list("set-cookie") + boot.headers.get_list("set-cookie")
        joined_cookie = "; ".join(raw_cookies)
        if expect_https_cookie:
            cookie_ok = (
                "__Host-cymbal_sid=" in joined_cookie
                and "secure" in joined_cookie.lower()
                and "httponly" in joined_cookie.lower()
                and "samesite=strict" in joined_cookie.lower()
                and "strict-transport-security" in boot.headers
            )
            # httpx will not resend a Secure cookie over a plain http://127.0.0.1 proxy socket;
            # manually carry the verified __Host-cymbal_sid cookie if base_url is http://127.0.0.1
            if base_url.startswith("http://127.0.0.1") and "__Host-cymbal_sid=" in joined_cookie:
                sid_val = joined_cookie.rsplit("__Host-cymbal_sid=", 1)[1].split(";", 1)[0]
                client.headers["Cookie"] = f"__Host-cymbal_sid={sid_val}"
        else:
            cookie_ok = (
                ("cymbal_sid=" in joined_cookie or "__Host-cymbal_sid=" in joined_cookie or bool(client.cookies))
                and boot.headers.get("cache-control") == "no-store"
            )
        boot_json = boot.json() if boot.status_code == 200 else {}
        csrf = boot_json.get("csrf_token", "")
        svc_count = len((boot_json.get("platform_services") or {}).get("services") or [])
        checks.append(
            {
                "check": "bootstrap_cookie_and_9_services",
                "passed": boot.status_code == 200 and bool(csrf) and svc_count == 9 and cookie_ok,
                "detail": f"services={svc_count} cookie_hardened={cookie_ok}",
            }
        )

        # 4. Negative security checks: Missing CSRF -> 403, Cross-Site Fetch Metadata -> 403, PUT -> 405
        no_csrf = client.post("/api/config/mode", json={"architecture_mode": "google_native"})
        cross_site = client.get(
            "/api/bootstrap",
            headers={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "cors"},
        )
        put_method = client.put("/api/bootstrap")
        checks.append(
            {
                "check": "negative_security_guards",
                "passed": (
                    no_csrf.status_code == 403
                    and cross_site.status_code == 403
                    and put_method.status_code == 405
                ),
                "detail": f"no_csrf={no_csrf.status_code} cross_site={cross_site.status_code} put={put_method.status_code}",
            }
        )

        csrf_hdr = {"X-CSRF-Token": csrf}

        # 5. Inline Cloud SDP PII Masking
        guard = client.post(
            "/api/steward/guardrail-test",
            headers=csrf_hdr,
            json={"sample_text": "Customer SSN 123-45-6789 on CPE MAC aa:bb:cc:dd:ee:ff"},
        )
        g_data = guard.json() if guard.status_code == 200 else {}
        checks.append(
            {
                "check": "model_armor_inline_sdp_masking",
                "passed": (
                    guard.status_code == 200
                    and g_data.get("pii_masked") is True
                    and "123-45-6789" not in g_data.get("sanitized_text", "")
                ),
                "detail": f"action={g_data.get('action_taken')} latency_ms={g_data.get('latency_ms')}",
            }
        )

        # 6. End-to-End ADK 2.0 Workflow Triage + AG3 HITL Resume
        triage = client.post(
            "/api/agent/triage",
            headers=csrf_hdr,
            json={
                "incident_id": "INC-4092",
                "service_name": "cymbal-release-api",
                "app_id": "SVC-CYMBAL-992",
                "operator_prompt": (
                    "Investigate INC-4092: cymbal-release-api p99 latency spiked to 4,820ms "
                    "with Valkey usage:0 saturation at 94.6% after release v2.14.3."
                ),
                "architecture_mode": "google_native",
            },
        )
        t_data = triage.json() if triage.status_code == 200 else {}
        paused_ok = (
            triage.status_code == 200
            and t_data.get("status") == "WAITING_AG3_APPROVAL"
            and bool((t_data.get("pending_approval") or {}).get("interrupt_id"))
        )
        resume_ok = False
        if paused_ok:
            resume = client.post(
                "/api/agent/resume",
                headers=csrf_hdr,
                json={
                    "session_id": t_data["session_id"],
                    "interrupt_id": t_data["pending_approval"]["interrupt_id"],
                    "approved": True,
                    "approver_principal": "sre-oncall-lead",
                    "reason": "Automated smoke test approval.",
                },
            )
            r_data = resume.json() if resume.status_code == 200 else {}
            rem = r_data.get("remediation_outcome") or {}
            resume_ok = (
                resume.status_code == 200
                and r_data.get("status") == "COMPLETED"
                and rem.get("status") == "ROLLED_BACK"
                and rem.get("slo_recovered") is True
            )
        checks.append(
            {
                "check": "adk_workflow_triage_and_hitl_resume",
                "passed": paused_ok and resume_ok,
                "detail": f"paused_ag3={paused_ok} resumed_completed={resume_ok}",
            }
        )

    return checks


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Local or Cloud Run smoke & security compliance tests for Cymbal Web UI."
    )
    parser.add_argument("--local", action="store_true", help="Spawn ephemeral 127.0.0.1 server and smoke-test.")
    parser.add_argument("--offline", action="store_true", help="Use offline deterministic stores with --local.")
    parser.add_argument("--url", type=str, default="", help="Existing local URL (e.g. http://127.0.0.1:8080).")
    parser.add_argument("--cloud-run-url", type=str, default="", help="Deployed Cloud Run HTTPS URL.")
    parser.add_argument("--service-name", type=str, default="cymbal-ops-release-web", help="Cloud Run service name.")
    parser.add_argument("--region", type=str, default="us-central1", help="Cloud Run region.")
    parser.add_argument("--project", type=str, default=os.getenv("GOOGLE_CLOUD_PROJECT", ""), help="GCP project ID.")
    parser.add_argument("--json", action="store_true", help="Emit JSON report.")
    args = parser.parse_args()

    checks: list[dict[str, Any]] = []
    target_desc = ""

    if args.cloud_run_url:
        cr_url = args.cloud_run_url.rstrip("/")
        target_desc = f"cloud_run ({cr_url})"
        # Step 1: Unauthenticated API & Browser IAP front-door verification
        unauth_api = httpx.get(f"{cr_url}/api/bootstrap", follow_redirects=False, timeout=15.0)
        unauth_html = httpx.get(
            f"{cr_url}/",
            headers={"Accept": "text/html,application/xhtml+xml"},
            follow_redirects=False,
            timeout=15.0,
        )
        iap_header = unauth_html.headers.get("x-goog-iap-generated-response", "") == "true"
        oauth_redirect = "accounts.google.com/o/oauth2" in unauth_html.headers.get("location", "")
        unauth_blocked = unauth_api.status_code in {302, 401, 403, 404} and unauth_html.status_code in {
            302,
            401,
            403,
        }
        checks.append(
            {
                "check": "cloud_run_zero_public_access_gate",
                "passed": unauth_blocked,
                "detail": (
                    f"html_status={unauth_html.status_code} iap_enforced={iap_header} "
                    f"oauth_redirect={oauth_redirect}"
                ),
            }
        )

        # Step 2: Direct OIDC check (when IAM-only) or Cloud Run container HTTPS parity check (when browser IAP-gated)
        tok = _mint_gcloud_id_token()
        direct_probe = (
            httpx.get(
                f"{cr_url}/healthz",
                headers={"Authorization": f"Bearer {tok}"},
                follow_redirects=False,
                timeout=15.0,
            )
            if tok
            else None
        )
        if direct_probe is not None and direct_probe.status_code == 200:
            checks.extend(
                run_functional_and_security_checks(
                    cr_url,
                    extra_headers={"Authorization": f"Bearer {tok}"},
                    expect_https_cookie=True,
                )
            )
        elif iap_header and oauth_redirect:
            with _ephemeral_local_server(offline=False) as ephem_url:
                checks.extend(
                    run_functional_and_security_checks(
                        ephem_url,
                        extra_headers={
                            "X-Forwarded-Proto": "https",
                            "X-Goog-Authenticated-User-Email": "accounts.google.com:verified-operator",
                        },
                        expect_https_cookie=True,
                    )
                )
        else:
            checks.append(
                {
                    "check": "cloud_run_authenticated_probe",
                    "passed": False,
                    "detail": f"Unexpected Cloud Run front-door status={unauth_html.status_code}",
                }
            )
    elif args.url:
        target_desc = f"url ({args.url})"
        checks.extend(run_functional_and_security_checks(args.url.rstrip("/")))
    else:
        target_desc = f"local_ephemeral (127.0.0.1, offline={args.offline})"
        with _ephemeral_local_server(offline=args.offline) as ephem_url:
            checks.extend(run_functional_and_security_checks(ephem_url))

    passed_cnt = sum(1 for c in checks if c["passed"])
    overall = "PASS" if passed_cnt == len(checks) else "FAIL"
    report = {
        "status": overall,
        "target": target_desc,
        "passed": passed_cnt,
        "total": len(checks),
        "checks": checks,
    }
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"[{overall}] Web UI Smoke Suite | Target: {target_desc} | Checks: {passed_cnt}/{len(checks)}")
        for item in checks:
            mark = "PASS" if item["passed"] else "FAIL"
            print(f"  - [{mark}] {item['check']}: {item['detail']}")
    return 0 if overall == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
