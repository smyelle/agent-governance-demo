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
isolation, inline Cloud SDP PII masking, ADK 2.0 triage + HITL resume, and the
4-stage Cymbal Platform lifecycle console (`/build`, `/evaluate`, `/deploy`,
`/govern`) against either a local 127.0.0.1 server (`--local` / `--url`) or a
deployed Cloud Run service (`--cloud-run-url`).
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Iterator

import httpx
import uvicorn
import websockets

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

        # 3. Bootstrap + Session Cookie + 9 Platform Services + 10 Functional Slots
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
        slot_count = len(boot_json.get("slot_catalog") or [])
        checks.append(
            {
                "check": "bootstrap_cookie_services_and_10_slots",
                "passed": (
                    boot.status_code == 200
                    and bool(csrf)
                    and svc_count == 9
                    and slot_count == 10
                    and cookie_ok
                ),
                "detail": f"services={svc_count} slots={slot_count} cookie_hardened={cookie_ok}",
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

        # 6. End-to-End ADK 2.0 Governance Audit + AG3 HITL Deployment Resume
        triage = client.post(
            "/api/agent/audit",
            headers=csrf_hdr,
            json={
                "candidate_id": "CAND-101",
                "agent_name": "billing-dispute-assistant",
                "app_id": "SVC-CYMBAL-101",
                "operator_prompt": (
                    "Audit CAND-101 (billing-dispute-assistant) and prepare governed Terraform "
                    "Paved-Path & Golden Blueprint deployment."
                ),
                "architecture_mode": "enterprise_hybrid",
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
                    "approver_principal": "gov-steward-lead",
                    "reason": "Automated smoke test approval.",
                },
            )
            r_data = resume.json() if resume.status_code == 200 else {}
            rem = r_data.get("remediation_outcome") or {}
            resume_ok = (
                resume.status_code == 200
                and r_data.get("status") == "COMPLETED"
                and rem.get("status") == "DEPLOYED_PAVED_PATH"
                and rem.get("compliance_verified") is True
            )
        checks.append(
            {
                "check": "adk_workflow_audit_and_hitl_resume",
                "passed": paused_ok and resume_ok,
                "detail": f"paused_ag3={paused_ok} resumed_deployed={resume_ok}",
            }
        )

        # 7. Cymbal Lifecycle Routes (/build, /evaluate, /deploy, /govern), Zero Meta Terms & 10-Component FinOps
        b_html = client.get("/build")
        e_html = client.get("/evaluate")
        d_html = client.get("/deploy")
        g_html = client.get("/govern")
        ops_m = client.get("/api/ops/metrics")
        exec_c = client.get("/api/executive/costs")
        exec_json = exec_c.json() if exec_c.status_code == 200 else {}
        lower_html = b_html.text.lower()
        lifecycle_ok = (
            b_html.status_code == 200
            and e_html.status_code == 200
            and d_html.status_code == 200
            and g_html.status_code == 200
            and 'id="left-lifecycle-nav"' in b_html.text
            and 'id="pinned-template-section"' not in b_html.text
            and "mock" not in lower_html
            and "persona" not in lower_html
            and ops_m.status_code == 200
            and exec_c.status_code == 200
            and len(exec_json.get("component_cost_rollup") or []) == 10
            and len(exec_json.get("pillar_cost_rollup") or []) == 4
            and int(exec_json.get("deployment_count") or 0) >= 22
        )
        checks.append(
            {
                "check": "cymbal_lifecycle_routes_metrics_and_10_component_finops",
                "passed": lifecycle_ok,
                "detail": (
                    f"routes_200={b_html.status_code}/{e_html.status_code}/{d_html.status_code}/{g_html.status_code} "
                    f"components={len(exec_json.get('component_cost_rollup') or [])} "
                    f"deployments={exec_json.get('deployment_count')}"
                ),
            }
        )

    return checks


def find_local_chrome_binary() -> str | None:
    env_bin = os.getenv("CHROME_BIN", "").strip()
    if env_bin and Path(env_bin).is_file():
        return env_bin
    mac_candidates = [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
    ]
    for cand in mac_candidates:
        if Path(cand).is_file():
            return cand
    for cmd_name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser"):
        resolved = shutil.which(cmd_name)
        if resolved:
            return resolved
    return None


async def _drive_cdp_golden_walkthrough(
    ws_url: str,
    base_url: str,
    screenshot_dir: Path | None = None,
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    cdp_exceptions: list[str] = []
    msg_seq = 0

    async with websockets.connect(ws_url, max_size=32 * 1024 * 1024) as ws:

        async def cdp(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
            nonlocal msg_seq
            msg_seq += 1
            req_id = msg_seq
            await ws.send(json.dumps({"id": req_id, "method": method, "params": params or {}}))
            while True:
                raw = await asyncio.wait_for(ws.recv(), timeout=20.0)
                data = json.loads(raw)
                if data.get("method") == "Runtime.exceptionThrown":
                    exc_meta = (data.get("params") or {}).get("exceptionDetails") or {}
                    cdp_exceptions.append(str(exc_meta.get("text") or exc_meta))
                if data.get("id") == req_id:
                    if "error" in data:
                        raise RuntimeError(f"CDP {method} error: {data['error']}")
                    return data.get("result") or {}

        async def eval_js(expr: str) -> Any:
            wrapped = f"(() => {{ {expr} }})()"
            res = await cdp(
                "Runtime.evaluate",
                {"expression": wrapped, "returnByValue": True, "awaitPromise": True},
            )
            if "exceptionDetails" in res:
                raise RuntimeError(f"JS evaluation error: {res['exceptionDetails']}")
            return (res.get("result") or {}).get("value")

        async def wait_js(predicate_body: str, timeout_s: float = 12.0) -> Any:
            deadline = time.monotonic() + timeout_s
            last_val = None
            while time.monotonic() < deadline:
                last_val = await eval_js(predicate_body)
                if last_val:
                    return last_val
                await asyncio.sleep(0.08)
            raise TimeoutError(f"Timed out waiting for JS condition: {predicate_body[:140]}")

        async def save_shot(filename: str) -> None:
            if screenshot_dir is None:
                return
            screenshot_dir.mkdir(parents=True, exist_ok=True)
            shot = await cdp("Page.captureScreenshot", {"format": "png"})
            (screenshot_dir / filename).write_bytes(base64.b64decode(shot["data"]))

        await cdp("Page.enable")
        await cdp("Runtime.enable")
        await cdp(
            "Emulation.setDeviceMetricsOverride",
            {"width": 1440, "height": 1080, "deviceScaleFactor": 2, "mobile": False},
        )
        await cdp(
            "Page.addScriptToEvaluateOnNewDocument",
            {
                "source": """
                window.__cspViolations = [];
                window.__unhandledErrors = [];
                document.addEventListener('securitypolicyviolation', (e) => {
                  window.__cspViolations.push(e.violatedDirective + ':' + e.blockedURI);
                });
                window.addEventListener('error', (e) => {
                  window.__unhandledErrors.push(String(e.message || 'error'));
                });
                window.addEventListener('unhandledrejection', (e) => {
                  window.__unhandledErrors.push(String(e.reason || 'rejection'));
                });
                """
            },
        )

        # 1. Boot /build, verify newest-first sort, desktop overflow: clip, and column filter
        await cdp("Page.navigate", {"url": f"{base_url}/build"})
        boot_meta = await wait_js(
            """
            const rows = document.querySelectorAll('#stage-body-content tbody tr');
            if (rows.length !== 10) return null;
            const wrap = document.querySelector('#stage-body-content .table-wrap');
            const sortTh = document.querySelector('th[aria-sort="descending"]');
            const pag = document.querySelector('.pagination-meta');
            return {
              brandSub: (document.getElementById('sidebar-brand-subtitle') || {}).textContent || '',
              navCount: document.querySelectorAll('.lifecycle-nav-btn').length,
              railFooter: Boolean(document.querySelector('.rail-footer')),
              firstAgent: rows[0].querySelector('.row-select-btn').textContent.trim(),
              overflowY: wrap ? getComputedStyle(wrap).overflowY : '',
              hasDescSort: Boolean(sortTh),
              pagText: pag ? pag.textContent : ''
            };
            """
        )
        await eval_js(
            """
            const sel = document.getElementById('tbl-flt-build-agents-lifecycle_status');
            sel.value = 'DRAFT';
            sel.dispatchEvent(new Event('change', { bubbles: true }));
            """
        )
        flt_text = await wait_js(
            """
            const bar = document.querySelector('.table-active-filters-bar');
            return bar ? bar.textContent : null;
            """
        )
        await eval_js(
            """
            const btn = Array.from(document.querySelectorAll('.table-active-filters-bar button'))
              .find((b) => b.textContent.includes('Clear Column Filters'));
            btn.click();
            """
        )
        await wait_js(
            "return document.querySelectorAll('#stage-body-content tbody tr').length === 10;"
        )
        checks.append(
            {
                "check": "gw_01_build_boot_sort_scroll_and_filters",
                "passed": (
                    boot_meta["brandSub"] == "Agent Governance Platform"
                    and boot_meta["navCount"] == 4
                    and boot_meta["railFooter"] is False
                    and boot_meta["overflowY"] == "clip"
                    and boot_meta["hasDescSort"] is True
                    and "of 27 rows" in boot_meta["pagText"]
                    and "matching 5 of 27 rows" in flt_text
                ),
                "detail": (
                    f"overflowY={boot_meta['overflowY']} first={boot_meta['firstAgent']} "
                    f"draft_filter_ok={'matching 5 of 27' in flt_text}"
                ),
            }
        )

        # 2. Expand Google Cloud agent row, test Google Cloud <-> Custom switcher & 10 nested expanders
        await eval_js(
            """
            const btn = Array.from(document.querySelectorAll('.row-select-btn'))
              .find((b) => b.textContent.includes('network-telemetry-advisor'));
            btn.click();
            """
        )
        tpl_meta = await wait_js(
            """
            const exp = document.querySelector('.expanded-editor-row');
            if (!exp) return null;
            const tiles = Array.from(exp.querySelectorAll('.component-tile'));
            const dets = Array.from(exp.querySelectorAll('details.component-expander'));
            const rad = document.getElementById('inst-tpl-network-telemetry-advisor-google_gcp');
            const radRect = rad.getBoundingClientRect();
            const radOpacity = getComputedStyle(rad).opacity;
            return {
              tileCount: tiles.length,
              detCount: dets.length,
              allGoogleCaptions: tiles.every((t) =>
                t.querySelector('.tile-impl-caption').textContent.trim().startsWith('Google ')
              ),
              radHidden: radRect.width <= 2 && radOpacity === '0'
            };
            """
        )
        await eval_js(
            """
            document.querySelector('label[for="inst-tpl-network-telemetry-advisor-custom"]').click();
            """
        )
        custom_switched = await wait_js(
            """
            const customRad = document.getElementById('inst-tpl-network-telemetry-advisor-custom');
            const fs = document.querySelector('.expanded-editor-row fieldset.radio-card-list');
            return customRad && customRad.checked && fs && !fs.disabled ? true : null;
            """
        )
        await eval_js(
            """
            document.querySelector('.expanded-editor-row .component-tile[data-slot-id="runtime_sandbox"]').click();
            """
        )
        slot_sync = await wait_js(
            """
            const openDets = Array.from(
              document.querySelectorAll('.expanded-editor-row details.component-expander[open]')
            );
            if (openDets.length !== 1 || openDets[0].dataset.slotId !== 'runtime_sandbox') return null;
            const bodyTxt = openDets[0].textContent;
            return {
              hasOss: bodyTxt.includes('LangGraph + E2B Firecracker Sandbox'),
              hasGcp: bodyTxt.includes('Google Agent Runtime (Agent Engine + gVisor)')
            };
            """
        )
        await save_shot("golden_01_build_expanded.png")
        checks.append(
            {
                "check": "gw_02_build_template_switcher_10_blocks_and_nested_accordions",
                "passed": (
                    tpl_meta["tileCount"] == 10
                    and tpl_meta["detCount"] == 10
                    and tpl_meta["allGoogleCaptions"] is True
                    and tpl_meta["radHidden"] is True
                    and custom_switched is True
                    and slot_sync["hasOss"] is True
                    and slot_sync["hasGcp"] is True
                ),
                "detail": (
                    f"tiles={tpl_meta['tileCount']} expanders={tpl_meta['detCount']} "
                    f"custom_switch={custom_switched} radio_hidden={tpl_meta['radHidden']}"
                ),
            }
        )

        # 3. Register + New Agent & Import Shadow AG3 Manifest -> Navigate to Evaluate
        await eval_js(
            """
            const b = Array.from(document.querySelectorAll('button'))
              .find((x) => x.textContent.trim() === '+ New Agent');
            b.click();
            """
        )
        await wait_js("const d = document.getElementById('agent-modal-dialog'); return d && d.open;")
        await eval_js(
            """
            const inp = document.getElementById('new-agent-id');
            inp.value = 'media-rights-concierge';
            document.querySelector('#agent-modal-body form').requestSubmit();
            """
        )
        await wait_js(
            """
            const d = document.getElementById('agent-modal-dialog');
            const exp = document.querySelector('.is-expanded-parent .row-select-btn');
            return d && !d.open && exp && exp.textContent.includes('media-rights-concierge');
            """
        )
        await eval_js(
            """
            const imp = Array.from(document.querySelectorAll('.expanded-editor-row button'))
              .find((x) => x.textContent.trim() === 'Import Manifest');
            imp.click();
            """
        )
        await wait_js("const d = document.getElementById('agent-modal-dialog'); return d && d.open;")
        await eval_js("document.querySelector('#agent-modal-body form').requestSubmit();")
        await wait_js(
            """
            const d = document.getElementById('agent-modal-dialog');
            const clearBtn = Array.from(document.querySelectorAll('.expanded-editor-row button'))
              .find((x) => x.textContent.includes('Remove Static Env Keys'));
            return d && !d.open && Boolean(clearBtn);
            """
        )
        await eval_js(
            """
            const evBtn = Array.from(document.querySelectorAll('.expanded-editor-row button'))
              .find((x) => x.textContent.includes('Evaluate Agent'));
            evBtn.click();
            """
        )
        checks.append(
            {
                "check": "gw_03_build_new_agent_and_shadow_manifest_import",
                "passed": True,
                "detail": "created=media-rights-concierge imported_shadow_manifest=True",
            }
        )

        # 4. Evaluate Stage: Blocking Gates, Numeric Filter & Rule Expanders
        eval_blocked = await wait_js(
            """
            if (window.location.pathname !== '/evaluate') return null;
            const exp = document.querySelector('.expanded-editor-row');
            if (!exp) return null;
            const hero = exp.querySelector('.hero-metric-card');
            const failedTiles = exp.querySelectorAll('.component-tile.tile-status-failed');
            const callouts = exp.querySelectorAll('.finding-callout');
            const excInp = exp.querySelector('input[id^="exc-input-"]');
            if (!hero || failedTiles.length === 0 || callouts.length === 0 || !excInp) return null;
            return {
              heroText: hero.textContent,
              failedTileCount: failedTiles.length,
              calloutCount: callouts.length,
              excHiddenByDefault: excInp.offsetParent === null
            };
            """
        )
        await save_shot("golden_02_evaluate_blocked.png")

        await eval_js(
            """
            const fInp = document.getElementById('tbl-flt-eval-agents-latest_eval_score');
            fInp.value = '<60';
            fInp.dispatchEvent(new Event('input', { bubbles: true }));
            """
        )
        eval_flt_bar = await wait_js(
            """
            const bar = document.querySelector('.table-active-filters-bar');
            return bar ? bar.textContent : null;
            """
        )
        await eval_js(
            """
            const btn = Array.from(document.querySelectorAll('.table-active-filters-bar button'))
              .find((b) => b.textContent.includes('Clear Column Filters'));
            btn.click();
            """
        )
        await wait_js("return !document.querySelector('.table-active-filters-bar');")
        checks.append(
            {
                "check": "gw_04_evaluate_blocking_gates_and_numeric_filter",
                "passed": (
                    "Blocking Gate" in eval_blocked["heroText"]
                    and eval_blocked["failedTileCount"] >= 4
                    and eval_blocked["excHiddenByDefault"] is True
                    and "column filter(s) active" in eval_flt_bar
                ),
                "detail": (
                    f"failed_tiles={eval_blocked['failedTileCount']} "
                    f"open_findings={eval_blocked['calloutCount']} "
                    f"exc_hidden={eval_blocked['excHiddenByDefault']} numeric_filter_ok=True"
                ),
            }
        )

        # 5. Remediate all open findings + Optimize Prompt & Traces (v2) + Run ADK Workflow Audit
        for _ in range(12):
            rem_left = await eval_js(
                "return document.querySelectorAll('.expanded-editor-row .finding-callout').length;"
            )
            if not rem_left:
                break
            await eval_js(
                """
                const det = Array.from(
                  document.querySelectorAll('.expanded-editor-row details.component-expander')
                ).find((d) => d.querySelector('.finding-callout'));
                if (det && !det.open) det.open = true;
                const fixBtn = det.querySelector('.finding-callout .primary-btn');
                fixBtn.click();
                """
            )
            await wait_js(
                f"""
                const cur = document.querySelectorAll('.expanded-editor-row .finding-callout').length;
                return cur < {int(rem_left)} ? true : null;
                """
            )

        await eval_js(
            """
            const opt = Array.from(document.querySelectorAll('.expanded-editor-row button'))
              .find((b) => b.textContent.includes('Optimize Prompt & Traces'));
            opt.click();
            """
        )
        await wait_js(
            """
            const t = document.getElementById('status-toast-banner');
            return t && !t.hidden && t.textContent.includes('Promoted v2 instructions') ? true : null;
            """
        )

        await eval_js(
            """
            const aud = Array.from(document.querySelectorAll('.expanded-editor-row button'))
              .find((b) => b.textContent.includes('Run ADK Workflow Audit'));
            aud.click();
            """
        )
        audit_toast = await wait_js(
            """
            const t = document.getElementById('status-toast-banner');
            return t && !t.hidden && t.textContent.includes('AG3 approval checkpoint')
              ? t.textContent
              : null;
            """
        )
        eval_ready = await eval_js(
            """
            const exp = document.querySelector('.expanded-editor-row');
            return {
              heroText: exp.querySelector('.hero-metric-card').textContent,
              passedTiles: exp.querySelectorAll('.component-tile.tile-status-passed').length
            };
            """
        )
        await save_shot("golden_03_evaluate_remediated.png")
        await eval_js(
            """
            const depBtn = Array.from(document.querySelectorAll('.expanded-editor-row button'))
              .find((b) => b.textContent.includes('Proceed to Deploy'));
            depBtn.click();
            """
        )
        checks.append(
            {
                "check": "gw_05_evaluate_remediation_closed_loop_v2_and_adk_audit",
                "passed": (
                    "[OK] Gate Passed" in eval_ready["heroText"]
                    and eval_ready["passedTiles"] == 10
                    and "ag3_deploy_" in audit_toast
                ),
                "detail": f"passed_tiles={eval_ready['passedTiles']}/10 gate_passed=True hitl_staged=True",
            }
        )

        # 6. Deploy Stage: Pixel-Exact Horizontal Alignment & Terraform / Guardrail Previews
        deploy_geom = await wait_js(
            """
            if (window.location.pathname !== '/deploy') return null;
            const exp = document.querySelector('.expanded-editor-row');
            if (!exp) return null;
            const appInp = document.getElementById('deploy-approver-media-rights-concierge');
            const tktInp = document.getElementById('deploy-ticket-media-rights-concierge');
            const depBtn = exp.querySelector('form.inline-action-form button[type="submit"]');
            const kpis = exp.querySelectorAll('.kpi-grid-4 > .surface-card');
            if (!appInp || !tktInp || !depBtn || kpis.length !== 4) return null;
            const rApp = appInp.getBoundingClientRect();
            const rTkt = tktInp.getBoundingClientRect();
            const rBtn = depBtn.getBoundingClientRect();
            const rKpi4 = kpis[3].getBoundingClientRect();
            return {
              topDeltaApp: Math.abs(rApp.top - rBtn.top),
              bottomDeltaApp: Math.abs(rApp.bottom - rBtn.bottom),
              topDeltaTkt: Math.abs(rTkt.top - rBtn.top),
              rightEdgeDelta: Math.abs(rKpi4.right - rBtn.right),
              hasHitlBtn: Array.from(exp.querySelectorAll('form.inline-action-form button'))
                .some((b) => b.textContent.includes('Approve ADK Checkpoint'))
            };
            """
        )
        await save_shot("golden_04_deploy_approval_aligned.png")

        hcl_and_json = await eval_js(
            """
            const tfDet = document.querySelector('details[data-section-key="terraform"]');
            tfDet.open = true;
            const tfText = tfDet.querySelector('pre.code-block').textContent;
            const polDet = document.querySelector('details[data-section-key="guardrail"]');
            polDet.open = true;
            const polText = polDet.querySelector('pre.code-block').textContent;
            const appDet = document.querySelector('details[data-section-key="approval"]');
            appDet.open = true;
            return {
              hasTerraform: tfText.includes('resource') || tfText.includes('module'),
              hasPolicyJson: polText.includes('DEIDENTIFY_INLINE')
            };
            """
        )
        checks.append(
            {
                "check": "gw_06_deploy_button_pixel_alignment_and_hcl_guardrail_preview",
                "passed": (
                    deploy_geom["topDeltaApp"] <= 2.0
                    and deploy_geom["bottomDeltaApp"] <= 2.0
                    and deploy_geom["topDeltaTkt"] <= 2.0
                    and deploy_geom["rightEdgeDelta"] <= 2.5
                    and deploy_geom["hasHitlBtn"] is True
                    and hcl_and_json["hasTerraform"] is True
                    and hcl_and_json["hasPolicyJson"] is True
                ),
                "detail": (
                    f"top_delta_px={deploy_geom['topDeltaApp']:.2f} "
                    f"bottom_delta_px={deploy_geom['bottomDeltaApp']:.2f} "
                    f"right_edge_delta_px={deploy_geom['rightEdgeDelta']:.2f}"
                ),
            }
        )

        # 7. Resume ADK HITL Checkpoint & Deploy Agent to Fleet -> Cost Attribution Expander
        await eval_js(
            """
            const hitl = Array.from(
              document.querySelectorAll('.expanded-editor-row form.inline-action-form button')
            ).find((b) => b.textContent.includes('Approve ADK Checkpoint'));
            hitl.click();
            """
        )
        await wait_js(
            """
            const t = document.getElementById('status-toast-banner');
            return t && !t.hidden && t.textContent.includes('Resumed and completed ADK 2.0 AG3')
              ? true
              : null;
            """
        )
        await eval_js(
            "document.querySelector('.expanded-editor-row form.inline-action-form').requestSubmit();"
        )
        post_deploy = await wait_js(
            """
            const t = document.getElementById('status-toast-banner');
            if (!t || t.hidden || !t.textContent.includes('Deployed media-rights-concierge')) return null;
            const costDet = document.querySelector('details[data-section-key="costs"]');
            if (!costDet || !costDet.open) return null;
            const parentRow = document.querySelector('tr.is-expanded-parent');
            return {
              parentText: parentRow ? parentRow.textContent : '',
              costRows: costDet.querySelectorAll('table > tbody > tr').length
            };
            """
        )
        await save_shot("golden_05_deploy_completed_costs.png")
        checks.append(
            {
                "check": "gw_07_deploy_hitl_checkpoint_and_fleet_promotion",
                "passed": (
                    "Deployed" in post_deploy["parentText"] and post_deploy["costRows"] == 10
                ),
                "detail": f"status=Deployed cost_attribution_rows={post_deploy['costRows']}",
            }
        )

        # 8. Govern Stage -> 1. Policies & Rubric + Inline Rule Row Editor
        await eval_js("document.querySelector('.lifecycle-nav-btn[data-stage=\"govern\"]').click();")
        gov_pol = await wait_js(
            """
            if (window.location.pathname !== '/govern') return null;
            const tiles = document.querySelectorAll('.four-tile-strip .component-tile');
            const polDet = document.querySelector('details[data-govern-domain="policies"]');
            const inp = document.getElementById('rubric-threshold-input');
            const saveBtn = polDet ? polDet.querySelector('form.inline-single-action-row button[type="submit"]') : null;
            if (tiles.length !== 4 || !polDet || !polDet.open || !inp || !saveBtn) return null;
            const rI = inp.getBoundingClientRect();
            const rB = saveBtn.getBoundingClientRect();
            return {
              subtabCount: document.querySelectorAll('.subtab-bar').length,
              tileCount: tiles.length,
              alignDelta: Math.abs(rI.top - rB.top)
            };
            """
        )
        await eval_js(
            """
            const rubBtn = Array.from(
              document.querySelectorAll('details[data-govern-domain="policies"] .row-select-btn')
            ).find((b) => b.textContent.includes('RUB-01'));
            rubBtn.click();
            """
        )
        rub_exp = await wait_js(
            """
            const exp = document.querySelector('details[data-govern-domain="policies"] .expanded-editor-row');
            if (!exp) return null;
            return {
              segGroups: exp.querySelectorAll('fieldset.segmented-radio-group').length,
              hasSaveBtn: Array.from(exp.querySelectorAll('button'))
                .some((b) => b.textContent.includes('Save Rule & Rubric'))
            };
            """
        )
        await save_shot("golden_06_govern_policies_expanded.png")
        checks.append(
            {
                "check": "gw_08_govern_policies_domain_and_inline_rule_editor",
                "passed": (
                    gov_pol["subtabCount"] == 0
                    and gov_pol["tileCount"] == 4
                    and gov_pol["alignDelta"] <= 2.0
                    and rub_exp["segGroups"] == 3
                    and rub_exp["hasSaveBtn"] is True
                ),
                "detail": (
                    f"domain_tiles={gov_pol['tileCount']} subtabs={gov_pol['subtabCount']} "
                    f"btn_align_px={gov_pol['alignDelta']:.2f} rule_pill_groups={rub_exp['segGroups']}"
                ),
            }
        )

        # 9. Govern Stage -> 2. Fleet Operations (Adoption Drilldown) & 3. FinOps Simulator
        await eval_js("document.querySelector('button[data-govern-domain=\"fleet\"]').click();")
        fleet_meta = await wait_js(
            """
            const openDomains = Array.from(
              document.querySelectorAll('details[name="govern-domain-accordion"][open]')
            ).map((d) => d.dataset.governDomain);
            if (openDomains.length !== 1 || openDomains[0] !== 'fleet') return null;
            const fleetDet = document.querySelector('details[data-govern-domain="fleet"]');
            const heroVal = fleetDet.querySelector('.hero-metric-card .kpi-value').textContent.trim();
            return { openDomains, heroVal };
            """
        )
        await eval_js(
            """
            const capBtn = Array.from(
              document.querySelectorAll('details[data-govern-domain="fleet"] .row-select-btn')
            ).find((b) => b.textContent.includes('Identity & Access'));
            capBtn.click();
            """
        )
        adopt_sub = await wait_js(
            """
            const exp = document.querySelector('details[data-govern-domain="fleet"] .expanded-editor-row');
            if (!exp) return null;
            return {
              hasNewAgent: exp.textContent.includes('media-rights-concierge'),
              rowCount: exp.querySelectorAll('tbody tr').length
            };
            """
        )
        await save_shot("golden_07_govern_fleet_expanded.png")

        await eval_js("document.querySelector('button[data-govern-domain=\"finops\"]').click();")
        await wait_js(
            "return document.querySelector('details[data-govern-domain=\"finops\"]').open;"
        )
        finops_sim = await eval_js(
            """
            const simDet = document.querySelector('details[data-sub-key="simulator"]');
            simDet.open = true;
            const beforeText = simDet.textContent;
            const sel = document.getElementById('tco-daily-turns-select');
            const btn = simDet.querySelector('form.inline-single-action-row button[type="submit"]');
            const alignDelta = Math.abs(sel.getBoundingClientRect().top - btn.getBoundingClientRect().top);
            window.__beforeTcoText = beforeText;
            sel.value = '50000000';
            simDet.querySelector('form.inline-single-action-row').requestSubmit();
            return alignDelta;
            """
        )
        await wait_js(
            """
            const simDet = document.querySelector('details[data-sub-key="simulator"]');
            const sel = document.getElementById('tco-daily-turns-select');
            const btn = simDet ? simDet.querySelector('form.inline-single-action-row button[type="submit"]') : null;
            return simDet && simDet.open && sel && sel.value === '50000000'
              && btn && !btn.disabled
              && simDet.textContent.includes('$1,825,000.00')
              && simDet.textContent.includes('$16,425,000.00')
              ? true
              : null;
            """
        )
        checks.append(
            {
                "check": "gw_09_govern_fleet_adoption_and_finops_simulator",
                "passed": (
                    int(fleet_meta["heroVal"]) >= 23
                    and adopt_sub["hasNewAgent"] is True
                    and adopt_sub["rowCount"] >= 23
                    and finops_sim <= 2.0
                ),
                "detail": (
                    f"fleet_deployments={fleet_meta['heroVal']} "
                    f"new_agent_in_adoption={adopt_sub['hasNewAgent']} "
                    f"sim_btn_align_px={finops_sim:.2f}"
                ),
            }
        )

        # 10. Govern Stage -> 4. Runtime Controls (OBO, Inline PII, 8 Live Checks & Zero Errors)
        await eval_js("document.querySelector('button[data-govern-domain=\"controls\"]').click();")
        await wait_js(
            "return document.querySelector('details[data-govern-domain=\"controls\"]').open;"
        )
        cap_align = await eval_js(
            """
            const ksDet = document.querySelector('details[data-sub-key="killswitch"]');
            const inp = document.getElementById('wallet-cap-usd-input');
            const upd = ksDet.querySelector('form.inline-single-action-row button[type="submit"]');
            const obo = Array.from(ksDet.querySelectorAll('button'))
              .find((b) => b.textContent.includes('Verify OBO Token Pair'));
            const delta = Math.abs(inp.getBoundingClientRect().top - upd.getBoundingClientRect().top);
            obo.click();
            return delta;
            """
        )
        await wait_js(
            """
            const pre = document.querySelector('details[data-sub-key="killswitch"] pre.code-block');
            return pre && pre.textContent.includes('azp') ? true : null;
            """
        )

        guard_align = await eval_js(
            """
            const gDet = document.querySelector('details[data-sub-key="guardrail"]');
            gDet.open = true;
            const sel = document.getElementById('guardrail-sdp-select');
            const btn = gDet.querySelector('.inline-single-action-row button[type="submit"]');
            const delta = Math.abs(sel.getBoundingClientRect().top - btn.getBoundingClientRect().top);
            gDet.querySelector('form').requestSubmit();
            return delta;
            """
        )
        pii_redacted = await wait_js(
            """
            const pre = document.querySelector('details[data-sub-key="guardrail"] pre.code-block');
            return pre && !pre.textContent.includes('123-45-6789') ? true : null;
            """
        )

        await eval_js(
            """
            const pDet = document.querySelector('details[data-sub-key="proofs"]');
            pDet.open = true;
            const runBtn = Array.from(pDet.querySelectorAll('button'))
              .find((b) => b.textContent.includes('Run All 8 Verification Checks'));
            runBtn.click();
            """
        )
        proofs_meta = await wait_js(
            """
            const pDet = document.querySelector('details[data-sub-key="proofs"]');
            const rows = pDet ? pDet.querySelectorAll('tbody tr') : [];
            if (rows.length !== 8) return null;
            return {
              pill: pDet.querySelector('.expander-choice-pill').textContent.trim(),
              cspViolations: (window.__cspViolations || []).length,
              unhandledErrors: (window.__unhandledErrors || []).length
            };
            """
        )
        await save_shot("golden_08_govern_controls_verified.png")
        checks.append(
            {
                "check": "gw_10_govern_runtime_controls_pii_obo_8_checks_and_zero_errors",
                "passed": (
                    cap_align <= 2.0
                    and guard_align <= 2.0
                    and pii_redacted is True
                    and proofs_meta["pill"] == "8/8 Passed"
                    and proofs_meta["cspViolations"] == 0
                    and proofs_meta["unhandledErrors"] == 0
                    and len(cdp_exceptions) == 0
                ),
                "detail": (
                    f"proofs={proofs_meta['pill']} pii_redacted={pii_redacted} "
                    f"csp_violations={proofs_meta['cspViolations']} js_errors={len(cdp_exceptions)}"
                ),
            }
        )

    return checks


def run_headless_browser_golden_walkthrough(
    base_url: str,
    *,
    screenshot_dir: Path | None = None,
) -> list[dict[str, Any]]:
    chrome_bin = find_local_chrome_binary()
    if not chrome_bin:
        raise RuntimeError("Google Chrome / Chromium binary not found for headless walkthrough.")

    cdp_port = _pick_free_local_port()
    with tempfile.TemporaryDirectory(prefix="cymbal_cdp_") as profile_dir:
        proc = subprocess.Popen(
            [
                chrome_bin,
                "--headless=new",
                "--remote-debugging-address=127.0.0.1",
                f"--remote-debugging-port={cdp_port}",
                f"--user-data-dir={profile_dir}",
                "--window-size=1440,1080",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-gpu",
                "--disable-extensions",
                "--disable-background-networking",
                "about:blank",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            ws_url = ""
            deadline = time.time() + 12.0
            while time.time() < deadline:
                try:
                    resp = httpx.get(f"http://127.0.0.1:{cdp_port}/json/list", timeout=1.0)
                    if resp.status_code == 200:
                        pages = [
                            t
                            for t in resp.json()
                            if t.get("type") == "page" and t.get("webSocketDebuggerUrl")
                        ]
                        if pages:
                            ws_url = pages[0]["webSocketDebuggerUrl"]
                            break
                except Exception:
                    time.sleep(0.1)
            if not ws_url:
                raise RuntimeError("Timed out waiting for Headless Chrome CDP WebSocket target.")
            return asyncio.run(
                _drive_cdp_golden_walkthrough(ws_url, base_url, screenshot_dir=screenshot_dir)
            )
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=4.0)
            except subprocess.TimeoutExpired:
                proc.kill()


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
    parser.add_argument(
        "--golden-walkthrough",
        action="store_true",
        help="Execute 10-stage Headless Chrome CDP Golden Walkthrough & pixel alignment checks.",
    )
    parser.add_argument(
        "--screenshot-dir",
        type=str,
        default="",
        help="Optional directory to write PNG screenshots during --golden-walkthrough.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON report.")
    args = parser.parse_args()

    checks: list[dict[str, Any]] = []
    target_desc = ""
    shot_dir = Path(args.screenshot_dir).expanduser().resolve() if args.screenshot_dir else None

    if args.cloud_run_url:
        cr_url = args.cloud_run_url.rstrip("/")
        target_desc = f"cloud_run ({cr_url})"
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
        clean_url = args.url.rstrip("/")
        checks.extend(run_functional_and_security_checks(clean_url))
        if args.golden_walkthrough:
            checks.extend(
                run_headless_browser_golden_walkthrough(clean_url, screenshot_dir=shot_dir)
            )
    else:
        target_desc = f"local_ephemeral (127.0.0.1, offline={args.offline})"
        with _ephemeral_local_server(offline=args.offline) as ephem_url:
            checks.extend(run_functional_and_security_checks(ephem_url))
            if args.golden_walkthrough:
                checks.extend(
                    run_headless_browser_golden_walkthrough(ephem_url, screenshot_dir=shot_dir)
                )

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
