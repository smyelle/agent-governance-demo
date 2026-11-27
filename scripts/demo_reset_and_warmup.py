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

"""One-command live demo reset, GCP warmup & local console launcher.

Resets isolated runtime workbench state (and Firestore kill-switch/wallet when
online), verifies Vertex AI Gemini 3.8 Flash, Model Armor Floor + templates, and
downstream Cloud Run services, prints a concise readiness scorecard, and launches
the FastAPI BFF console on http://127.0.0.1:8080 unless --no-serve is passed.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _reset_local_runtime_state(state_dir: Path) -> dict[str, Any]:
    if state_dir.exists():
        shutil.rmtree(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    os.environ["CYMBAL_RUNTIME_STATE_DIR"] = str(state_dir)

    from cymbal_agent.governance.workbench_state import (
        CAAS_49_FACTORS,
        PHASE5_REVIEWER_ROLES,
        WorkbenchGovernanceEngine,
        list_local_starter_templates,
    )
    from cymbal_agent.tenant import load_tenant_profile

    profile = load_tenant_profile()
    engine = WorkbenchGovernanceEngine()
    engine._persist_locked()
    starters = list_local_starter_templates(profile=profile)
    return {
        "state_dir": str(state_dir),
        "profile_key": profile.profile_key,
        "platform_title": profile.terminology.platform_title,
        "starter_count": len(starters),
        "starter_names": [s["name"] for s in starters],
        "seeded_templates": len(engine.list_templates()),
        "caas_factors": len(CAAS_49_FACTORS),
        "phase5_reviewers": len(PHASE5_REVIEWER_ROLES),
        "recertification_records": len(engine.list_recertification_records()),
    }


def _reset_firestore_state(project_id: str) -> dict[str, Any]:
    from google.cloud import firestore
    from cymbal_agent.governance.gcp_auth import get_gcp_credentials

    t0 = time.monotonic()
    creds, _ = get_gcp_credentials(project_id)
    db_name = os.getenv("CYMBAL_FIRESTORE_DATABASE", "(default)")
    db = firestore.Client(project=project_id, database=db_name, credentials=creds)
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    db.collection("cymbal_agents").document("agent-governance-demo").set(
        {
            "agent_id": "agent-governance-demo",
            "status": "ACTIVE",
            "active_prompt_version": "v2",
            "updated_at": now_iso,
        },
        merge=True,
    )
    db.collection("cymbal_wallets").document("wallet-cymbal-ops").set(
        {
            "wallet_id": "wallet-cymbal-ops",
            "monthly_cap_nano_usd": 15_000_000_000,
            "spent_nano_usd": 0,
            "reserved_nano_usd": 0,
            "resolved_incidents_count": 0,
            "status": "ACTIVE",
            "updated_at": now_iso,
        },
        merge=True,
    )
    return {
        "status": "RESET_ACTIVE",
        "latency_ms": round((time.monotonic() - t0) * 1000.0, 1),
    }


def _warmup_gemini(project_id: str, model_id: str) -> dict[str, Any]:
    from google import genai
    from google.genai import types
    from cymbal_agent.governance.gcp_auth import get_gcp_credentials

    t0 = time.monotonic()
    creds, _ = get_gcp_credentials(project_id)
    client = genai.Client(
        enterprise=True,
        project=project_id,
        location=os.getenv("CYMBAL_GEMINI_LOCATION", "global"),
        credentials=creds,
        http_options=types.HttpOptions(timeout=20000),
    )
    resp = client.models.generate_content(
        model=model_id,
        contents="Respond with READY.",
        config=types.GenerateContentConfig(
            temperature=0.0,
            max_output_tokens=8,
            thinking_config=types.ThinkingConfig(thinking_budget=0),
        ),
    )
    return {
        "model": model_id,
        "status": "READY",
        "reply": (resp.text or "").strip()[:32],
        "latency_ms": round((time.monotonic() - t0) * 1000.0, 1),
    }


def _warmup_model_armor(project_id: str, location: str) -> dict[str, Any]:
    from cymbal_agent.governance.model_armor_guard import (
        DynamicGuardrailPolicyPayload,
        FailClosedModelArmorGuard,
    )

    t0 = time.monotonic()
    guard = FailClosedModelArmorGuard(
        project_id=project_id,
        location=location,
        live_api_enabled=True,
    )
    verdict = guard.inspect_text(
        "Demo readiness warmup probe.",
        direction="USER_PROMPT",
        dynamic_policy=DynamicGuardrailPolicyPayload(risk_tier="AG2"),
    )
    return {
        "status": "READY" if verdict.allowed else "BLOCKED",
        "action_taken": verdict.action_taken,
        "latency_ms": round((time.monotonic() - t0) * 1000.0, 1),
    }


def _mint_id_token(audience: str | None = None) -> str | None:
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
        proc = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=10, env=env)
        return proc.stdout.strip() or None
    except Exception:
        return None


def _warmup_cloud_run_endpoints() -> dict[str, Any]:
    import httpx

    mcp_url = os.getenv("CYMBAL_MCP_URL", "").strip()
    a2a_url = os.getenv("CYMBAL_A2A_URL", "").strip().rstrip("/")
    tier0_url = os.getenv("CYMBAL_TIER0_GATEWAY_URL", "").strip().rstrip("/")
    targets: dict[str, tuple[str, str, dict[str, Any] | None, dict[str, str]]] = {
        "mcp_server": (
            "POST",
            mcp_url,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "warmup", "version": "1.0"},
                },
            },
            {"Accept": "application/json, text/event-stream"},
        ),
        "a2a_agent": (
            "GET",
            f"{a2a_url}/.well-known/agent-card.json" if a2a_url else "",
            None,
            {},
        ),
        "tier0_gateway": (
            "POST",
            f"{tier0_url}/v1/guardrails/compile-policy" if tier0_url else "",
            {"business_unit": "enterprise_shared", "risk_tier": "AG2"},
            {},
        ),
    }

    tok = _mint_id_token()
    base_headers = {"Authorization": f"Bearer {tok}"} if tok else {}
    statuses: dict[str, Any] = {}

    def _ping(
        name: str,
        method: str,
        url: str,
        payload: dict[str, Any] | None,
        extra_headers: dict[str, str],
    ) -> tuple[str, dict[str, Any]]:
        if not url:
            return name, {"status": "NOT_CONFIGURED"}
        t0 = time.monotonic()
        req_headers = {**base_headers, **extra_headers}
        try:
            if method == "POST":
                r = httpx.post(url, headers=req_headers, json=payload, timeout=15.0)
            else:
                r = httpx.get(url, headers=req_headers, timeout=15.0)
            return name, {
                "http_status": r.status_code,
                "url": url,
                "latency_ms": round((time.monotonic() - t0) * 1000.0, 1),
            }
        except Exception as exc:
            return name, {
                "http_status": 0,
                "url": url,
                "error": str(exc)[:120],
                "latency_ms": round((time.monotonic() - t0) * 1000.0, 1),
            }

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = [
            pool.submit(_ping, name, method, url, payload, extra_hdrs)
            for name, (method, url, payload, extra_hdrs) in targets.items()
        ]
        for fut in futures:
            name, data = fut.result()
            statuses[name] = data
    return statuses


def run_reset_and_warmup(
    *,
    state_dir: Path,
    reset_only: bool = False,
    warmup_only: bool = False,
    offline: bool = False,
    host: str = "127.0.0.1",
    port: int = 8080,
) -> dict[str, Any]:
    load_dotenv(REPO_ROOT / ".env", override=False)
    project_id = os.getenv("GOOGLE_CLOUD_PROJECT", "cymbal-agent-platform")
    location = os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1")
    model_id = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
    os.environ["CYMBAL_BFF_OFFLINE"] = "true" if offline else "false"

    report: dict[str, Any] = {
        "mode": "offline" if offline else "live_vertex_ai",
        "project_id": project_id,
        "location": location,
        "console_url": f"http://{host}:{port}/build",
        "fallback_hint": "Use header toggle 'Offline Demo Fallback' (#offline-demo-toggle) if network degrades.",
    }

    if not warmup_only:
        report["local_state"] = _reset_local_runtime_state(state_dir)
    else:
        os.environ["CYMBAL_RUNTIME_STATE_DIR"] = str(state_dir)

    if offline:
        if not warmup_only:
            report["firestore"] = {"status": "SKIPPED_OFFLINE"}
        if not reset_only:
            report["gemini"] = {"model": model_id, "status": "SKIPPED_OFFLINE"}
            report["model_armor"] = {"status": "SKIPPED_OFFLINE"}
            report["cloud_run"] = {"status": "SKIPPED_OFFLINE"}
        return report

    from cymbal_agent.governance.gcp_auth import install_local_gcloud_auth_bridge

    install_local_gcloud_auth_bridge(project_id)

    tasks: dict[str, concurrent.futures.Future[Any]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        if not warmup_only:
            tasks["firestore"] = pool.submit(_reset_firestore_state, project_id)
        if not reset_only:
            tasks["gemini"] = pool.submit(_warmup_gemini, project_id, model_id)
            tasks["model_armor"] = pool.submit(_warmup_model_armor, project_id, location)
            tasks["cloud_run"] = pool.submit(_warmup_cloud_run_endpoints)

        for key, fut in tasks.items():
            try:
                report[key] = fut.result()
            except Exception as exc:
                report[key] = {"status": "ERROR", "error": str(exc)[:180]}

    return report


def _print_scorecard(report: dict[str, Any]) -> None:
    ls = report.get("local_state") or {}
    gem = report.get("gemini") or {}
    ma = report.get("model_armor") or {}
    fs = report.get("firestore") or {}
    cr = report.get("cloud_run") or {}
    print("=== Live Demo Readiness Scorecard ===")
    print(f"Mode           : {report['mode']} | Project: {report['project_id']} ({report['location']})")
    if ls:
        print(
            f"Tenant Profile : {ls['profile_key']} | {ls['platform_title']} | "
            f"Starters: {ls['starter_count']} ({', '.join(ls['starter_names'])})"
        )
        print(
            f"Golden Seed    : {ls['seeded_templates']} agents | {ls['caas_factors']} CaaS factors | "
            f"{ls['phase5_reviewers']} Phase 5 reviewers | {ls['recertification_records']} recert rows"
        )
        print(f"State Dir      : {ls['state_dir']}")
    if fs:
        print(f"Firestore      : {fs.get('status')} ({fs.get('latency_ms', 0)}ms)")
    if gem:
        print(f"Gemini LTA     : {gem.get('model')} -> {gem.get('status')} ({gem.get('latency_ms', 0)}ms)")
    if ma:
        print(f"Model Armor    : {ma.get('status')} / {ma.get('action_taken', '-')} ({ma.get('latency_ms', 0)}ms)")
    if isinstance(cr, dict) and "status" not in cr:
        summary = ", ".join(
            f"{k}={v.get('http_status', v.get('status'))}" for k, v in cr.items()
        )
        print(f"Cloud Run      : {summary}")
    print(f"Console URL    : {report['console_url']}")
    print(f"Fallback       : {report['fallback_hint']}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reset runtime state, warmup live Vertex AI/Model Armor/Cloud Run services, and launch the console."
    )
    parser.add_argument(
        "--state-dir",
        type=str,
        default="/tmp/cymbal_demo_clean_state",
        help="Isolated CYMBAL_RUNTIME_STATE_DIR path (wiped on reset).",
    )
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Uvicorn bind host.")
    parser.add_argument("--port", type=int, default=8080, help="Uvicorn listen port.")
    parser.add_argument("--reset-only", action="store_true", help="Reset state/Firestore and exit.")
    parser.add_argument("--warmup-only", action="store_true", help="Run warmup probes and exit.")
    parser.add_argument(
        "--no-serve",
        action="store_true",
        help="Run reset + warmup, print readiness scorecard, and exit without launching uvicorn.",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Skip live GCP warmup calls and run in deterministic offline mode.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON scorecard.")
    args = parser.parse_args()

    state_path = Path(args.state_dir).expanduser().resolve()
    report = run_reset_and_warmup(
        state_dir=state_path,
        reset_only=args.reset_only,
        warmup_only=args.warmup_only,
        offline=args.offline,
        host=args.host,
        port=args.port,
    )

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_scorecard(report)

    if args.reset_only or args.warmup_only or args.no_serve:
        return 0

    import uvicorn

    uvicorn.run("web.api:app", host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
