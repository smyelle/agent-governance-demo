/*
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

(function () {
  "use strict";

  const state = {
    csrfToken: "",
    scapeMode: "google_native",
    tenantProfile: "comcast_devx",
    incidents: [],
    selectedIncident: null,
    activeSessionId: "",
    activeInterruptId: "",
  };

  const PROOF_DEFINITIONS = [
    {
      id: 1,
      title: "1. Un-Bypassable Tenant Network (ACT + PSC-I) & Unified Kill Switch",
      baseline: "Current Baseline: Opt-in HTTP proxy URL; PAUSED blocks A2A only.",
      vendors: "Eliminates: Agentgateway, Hush, Geordie, Harmonic",
    },
    {
      id: 2,
      title: "2. Inline Per-Tool & Semantic Payload Authz (UAP Policy V2 CEL)",
      baseline: "Current Baseline: Coarse mcp.use scope allows all tools in pool.",
      vendors: "Eliminates: Runlayer, Keycard, Arcade",
    },
    {
      id: 3,
      title: "3. Zero-Secret Container (SPIFFE AGENT_IDENTITY) & ADR-011 azp OBO",
      baseline: "Current Baseline: Pod SAT keys, OBO sidecar 2x hop, pairwise sub mismatch.",
      vendors: "Eliminates: Keycard, Custom Sidecars, Vault",
    },
    {
      id: 4,
      title: "4. Un-Bypassable Org Safety Floor + Inline SDP PII + 40-URL Scan",
      baseline: "Current Baseline: 10x cost, cross-cloud hairpin, fail-open, plain text only.",
      vendors: "Eliminates: Straiker.ai, Azure Content Safety, Bedrock Guardrails",
    },
    {
      id: 5,
      title: "5. Durable RequestInput HITL Checkpointing & Native gVisor Sandbox",
      baseline: "Current Baseline: Stateless request wrapper, no isolated code execution.",
      vendors: "Eliminates: E2B MicroVMs, Custom Checkpoint Glue",
    },
    {
      id: 6,
      title: "6. Longitudinal Cross-Session Memory Bank (Strict JWT Isolation)",
      baseline: "Current Baseline: Stateless across sessions; custom ABAC wrappers needed.",
      vendors: "Eliminates: Mem0, Memori, Custom Memory Stores",
    },
    {
      id: 7,
      title: "7. Unified Single-Trace Join & Atomic Cost-per-Outcome Wallet",
      baseline: "Current Baseline: Split ELK vs Langfuse stores; post-response Valkey lag.",
      vendors: "Eliminates: Revenium, Ascerta, Faros",
    },
    {
      id: 8,
      title: "8. Closed-Loop Trace -> 503 & Freeze Sim -> Prompt Optimizer -> Gate",
      baseline: "Current Baseline: Static CI YAML only; no 503 fault sim or prompt rewrite.",
      vendors: "Eliminates: Veris Simulator, LangSmith",
    },
  ];

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) {
      node.className = className;
    }
    if (text !== undefined && text !== null) {
      node.textContent = String(text);
    }
    return node;
  }

  async function apiGet(path) {
    const resp = await fetch(path, { credentials: "same-origin" });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ detail: resp.statusText }));
      throw new Error(err.detail || resp.statusText);
    }
    return resp.json();
  }

  async function apiPost(path, body) {
    const resp = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": state.csrfToken,
      },
      body: JSON.stringify(body || {}),
    });
    const data = await resp.json().catch(() => ({ detail: resp.statusText }));
    if (!resp.ok) {
      throw new Error(data.detail || resp.statusText);
    }
    return data;
  }

  function applyTenantBranding(tenant) {
    if (!tenant) {
      return;
    }
    document.getElementById("app-title").textContent = tenant.copilot_title;
    document.getElementById("org-subtitle").textContent = tenant.organization_display_name;
    document.getElementById("brand-badge").textContent = tenant.theme.badge_text;
    document.getElementById("term-observability").textContent = tenant.terminology.observability_name;
    document.getElementById("term-wallet").textContent = tenant.terminology.wallet_name;
    document.getElementById("term-guardrail").textContent =
      tenant.terminology.guardrail_policy_name + " TCO Calculator";
    document.documentElement.style.setProperty("--accent-primary", tenant.theme.accent_primary);
    document.documentElement.style.setProperty("--accent-secondary", tenant.theme.accent_secondary);
  }

  function renderIncidentList() {
    const container = document.getElementById("incident-list");
    container.replaceChildren();
    state.incidents.forEach((inc) => {
      const btn = el(
        "button",
        "incident-item" +
          (state.selectedIncident && state.selectedIncident.incident_id === inc.incident_id
            ? " selected"
            : "")
      );
      btn.type = "button";
      const top = el("div", "incident-item-top");
      top.appendChild(el("span", "", inc.incident_id));
      top.appendChild(el("span", "", inc.severity));
      btn.appendChild(top);
      btn.appendChild(el("div", "incident-item-title", inc.title));
      btn.addEventListener("click", () => {
        state.selectedIncident = inc;
        document.getElementById("selected-incident-heading").textContent =
          inc.incident_id + ": " + inc.title;
        document.getElementById("copilot-prompt-input").value = inc.default_prompt;
        renderIncidentList();
      });
      container.appendChild(btn);
    });
  }

  function renderMemories(memories) {
    const container = document.getElementById("memory-list");
    container.replaceChildren();
    (memories || []).forEach((m) => {
      const box = el("div", "memory-entry");
      box.appendChild(el("strong", "", "[" + (m.incident_id || "MEM") + "] "));
      box.appendChild(el("span", "", m.fact));
      container.appendChild(box);
    });
  }

  function renderTriageResult(data) {
    const panel = document.getElementById("triage-results-panel");
    panel.replaceChildren();

    const sdpNotice = document.getElementById("inline-sdp-notice");
    if (data.pii_masked_inline) {
      sdpNotice.classList.remove("hidden");
    } else {
      sdpNotice.classList.add("hidden");
    }

    if (data.correlated_bundle) {
      const b = data.correlated_bundle;
      const corrCard = el("div", "card");
      corrCard.appendChild(
        el("h3", "", "Parallel 3-Way MCP Triage & JoinNode Correlation (" + b.app_id + ")")
      );
      corrCard.appendChild(el("p", "muted-note", "Observability: " + b.observability.summary));
      corrCard.appendChild(el("p", "muted-note", "Jira & Freeze: " + b.jira_change.summary));
      corrCard.appendChild(el("p", "muted-note", "CMDB & Runbook: " + b.cmdb_runbook.summary));
      if (data.sandbox_anomaly) {
        corrCard.appendChild(
          el(
            "p",
            "mono-note",
            "Native gVisor Sandbox: " + data.sandbox_anomaly.calculation_summary
          )
        );
      }
      panel.appendChild(corrCard);
    }

    if (data.assessment) {
      const a = data.assessment;
      const synthCard = el("div", "card");
      synthCard.appendChild(
        el("h3", "", "Synthesizer Assessment (" + a.risk_level + " -> " + a.recommended_route + ")")
      );
      synthCard.appendChild(el("p", "", a.root_cause_summary));
      synthCard.appendChild(el("p", "muted-note", "Remediation Plan: " + a.remediation_plan));
      synthCard.appendChild(
        el("p", "mono-note", "Citations: " + (a.citations || []).join(", ") + " | Trace: " + data.trace_id)
      );
      panel.appendChild(synthCard);
    }

    const approvalCard = document.getElementById("ag3-approval-card");
    if (data.pending_approval) {
      state.activeSessionId = data.session_id;
      state.activeInterruptId = data.pending_approval.interrupt_id;
      document.getElementById("approval-plan-summary").textContent =
        data.pending_approval.remediation_plan;
      const freezeBanner = document.getElementById("approval-freeze-banner");
      if (data.pending_approval.change_freeze_active) {
        freezeBanner.classList.remove("hidden");
      } else {
        freezeBanner.classList.add("hidden");
      }
      approvalCard.classList.remove("hidden");
    } else {
      approvalCard.classList.add("hidden");
    }

    if (data.postmortem_record) {
      const outCard = el("div", "card");
      outCard.appendChild(
        el("h3", "", "Final Resolution (" + data.postmortem_record.final_status + ")")
      );
      outCard.appendChild(el("p", "", data.postmortem_record.executive_summary));
      panel.appendChild(outCard);
    }
  }

  function renderProofCards() {
    const grid = document.getElementById("proof-cards-grid");
    grid.replaceChildren();
    PROOF_DEFINITIONS.forEach((def) => {
      const card = el("div", "proof-card");
      card.id = "proof-card-" + def.id;
      const top = el("div", "");
      top.appendChild(el("h4", "", def.title));
      top.appendChild(el("p", "muted-note", def.baseline));
      top.appendChild(el("p", "mono-note", def.vendors));
      const resultLine = el("div", "muted-note", "Click Run Live Proof to execute.");
      resultLine.id = "proof-result-" + def.id;
      const btn = el("button", "small-btn", "Run Live Proof");
      btn.type = "button";
      btn.addEventListener("click", async () => {
        resultLine.textContent = "Running live verification...";
        try {
          const res = await apiPost("/api/steward/proofs/" + def.id, {});
          resultLine.textContent =
            "[" +
            (res.passed ? "PASS" : "FAIL") +
            " in " +
            res.latency_ms +
            "ms] " +
            res.measured_evidence;
        } catch (err) {
          resultLine.textContent = "Error: " + err.message;
        }
      });
      card.appendChild(top);
      card.appendChild(resultLine);
      card.appendChild(btn);
      grid.appendChild(card);
    });
  }

  function renderTco(tco) {
    if (!tco) {
      return;
    }
    const container = document.getElementById("tco-breakdown");
    container.replaceChildren();

    const b1 = el("div", "tco-box");
    b1.appendChild(el("strong", "", "Azure Content Safety"));
    b1.appendChild(
      el("div", "", "$" + Math.round(tco.azure_content_safety_annual_usd).toLocaleString() + " / yr")
    );

    const b2 = el("div", "tco-box");
    b2.appendChild(el("strong", "", "AWS Bedrock Guardrails"));
    b2.appendChild(
      el(
        "div",
        "",
        "$" + Math.round(tco.aws_bedrock_guardrails_annual_usd).toLocaleString() + " / yr"
      )
    );

    const b3 = el("div", "tco-box highlight");
    b3.appendChild(el("strong", "", "Google Cloud Model Armor"));
    b3.appendChild(
      el("div", "", "$" + Math.round(tco.google_model_armor_annual_usd).toLocaleString() + " / yr")
    );
    b3.appendChild(
      el(
        "div",
        "mono-note",
        "Saves $" +
          Math.round(tco.annual_savings_vs_azure_usd).toLocaleString() +
          "/yr vs Azure (90%)"
      )
    );

    container.appendChild(b1);
    container.appendChild(b2);
    container.appendChild(b3);
  }

  function renderAgentAndWallet(agentState, walletState) {
    if (agentState) {
      const pill = document.getElementById("agent-status-pill");
      pill.textContent = agentState.status || "ACTIVE";
    }
    if (walletState) {
      const spentUsd = ((walletState.spent_nano_usd || 0) / 1e9).toFixed(6);
      const capUsd = ((walletState.monthly_cap_nano_usd || 0) / 1e9).toFixed(4);
      const resolved = walletState.resolved_incidents_count || 0;
      document.getElementById("wallet-summary-text").textContent =
        "$" + spentUsd + " spent / $" + capUsd + " cap (" + resolved + " resolved)";
    }
  }

  function renderTelemetry(traces, ledger) {
    const traceBox = document.getElementById("trace-waterfall-list");
    traceBox.replaceChildren();
    (traces || []).slice(0, 5).forEach((t) => {
      const row = el("div", "trace-row");
      const stages = (t.spans || []).map((s) => s.span_name + " (" + s.duration_ms + "ms)").join(" -> ");
      row.appendChild(el("strong", "", "Trace " + t.trace_id.slice(0, 16) + "... [" + t.scape_mode + "] "));
      row.appendChild(el("div", "muted-note", stages || "Root span initialized"));
      traceBox.appendChild(row);
    });

    const ledgerBox = document.getElementById("ledger-table-box");
    ledgerBox.replaceChildren();
    (ledger || []).slice(0, 5).forEach((r) => {
      const row = el("div", "trace-row");
      row.textContent =
        r.incident_id +
        " | " +
        r.outcome +
        " | turn=" +
        r.total_cost_nano_usd +
        " nano-USD | cost_per_resolved_incident=" +
        r.cost_per_resolved_incident_nano_usd +
        " nano-USD";
      ledgerBox.appendChild(row);
    });
  }

  async function init() {
    renderProofCards();
    const boot = await apiGet("/api/bootstrap");
    state.csrfToken = boot.csrf_token;
    state.scapeMode = boot.scape_mode;
    state.tenantProfile = boot.tenant.profile_key;
    state.incidents = boot.incidents || [];
    state.selectedIncident = state.incidents[0] || null;

    document.getElementById("mode-select").value = state.scapeMode;
    document.getElementById("profile-select").value = state.tenantProfile;
    applyTenantBranding(boot.tenant);
    renderIncidentList();
    if (state.selectedIncident) {
      document.getElementById("copilot-prompt-input").value = state.selectedIncident.default_prompt;
    }
    renderMemories(boot.recent_memories);
    renderAgentAndWallet(boot.agent_state, boot.wallet_state);
    if (boot.identity_posture) {
      document.getElementById("posture-summary-text").textContent = boot.identity_posture.summary;
    }
    renderTco(boot.tco_default);
    renderTelemetry(boot.recent_traces, boot.recent_ledger);

    if (boot.prompt_registry) {
      document.getElementById("prompt-v1-pre").textContent = boot.prompt_registry.v1_prompt;
      document.getElementById("prompt-v2-pre").textContent = boot.prompt_registry.v2_prompt;
      const sc = document.getElementById("flywheel-scorecard");
      sc.replaceChildren(
        el(
          "span",
          "status-chip",
          "Active Version: " +
            boot.prompt_registry.active.active_version +
            " (behavior_score=" +
            boot.prompt_registry.active.behavior_score +
            ")"
        )
      );
    }

    // Tab switching
    document.getElementById("tab-copilot").addEventListener("click", () => {
      document.getElementById("tab-copilot").classList.add("active");
      document.getElementById("tab-steward").classList.remove("active");
      document.getElementById("view-copilot").classList.remove("hidden");
      document.getElementById("view-steward").classList.add("hidden");
    });
    document.getElementById("tab-steward").addEventListener("click", () => {
      document.getElementById("tab-steward").classList.add("active");
      document.getElementById("tab-copilot").classList.remove("active");
      document.getElementById("view-steward").classList.remove("hidden");
      document.getElementById("view-copilot").classList.add("hidden");
    });

    // Mode & Tenant switching
    const handleConfigChange = async () => {
      state.scapeMode = document.getElementById("mode-select").value;
      state.tenantProfile = document.getElementById("profile-select").value;
      const res = await apiPost("/api/config/mode", {
        scape_mode: state.scapeMode,
        tenant_profile: state.tenantProfile,
      });
      applyTenantBranding(res.tenant);
    };
    document.getElementById("mode-select").addEventListener("change", handleConfigChange);
    document.getElementById("profile-select").addEventListener("change", handleConfigChange);

    // Copilot triage run
    document.getElementById("btn-run-triage").addEventListener("click", async () => {
      const statusEl = document.getElementById("copilot-run-status");
      statusEl.textContent = "Running Workflow...";
      try {
        const inc = state.selectedIncident || state.incidents[0];
        const res = await apiPost("/api/copilot/triage", {
          incident_id: inc.incident_id,
          service_name: inc.service_name,
          app_id: inc.app_id,
          operator_prompt: document.getElementById("copilot-prompt-input").value,
          scape_mode: state.scapeMode,
          tenant_profile: state.tenantProfile,
        });
        statusEl.textContent = res.status;
        renderTriageResult(res);
      } catch (err) {
        statusEl.textContent = "Blocked: " + err.message;
        const panel = document.getElementById("triage-results-panel");
        panel.replaceChildren(el("div", "warning-banner", err.message));
      }
    });

    // HITL Approve / Hold
    const submitHitl = async (approved) => {
      const statusEl = document.getElementById("copilot-run-status");
      statusEl.textContent = "Resuming Workflow...";
      try {
        const res = await apiPost("/api/copilot/resume", {
          session_id: state.activeSessionId,
          interrupt_id: state.activeInterruptId,
          approved: approved,
          approver_principal: "sre-oncall-lead",
          vp_exception_ticket: document.getElementById("vp-ticket-input").value || null,
          reason: approved
            ? "Approved governed canary rollback."
            : "Held pending VP Change-Freeze Exception.",
        });
        document.getElementById("ag3-approval-card").classList.add("hidden");
        statusEl.textContent = res.status;
        renderTriageResult(res);
        renderMemories(res.memories);
      } catch (err) {
        statusEl.textContent = "Error: " + err.message;
      }
    };
    document
      .getElementById("btn-approve-rollback")
      .addEventListener("click", () => submitHitl(true));
    document
      .getElementById("btn-hold-exception")
      .addEventListener("click", () => submitHitl(false));

    // Kill switch buttons
    document.querySelectorAll("[data-kill]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const res = await apiPost("/api/steward/kill-switch", {
          status: btn.getAttribute("data-kill"),
        });
        renderAgentAndWallet(res.agent_state, null);
      });
    });

    // Wallet cap buttons
    document.getElementById("btn-cap-normal").addEventListener("click", async () => {
      const res = await apiPost("/api/steward/wallet-cap", {
        monthly_cap_nano_usd: 15000000000,
        reset_spend: true,
      });
      renderAgentAndWallet(null, res.wallet_state);
    });
    document.getElementById("btn-cap-tight").addEventListener("click", async () => {
      const res = await apiPost("/api/steward/wallet-cap", {
        monthly_cap_nano_usd: 1000,
        reset_spend: false,
      });
      renderAgentAndWallet(null, res.wallet_state);
    });

    // OBO verify
    document.getElementById("btn-verify-obo").addEventListener("click", async () => {
      const res = await apiPost("/api/steward/obo-verify", {});
      document.getElementById("obo-verify-output").textContent =
        "azp=" +
        res.adr011_valid_pair.authorized_party_azp +
        " verified=true | legacy_sub_equal=" +
        res.adr011_valid_pair.legacy_adr008_sub_check_would_pass +
        " | rogue_azp_blocked=" +
        res.mismatched_azp_blocked_fail_closed;
    });

    // Run all 8 proofs
    document.getElementById("btn-run-all-proofs").addEventListener("click", async () => {
      const btn = document.getElementById("btn-run-all-proofs");
      btn.textContent = "Running All 8 Live Proofs...";
      const res = await apiPost("/api/steward/proofs-all", {});
      (res.proofs || []).forEach((p) => {
        const line = document.getElementById("proof-result-" + p.proof_id);
        if (line) {
          line.textContent =
            "[" + (p.passed ? "PASS" : "FAIL") + " in " + p.latency_ms + "ms] " + p.measured_evidence;
        }
      });
      btn.textContent = "All 8 Proofs Passed (" + res.passed_count + "/" + res.total_count + ")";
    });

    // TCO Slider
    document.getElementById("tco-slider").addEventListener("input", async (ev) => {
      const val = parseInt(ev.target.value, 10);
      document.getElementById("tco-volume-label").textContent = val.toLocaleString();
      const tco = await apiPost("/api/steward/tco", { daily_turns: val, tokens_per_turn: 1000 });
      renderTco(tco);
    });

    // Threat lab presets & test
    document.querySelectorAll("[data-threat]").forEach((btn) => {
      btn.addEventListener("click", () => {
        document.getElementById("threat-input").value = btn.getAttribute("data-threat");
      });
    });
    document.getElementById("btn-test-threat").addEventListener("click", async () => {
      const box = document.getElementById("threat-verdict-box");
      box.replaceChildren(el("div", "muted-note", "Inspecting via Model Armor..."));
      const res = await apiPost("/api/steward/guardrail-test", {
        sample_text: document.getElementById("threat-input").value,
      });
      box.replaceChildren(
        el("strong", "", (res.allowed ? "ALLOWED" : "BLOCKED") + " (" + res.action_taken + ")"),
        el("div", "muted-note", res.summary),
        el("div", "mono-note", "Sanitized Output: " + (res.sanitized_text || "[BLOCKED]"))
      );
    });

    // Closed-loop flywheel button
    document.getElementById("btn-run-flywheel").addEventListener("click", async () => {
      const sc = document.getElementById("flywheel-scorecard");
      sc.replaceChildren(el("span", "risk-badge", "Running 5-Stage Closed-Loop Flywheel..."));
      const res = await apiPost("/api/steward/closed-loop-eval", {});
      sc.replaceChildren(
        el(
          "span",
          "risk-badge",
          "v1=" + res.v1_baseline.behavior_score + " (" + res.v1_baseline.gate_verdict + ")"
        ),
        el(
          "span",
          "status-chip",
          "Promoted v2=" +
            res.v2_candidate.behavior_score +
            " (" +
            res.v2_candidate.cases_passed +
            "/" +
            res.v2_candidate.cases_total +
            " Passed in " +
            res.elapsed_seconds +
            "s)"
        )
      );
    });

    // Telemetry refresh
    document.getElementById("btn-refresh-telemetry").addEventListener("click", async () => {
      const snap = await apiGet("/api/steward/telemetry");
      renderAgentAndWallet(snap.agent_state, snap.wallet_state);
      renderTelemetry(snap.recent_traces, snap.recent_ledger);
    });
  }

  document.addEventListener("DOMContentLoaded", init);
})();
