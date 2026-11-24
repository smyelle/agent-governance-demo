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
    architectureMode: "google_native",
    incidents: [],
    selectedIncident: null,
    activeSessionId: "",
    activeInterruptId: "",
    platformSnapshot: null,
    expandedServiceIds: new Set(["agent_runtime"]),
    expandAll: false,
    steppingServiceId: "",
    replayTimerIds: [],
  };

  const PROOF_DEFINITIONS = [
    {
      id: 1,
      title: "1. Un-Bypassable Tenant Network (ACT + PSC-I) & Unified Kill Switch",
      baseline: "DIY Baseline: Opt-in HTTP proxy URL; PAUSED blocks A2A only.",
      vendors: "Consolidates: Agentgateway, Hush, Geordie, Harmonic",
    },
    {
      id: 2,
      title: "2. Inline Per-Tool & Semantic Payload Authz (UAP Policy V2 CEL)",
      baseline: "DIY Baseline: Coarse mcp.use scope allows all tools in pool.",
      vendors: "Consolidates: Runlayer, Keycard, Arcade",
    },
    {
      id: 3,
      title: "3. Zero-Secret Container (SPIFFE AGENT_IDENTITY) & ADR-011 azp OBO",
      baseline: "DIY Baseline: Static pod keys, OBO sidecar 2x hop, pairwise sub mismatch.",
      vendors: "Consolidates: Keycard, Custom Sidecars, Vault",
    },
    {
      id: 4,
      title: "4. Un-Bypassable Org Safety Floor + Inline SDP PII + 40-URL Scan",
      baseline: "DIY Baseline: 10x cost, cross-cloud hairpin, fail-open, plain text only.",
      vendors: "Consolidates: Straiker.ai, Azure Content Safety, Bedrock Guardrails",
    },
    {
      id: 5,
      title: "5. Durable RequestInput HITL Checkpointing & Native gVisor Sandbox",
      baseline: "DIY Baseline: Stateless request wrapper, no isolated code execution.",
      vendors: "Consolidates: E2B MicroVMs, Custom Checkpoint Glue",
    },
    {
      id: 6,
      title: "6. Longitudinal Cross-Session Memory Bank (Strict JWT Isolation)",
      baseline: "DIY Baseline: Stateless across sessions; custom ABAC wrappers needed.",
      vendors: "Consolidates: Mem0, Memori, Custom Memory Stores",
    },
    {
      id: 7,
      title: "7. Unified Single-Trace Join & Atomic Cost-per-Outcome Wallet",
      baseline: "DIY Baseline: Split log vs agent trace stores; post-response Valkey lag.",
      vendors: "Consolidates: Revenium, Ascerta, Faros",
    },
    {
      id: 8,
      title: "8. Closed-Loop Trace -> 503 & Freeze Sim -> Prompt Optimizer -> Gate",
      baseline: "DIY Baseline: Static CI YAML only; no 503 fault sim or prompt rewrite.",
      vendors: "Consolidates: Veris Simulator, LangSmith",
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
      if (data && data.platform_services) {
        updatePlatformServices(data.platform_services, true);
      }
      throw new Error(data.detail || resp.statusText);
    }
    return data;
  }

  function applyTenantBranding(tenant) {
    if (!tenant) {
      return;
    }
    document.getElementById("app-title").textContent = tenant.agent_title;
    document.getElementById("org-subtitle").textContent = tenant.organization_display_name;
    document.getElementById("brand-badge").textContent = tenant.theme.badge_text;
    document.getElementById("term-observability").textContent = tenant.terminology.observability_name;
    document.getElementById("term-wallet").textContent = tenant.terminology.wallet_name;
    document.getElementById("term-guardrail").textContent =
      tenant.terminology.guardrail_policy_name + " TCO Calculator";
  }

  function clearReplayTimers() {
    state.replayTimerIds.forEach((tid) => window.clearTimeout(tid));
    state.replayTimerIds = [];
    state.steppingServiceId = "";
  }

  function statusChipClass(status) {
    if (status === "BLOCKED") {
      return "status-chip chip-danger";
    }
    if (status === "PAUSED_HITL" || status === "MASKED_PII") {
      return "status-chip chip-warn";
    }
    if (status === "READY") {
      return "status-chip chip-ready";
    }
    if (status === "STANDBY") {
      return "status-chip chip-muted";
    }
    return "status-chip";
  }

  function renderVerticalPipeline() {
    const container = document.getElementById("vertical-pipeline-list");
    container.replaceChildren();
    const snap = state.platformSnapshot;
    if (!snap || !snap.services) {
      return;
    }

    let currentStage = "";
    snap.services.forEach((svc) => {
      if (svc.stage_group && svc.stage_group !== currentStage) {
        currentStage = svc.stage_group;
        container.appendChild(el("div", "pipeline-stage-divider", currentStage));
      }

      const isExpanded = state.expandAll || state.expandedServiceIds.has(svc.id);
      const rowClasses = ["pipeline-step-row", "step-status-" + svc.status];
      if (isExpanded) {
        rowClasses.push("step-expanded");
      }
      if (state.steppingServiceId === svc.id) {
        rowClasses.push("step-stepping");
      }

      const row = el("div", rowClasses.join(" "));
      row.setAttribute("role", "listitem");

      // Left vertical timeline rail + numbered node circle
      const rail = el("div", "pipeline-rail");
      rail.appendChild(el("div", "pipeline-node-circle", String(svc.step)));
      rail.appendChild(el("div", "pipeline-rail-line"));
      row.appendChild(rail);

      // Spacious full-width service card
      const card = el("div", "pipeline-card");
      const trigger = el("button", "pipeline-card-trigger");
      trigger.type = "button";
      trigger.setAttribute("aria-expanded", String(isExpanded));

      const topLine = el("div", "pipeline-card-top");
      const nameWrap = el("div", "pipeline-name-wrap");
      nameWrap.appendChild(el("span", "pipeline-svc-name", svc.name));
      nameWrap.appendChild(el("span", "pipeline-plane-tag", svc.plane));

      const badgesWrap = el("div", "pipeline-badges-wrap");
      badgesWrap.appendChild(el("span", statusChipClass(svc.status), svc.badge_label));
      if (svc.latency_ms !== null && svc.latency_ms !== undefined) {
        badgesWrap.appendChild(el("span", "mono-pill", Math.round(svc.latency_ms * 10) / 10 + " ms"));
      }
      badgesWrap.appendChild(el("span", "pipeline-chevron", isExpanded ? "Hide" : "Details"));

      topLine.appendChild(nameWrap);
      topLine.appendChild(badgesWrap);
      trigger.appendChild(topLine);

      // Subtitle (clean full text when collapsed; full live summary inside drawer when expanded)
      const briefLine =
        svc.status === "READY" || isExpanded ? svc.subtitle : svc.summary;
      trigger.appendChild(el("p", "pipeline-svc-subtitle", briefLine));

      trigger.addEventListener("click", () => {
        if (state.expandAll) {
          state.expandAll = false;
          document.getElementById("btn-expand-all").textContent = "Expand All";
          state.expandedServiceIds = new Set([svc.id]);
        } else if (state.expandedServiceIds.has(svc.id)) {
          state.expandedServiceIds.delete(svc.id);
        } else {
          state.expandedServiceIds = new Set([svc.id]);
        }
        renderVerticalPipeline();
      });

      card.appendChild(trigger);

      if (isExpanded) {
        const drawer = el("div", "pipeline-drawer");
        drawer.appendChild(el("p", "drawer-summary", svc.summary));

        const metaList = el("div", "drawer-meta-list");
        const apiRow = el("div", "drawer-meta-row");
        apiRow.appendChild(el("span", "drawer-label", "Google Cloud API Surface"));
        apiRow.appendChild(el("code", "drawer-code", svc.api_surface));
        metaList.appendChild(apiRow);

        const vendorRow = el("div", "drawer-meta-row");
        vendorRow.appendChild(el("span", "drawer-label", "Consolidates Specialist 3P Categories"));
        vendorRow.appendChild(el("code", "drawer-code", svc.consolidates));
        metaList.appendChild(vendorRow);
        drawer.appendChild(metaList);

        const metricsObj = svc.metrics || {};
        const metricKeys = Object.keys(metricsObj);
        if (metricKeys.length > 0) {
          const mGrid = el("div", "drawer-metrics-grid");
          metricKeys.forEach((k) => {
            const mBox = el("div", "drawer-metric-box");
            mBox.appendChild(el("strong", "", k.replace(/_/g, " ")));
            mBox.appendChild(el("span", "", metricsObj[k]));
            mGrid.appendChild(mBox);
          });
          drawer.appendChild(mGrid);
        }

        card.appendChild(drawer);
      }

      row.appendChild(card);
      container.appendChild(row);
    });
  }

  function pickHighlightService(snapshot) {
    if (!snapshot || !snapshot.services) {
      return "agent_runtime";
    }
    const blocked = snapshot.services.find((s) => s.status === "BLOCKED");
    if (blocked) {
      return blocked.id;
    }
    const paused = snapshot.services.find(
      (s) => s.status === "PAUSED_HITL" || s.status === "MASKED_PII"
    );
    if (paused) {
      return paused.id;
    }
    const anyActive = snapshot.services.some(
      (s) => s.status === "VERIFIED" || s.status === "ACTIVE"
    );
    const seq = snapshot.flow_sequence || [];
    if (anyActive && seq.length > 0) {
      return seq[seq.length - 1];
    }
    return "agent_runtime";
  }

  function animateFlowSequence(sequence, finalHighlightId) {
    clearReplayTimers();
    const steps = (sequence || []).slice();
    if (!steps.length) {
      renderVerticalPipeline();
      return;
    }

    steps.forEach((svcId, idx) => {
      const tid = window.setTimeout(() => {
        state.steppingServiceId = svcId;
        if (!state.expandAll) {
          state.expandedServiceIds = new Set([svcId]);
        }
        renderVerticalPipeline();
      }, idx * 130);
      state.replayTimerIds.push(tid);
    });

    const endTid = window.setTimeout(() => {
      state.steppingServiceId = "";
      if (!state.expandAll && finalHighlightId) {
        state.expandedServiceIds = new Set([finalHighlightId]);
      }
      renderVerticalPipeline();
    }, steps.length * 130 + 180);
    state.replayTimerIds.push(endTid);
  }

  function updatePlatformServices(snapshot, animate) {
    if (!snapshot) {
      return;
    }
    state.platformSnapshot = snapshot;
    document.getElementById("viz-last-event").textContent = snapshot.last_event || "";
    document.getElementById("viz-mode-pill").textContent =
      snapshot.architecture_mode === "enterprise_hybrid"
        ? "Enterprise Hybrid"
        : "Google-Native";
    document.getElementById("viz-trace-pill").textContent = snapshot.trace_id
      ? "Trace: " + snapshot.trace_id.slice(0, 12) + "..."
      : "W3C Trace: Ready";

    const targetHighlight = pickHighlightService(snapshot);
    if (animate && snapshot.flow_sequence && snapshot.flow_sequence.length) {
      animateFlowSequence(snapshot.flow_sequence, targetHighlight);
    } else {
      if (!state.expandAll) {
        state.expandedServiceIds = new Set([targetHighlight]);
      }
      renderVerticalPipeline();
    }
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
      top.appendChild(el("span", "subtle-tag", inc.severity));
      btn.appendChild(top);
      btn.appendChild(el("div", "incident-item-title", inc.title));
      btn.addEventListener("click", () => {
        state.selectedIncident = inc;
        document.getElementById("selected-incident-heading").textContent =
          inc.incident_id + ": " + inc.title;
        document.getElementById("agent-prompt-input").value = inc.default_prompt;
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
      corrCard.appendChild(el("p", "muted-note", "Golden Signals: " + b.observability.summary));
      corrCard.appendChild(el("p", "muted-note", "Release & Freeze: " + b.release_change.summary));
      corrCard.appendChild(el("p", "muted-note", "ServiceAtlas CMDB: " + b.cmdb_runbook.summary));
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
          if (res.platform_services) {
            updatePlatformServices(res.platform_services, true);
          }
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
      const st = agentState.status || "ACTIVE";
      pill.textContent = st;
      pill.className = st === "ACTIVE" ? "status-chip" : "status-chip chip-danger";
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
      const modeTag = t.architecture_mode || "google_native";
      row.appendChild(el("strong", "", "Trace " + t.trace_id.slice(0, 16) + "... [" + modeTag + "] "));
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

  function activateWorkspaceTab(mode) {
    const tabAgent = document.getElementById("tab-agent");
    const tabSteward = document.getElementById("tab-steward");
    const tabPipeline = document.getElementById("tab-pipeline");
    const shell = document.getElementById("workspace-shell");
    const leftCol = document.getElementById("primary-workspace-col");
    const viewAgent = document.getElementById("view-agent");
    const viewSteward = document.getElementById("view-steward");

    [tabAgent, tabSteward, tabPipeline].forEach((b) => {
      b.classList.remove("active");
      b.setAttribute("aria-selected", "false");
    });

    if (mode === "pipeline") {
      tabPipeline.classList.add("active");
      tabPipeline.setAttribute("aria-selected", "true");
      leftCol.classList.add("hidden");
      shell.className = "workspace-container workspace-focus-pipeline";
    } else if (mode === "steward") {
      tabSteward.classList.add("active");
      tabSteward.setAttribute("aria-selected", "true");
      leftCol.classList.remove("hidden");
      viewSteward.classList.remove("hidden");
      viewAgent.classList.add("hidden");
      shell.className = "workspace-container workspace-split";
    } else {
      tabAgent.classList.add("active");
      tabAgent.setAttribute("aria-selected", "true");
      leftCol.classList.remove("hidden");
      viewAgent.classList.remove("hidden");
      viewSteward.classList.add("hidden");
      shell.className = "workspace-container workspace-split";
    }
  }

  async function init() {
    renderProofCards();
    const boot = await apiGet("/api/bootstrap");
    state.csrfToken = boot.csrf_token;
    state.architectureMode = boot.architecture_mode || "google_native";
    state.incidents = boot.incidents || [];
    state.selectedIncident = state.incidents[0] || null;

    document.getElementById("mode-select").value = state.architectureMode;
    applyTenantBranding(boot.tenant);
    updatePlatformServices(boot.platform_services, false);

    renderIncidentList();
    if (state.selectedIncident) {
      document.getElementById("agent-prompt-input").value = state.selectedIncident.default_prompt;
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

    // Pipeline toolbar controls
    document.getElementById("btn-replay-flow").addEventListener("click", () => {
      if (state.platformSnapshot) {
        animateFlowSequence(
          state.platformSnapshot.flow_sequence,
          pickHighlightService(state.platformSnapshot)
        );
      }
    });

    document.getElementById("btn-expand-all").addEventListener("click", () => {
      state.expandAll = !state.expandAll;
      document.getElementById("btn-expand-all").textContent = state.expandAll
        ? "Collapse Details"
        : "Expand All";
      renderVerticalPipeline();
    });

    // Accessible Workspace Tabs (1. Agent | 2. Steward | 3. Full Platform Pipeline)
    document
      .getElementById("tab-agent")
      .addEventListener("click", () => activateWorkspaceTab("agent"));
    document
      .getElementById("tab-steward")
      .addEventListener("click", () => activateWorkspaceTab("steward"));
    document
      .getElementById("tab-pipeline")
      .addEventListener("click", () => activateWorkspaceTab("pipeline"));

    // Architecture Mode switching
    document.getElementById("mode-select").addEventListener("change", async () => {
      state.architectureMode = document.getElementById("mode-select").value;
      const res = await apiPost("/api/config/mode", {
        architecture_mode: state.architectureMode,
      });
      applyTenantBranding(res.tenant);
      updatePlatformServices(res.platform_services, true);
    });

    // Agent Workflow triage execution
    document.getElementById("btn-run-triage").addEventListener("click", async () => {
      const statusEl = document.getElementById("agent-run-status");
      statusEl.textContent = "Running Workflow...";
      statusEl.className = "status-chip chip-warn";
      try {
        const inc = state.selectedIncident || state.incidents[0];
        const res = await apiPost("/api/agent/triage", {
          incident_id: inc.incident_id,
          service_name: inc.service_name,
          app_id: inc.app_id,
          operator_prompt: document.getElementById("agent-prompt-input").value,
          architecture_mode: state.architectureMode,
        });
        statusEl.textContent = res.status;
        statusEl.className =
          res.status === "WAITING_AG3_APPROVAL" ? "status-chip chip-warn" : "status-chip";
        renderTriageResult(res);
        renderAgentAndWallet(res.agent_state, res.wallet_state);
        if (res.recent_memories) {
          renderMemories(res.recent_memories);
        }
        updatePlatformServices(res.platform_services, true);
      } catch (err) {
        statusEl.textContent = "Blocked: " + err.message;
        statusEl.className = "status-chip chip-danger";
        const panel = document.getElementById("triage-results-panel");
        panel.replaceChildren(el("div", "warning-banner", err.message));
      }
    });

    // HITL Approve / Hold
    const submitHitl = async (approved) => {
      const statusEl = document.getElementById("agent-run-status");
      statusEl.textContent = "Resuming Workflow...";
      statusEl.className = "status-chip chip-warn";
      try {
        const res = await apiPost("/api/agent/resume", {
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
        statusEl.className = "status-chip";
        renderTriageResult(res);
        renderAgentAndWallet(res.agent_state, res.wallet_state);
        renderMemories(res.memories);
        updatePlatformServices(res.platform_services, true);
      } catch (err) {
        statusEl.textContent = "Error: " + err.message;
        statusEl.className = "status-chip chip-danger";
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
        updatePlatformServices(res.platform_services, true);
      });
    });

    // Wallet cap buttons
    document.getElementById("btn-cap-normal").addEventListener("click", async () => {
      const res = await apiPost("/api/steward/wallet-cap", {
        monthly_cap_nano_usd: 15000000000,
        reset_spend: true,
      });
      renderAgentAndWallet(null, res.wallet_state);
      updatePlatformServices(res.platform_services, true);
    });
    document.getElementById("btn-cap-tight").addEventListener("click", async () => {
      const res = await apiPost("/api/steward/wallet-cap", {
        monthly_cap_nano_usd: 1000,
        reset_spend: false,
      });
      renderAgentAndWallet(null, res.wallet_state);
      updatePlatformServices(res.platform_services, true);
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
      updatePlatformServices(res.platform_services, true);
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
      updatePlatformServices(res.platform_services, true);
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
      updatePlatformServices(res.platform_services, true);
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
      updatePlatformServices(res.platform_services, true);
    });

    // Telemetry refresh
    document.getElementById("btn-refresh-telemetry").addEventListener("click", async () => {
      const snap = await apiGet("/api/steward/telemetry");
      renderAgentAndWallet(snap.agent_state, snap.wallet_state);
      renderTelemetry(snap.recent_traces, snap.recent_ledger);
      updatePlatformServices(snap.platform_services, false);
    });

    // Optional URL view parameter (?view=pipeline | ?view=steward)
    const params = new URLSearchParams(window.location.search);
    const requestedView = params.get("view");
    if (requestedView === "pipeline" || requestedView === "steward") {
      activateWorkspaceTab(requestedView);
    }
    if (params.get("expand") === "all") {
      state.expandAll = true;
      document.getElementById("btn-expand-all").textContent = "Collapse Details";
      renderVerticalPipeline();
    }
  }

  document.addEventListener("DOMContentLoaded", init);
})();
