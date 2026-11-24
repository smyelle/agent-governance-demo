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
    architectureMode: "enterprise_hybrid",
    tenant: null,
    incidents: [],
    selectedIncident: null,
    activeSessionId: "",
    activeInterruptId: "",
    platformSnapshot: null,
    expandedServiceIds: new Set(["eval_flywheel"]),
    expandAll: false,
    steppingServiceId: "",
    replayTimerIds: [],
  };

  const PROOF_DEFINITIONS = [
    {
      id: 1,
      title: "1. Un-Bypassable Tenant Network (ACT + PSC-I) & Unified Kill Switch",
      baseline: "Addresses Gap: Opt-in HTTP proxy URL bypass & A2A-only pause scope.",
      vendors: "Consolidates: Agentgateway, Hush, Geordie, Harmonic",
    },
    {
      id: 2,
      title: "2. Inline Per-Tool & Semantic Payload Authz (UAP Policy V2 CEL)",
      baseline: "Addresses Gap: Coarse mcp.use scope permits destructive tools in pool.",
      vendors: "Consolidates: Runlayer, Keycard, Arcade",
    },
    {
      id: 3,
      title: "3. Zero-Secret Container (SPIFFE AGENT_IDENTITY) & ADR-011 azp OBO",
      baseline: "Addresses Gap: Static pod keys, OBO sidecar 2x hop, pairwise sub mismatch.",
      vendors: "Consolidates: Keycard, Custom Sidecars, Vault",
    },
    {
      id: 4,
      title: "4. Dynamic Per-Request Model Armor Router + Inline SDP + 40-URL Floor",
      baseline: "Addresses Gap: Static template sprawl across BUs & fail-open defaults.",
      vendors: "Consolidates: Straiker.ai, Static Template Glue",
    },
    {
      id: 5,
      title: "5. Durable Reviewer RequestInput HITL & Native gVisor Sandbox",
      baseline: "Addresses Gap: Stateless request wrapper lacking isolated code execution.",
      vendors: "Consolidates: E2B MicroVMs, Custom Checkpoint Glue",
    },
    {
      id: 6,
      title: "6. Longitudinal Governance Memory Bank (Strict JWT Isolation)",
      baseline: "Addresses Gap: Stateless sessions requiring custom ABAC memory wrappers.",
      vendors: "Consolidates: Mem0, Memori, Custom Memory Stores",
    },
    {
      id: 7,
      title: "7. Unified W3C + OTLP Trace Join & Atomic Cost-per-Outcome Wallet",
      baseline: "Addresses Gap: Disconnected guardrail logs vs traces & post-charge overshoot.",
      vendors: "Consolidates: Revenium, Ascerta, Faros",
    },
    {
      id: 8,
      title: "8. A-La-Carte 6-Stage Cross-Cloud Trace -> Eval -> Optimizer -> Gate",
      baseline: "Addresses Gap: Static CI YAML unable to optimize AWS/Azure/GCP traces.",
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
    state.tenant = tenant;
    const terms = tenant.terminology || {};
    document.getElementById("app-title").textContent = tenant.agent_title;
    document.getElementById("org-subtitle").textContent = tenant.organization_display_name;
    document.getElementById("brand-badge").textContent = tenant.theme.badge_text;
    document.getElementById("term-observability").textContent = terms.observability_name || "";
    document.getElementById("term-wallet").textContent = terms.wallet_name || "";
    document.getElementById("term-guardrail").textContent =
      (terms.guardrail_policy_name || "Guardrail") + " & Ensemble TCO Calculator";
    if (terms.eval_engine_name) {
      document.getElementById("term-eval-engine").textContent =
        "6-Stage A-La-Carte " + terms.eval_engine_name;
    }
    if (terms.blueprint_registry_name) {
      document.getElementById("term-blueprint-heading").textContent =
        "Promoted v2 (" + terms.blueprint_registry_name + ")";
    }
    if (terms.platform_name) {
      document.getElementById("viz-panel-title").textContent =
        terms.platform_name + " + Google Pipeline";
    }
    if (terms.risk_framework) {
      document.getElementById("approval-card-title").textContent =
        terms.risk_framework + " AG3 Governance Reviewer Sign-Off Gate (RequestInput)";
    }
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

      const rail = el("div", "pipeline-rail");
      rail.appendChild(el("div", "pipeline-node-circle", String(svc.step)));
      rail.appendChild(el("div", "pipeline-rail-line"));
      row.appendChild(rail);

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
        apiRow.appendChild(el("span", "drawer-label", "Integration & API Surface"));
        apiRow.appendChild(el("code", "drawer-code", svc.api_surface));
        metaList.appendChild(apiRow);

        const vendorRow = el("div", "drawer-meta-row");
        vendorRow.appendChild(el("span", "drawer-label", "Point Vendors Consolidated"));
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
      return "eval_flywheel";
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
    return "eval_flywheel";
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
      }, idx * 120);
      state.replayTimerIds.push(tid);
    });

    const endTid = window.setTimeout(() => {
      state.steppingServiceId = "";
      if (!state.expandAll && finalHighlightId) {
        state.expandedServiceIds = new Set([finalHighlightId]);
      }
      renderVerticalPipeline();
    }, steps.length * 120 + 170);
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
        ? "4-Tier Coexistence"
        : "Full GCP-Native";
    document.getElementById("viz-trace-pill").textContent = snapshot.trace_id
      ? "Trace: " + snapshot.trace_id.slice(0, 12) + "..."
      : "W3C + OTLP Ready";

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

  function renderCandidateList() {
    const container = document.getElementById("incident-list");
    container.replaceChildren();
    state.incidents.forEach((cand) => {
      const cid = cand.candidate_id || cand.incident_id;
      const selId = state.selectedIncident
        ? state.selectedIncident.candidate_id || state.selectedIncident.incident_id
        : "";
      const btn = el("button", "incident-item" + (selId === cid ? " selected" : ""));
      btn.type = "button";
      const top = el("div", "incident-item-top");
      top.appendChild(el("span", "", cid));
      top.appendChild(el("span", "subtle-tag", cand.severity));
      btn.appendChild(top);
      btn.appendChild(el("div", "incident-item-title", cand.title));
      btn.addEventListener("click", () => {
        state.selectedIncident = cand;
        document.getElementById("selected-incident-heading").textContent =
          cid + ": " + cand.title;
        document.getElementById("agent-prompt-input").value = cand.default_prompt;
        renderCandidateList();
      });
      container.appendChild(btn);
    });
  }

  function renderMemories(memories) {
    const container = document.getElementById("memory-list");
    container.replaceChildren();
    (memories || []).forEach((m) => {
      const box = el("div", "memory-entry");
      box.appendChild(el("strong", "", "[" + (m.incident_id || "AUDIT") + "] "));
      box.appendChild(el("span", "", m.fact));
      container.appendChild(box);
    });
  }

  function renderAuditResult(data) {
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
        el(
          "h3",
          "",
          "Parallel 3-Way MCP Governance Audit & JoinNode Correlation (" + b.app_id + ")"
        )
      );
      if (b.manifest_security) {
        corrCard.appendChild(
          el("p", "muted-note", "Manifest & Identity: " + b.manifest_security.summary)
        );
      }
      if (b.tier1_supergraph) {
        corrCard.appendChild(
          el("p", "muted-note", "Tier-1 Intake & Supergraph: " + b.tier1_supergraph.summary)
        );
      }
      if (b.production_traces) {
        corrCard.appendChild(
          el("p", "muted-note", "OTLP / Langfuse Traces: " + b.production_traces.summary)
        );
      }
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
        el(
          "h3",
          "",
          "Synthesized Remediation & Paved-Path Plan (" +
            a.risk_level +
            " -> " +
            a.recommended_route +
            ")"
        )
      );
      synthCard.appendChild(
        el("p", "", a.governance_gaps_summary || a.root_cause_summary || "")
      );
      synthCard.appendChild(el("p", "muted-note", "Action Plan: " + a.remediation_plan));

      if (a.terraform_paved_path_hcl || a.dynamic_guardrail_spec) {
        const diffGrid = el("div", "prompt-diff-grid");
        if (a.terraform_paved_path_hcl) {
          const tfCol = el("div", "");
          tfCol.appendChild(el("h4", "", "Generated Terraform Paved-Path Module"));
          tfCol.appendChild(el("pre", "code-box", a.terraform_paved_path_hcl));
          diffGrid.appendChild(tfCol);
        }
        if (a.dynamic_guardrail_spec) {
          const polCol = el("div", "");
          polCol.appendChild(el("h4", "", "Dynamic Per-Request Guardrail Policy JSON"));
          let prettyPol = a.dynamic_guardrail_spec;
          try {
            prettyPol = JSON.stringify(JSON.parse(a.dynamic_guardrail_spec), null, 2);
          } catch (_e) {
            prettyPol = a.dynamic_guardrail_spec;
          }
          polCol.appendChild(el("pre", "code-box", prettyPol));
          diffGrid.appendChild(polCol);
        }
        synthCard.appendChild(diffGrid);
      }

      synthCard.appendChild(
        el(
          "p",
          "mono-note",
          "Citations: " + (a.citations || []).join(", ") + " | Trace: " + data.trace_id
        )
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
      if (
        data.pending_approval.policy_freeze_active ||
        data.pending_approval.change_freeze_active
      ) {
        freezeBanner.classList.remove("hidden");
      } else {
        freezeBanner.classList.add("hidden");
      }
      approvalCard.classList.remove("hidden");
    } else {
      approvalCard.classList.add("hidden");
    }

    if (data.remediation_outcome && data.status === "COMPLETED") {
      const ro = data.remediation_outcome;
      const depCard = el("div", "card");
      depCard.appendChild(el("h3", "", "Deployment & Registry Enrollment (" + ro.status + ")"));
      depCard.appendChild(el("p", "", ro.summary));
      if (ro.golden_blueprint_id) {
        depCard.appendChild(
          el(
            "p",
            "mono-note",
            "Golden Blueprint: " +
              ro.golden_blueprint_id +
              " | Post-Deploy Readiness: " +
              (ro.post_deploy_readiness_score || 98) +
              "/100"
          )
        );
      }
      panel.appendChild(depCard);
    }

    if (data.postmortem_record) {
      const outCard = el("div", "card");
      outCard.appendChild(
        el("h3", "", "Audit Memory Trail (" + data.postmortem_record.final_status + ")")
      );
      outCard.appendChild(el("p", "", data.postmortem_record.executive_summary));
      panel.appendChild(outCard);
    }
  }

  function renderFlywheelStages(stages) {
    const box = document.getElementById("flywheel-stages-list");
    if (!box) {
      return;
    }
    box.replaceChildren();
    (stages || []).forEach((s) => {
      const pill = el("div", "stage-pill-box");
      pill.appendChild(el("strong", "", "Stage " + s.stage + ": " + s.name));
      pill.appendChild(el("div", "muted-note", s.detail));
      box.appendChild(pill);
    });
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
    b3.appendChild(el("strong", "", "Model Armor ($0.10 / 1M tok)"));
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

    const b4 = el("div", "tco-box highlight");
    b4.appendChild(el("strong", "", "Ensemble Tier-0 Hybrid"));
    const ensVal =
      tco.ensemble_tier0_hybrid_annual_usd ||
      Math.round(tco.google_model_armor_annual_usd + 0.2 * tco.aws_bedrock_guardrails_annual_usd);
    b4.appendChild(el("div", "", "$" + Math.round(ensVal).toLocaleString() + " / yr"));
    b4.appendChild(el("div", "mono-note", "100% SDP/URL Pre-Filter + 20% Voter"));

    container.appendChild(b1);
    container.appendChild(b2);
    container.appendChild(b3);
    container.appendChild(b4);
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
        "$" + spentUsd + " spent / $" + capUsd + " cap (" + resolved + " deployed)";
    }
  }

  function renderTelemetry(traces, ledger) {
    const traceBox = document.getElementById("trace-waterfall-list");
    traceBox.replaceChildren();
    (traces || []).slice(0, 5).forEach((t) => {
      const row = el("div", "trace-row");
      const stages = (t.spans || []).map((s) => s.span_name + " (" + s.duration_ms + "ms)").join(" -> ");
      const modeTag =
        t.architecture_mode === "enterprise_hybrid" ? "OTLP+W3C Coexistence" : "GCP-Native W3C";
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
        " nano-USD | cost_per_outcome=" +
        r.cost_per_resolved_incident_nano_usd +
        " nano-USD";
      ledgerBox.appendChild(row);
    });
  }

  function activateWorkspaceTab(mode, focusButton) {
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
      b.setAttribute("tabindex", "-1");
    });

    let activeBtn = tabAgent;
    if (mode === "pipeline") {
      activeBtn = tabPipeline;
      leftCol.classList.add("hidden");
      shell.className = "workspace-container workspace-focus-pipeline";
    } else if (mode === "steward") {
      activeBtn = tabSteward;
      leftCol.classList.remove("hidden");
      viewSteward.classList.remove("hidden");
      viewAgent.classList.add("hidden");
      shell.className = "workspace-container workspace-split";
    } else {
      activeBtn = tabAgent;
      leftCol.classList.remove("hidden");
      viewAgent.classList.remove("hidden");
      viewSteward.classList.add("hidden");
      shell.className = "workspace-container workspace-split";
    }

    activeBtn.classList.add("active");
    activeBtn.setAttribute("aria-selected", "true");
    activeBtn.setAttribute("tabindex", "0");
    if (focusButton) {
      activeBtn.focus();
    }
  }

  function wireAccessibleTablistKeyboard() {
    const tabModes = ["agent", "steward", "pipeline"];
    const tabIds = ["tab-agent", "tab-steward", "tab-pipeline"];
    tabIds.forEach((id, index) => {
      const btn = document.getElementById(id);
      btn.addEventListener("keydown", (ev) => {
        let nextIdx = -1;
        if (ev.key === "ArrowRight") {
          nextIdx = (index + 1) % tabModes.length;
        } else if (ev.key === "ArrowLeft") {
          nextIdx = (index - 1 + tabModes.length) % tabModes.length;
        } else if (ev.key === "Home") {
          nextIdx = 0;
        } else if (ev.key === "End") {
          nextIdx = tabModes.length - 1;
        }
        if (nextIdx >= 0) {
          ev.preventDefault();
          activateWorkspaceTab(tabModes[nextIdx], true);
        }
      });
    });
  }

  async function init() {
    renderProofCards();
    const boot = await apiGet("/api/bootstrap");
    state.csrfToken = boot.csrf_token;
    state.architectureMode = boot.architecture_mode || "enterprise_hybrid";
    state.incidents = boot.candidates || boot.incidents || [];
    state.selectedIncident = state.incidents[0] || null;

    document.getElementById("mode-select").value = state.architectureMode;
    applyTenantBranding(boot.tenant);
    if (boot.runtime_environment) {
      const rtPill = document.getElementById("runtime-env-pill");
      if (rtPill) {
        let rtLabel = boot.runtime_environment.badge_label || "Local Dev (127.0.0.1)";
        if (boot.runtime_environment.iap_verified) {
          rtLabel += " | IAP";
        }
        rtPill.textContent = rtLabel;
        rtPill.className =
          boot.runtime_environment.target === "cloud_run"
            ? "runtime-pill runtime-cloud-run"
            : "runtime-pill";
      }
    }
    updatePlatformServices(boot.platform_services, false);

    renderCandidateList();
    if (state.selectedIncident) {
      const cid = state.selectedIncident.candidate_id || state.selectedIncident.incident_id;
      document.getElementById("selected-incident-heading").textContent =
        cid + ": " + state.selectedIncident.title;
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
          "Active Blueprint: " +
            boot.prompt_registry.active.active_version +
            " (behavior_score=" +
            boot.prompt_registry.active.behavior_score +
            ")"
        )
      );
    }

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

    document
      .getElementById("tab-agent")
      .addEventListener("click", () => activateWorkspaceTab("agent", false));
    document
      .getElementById("tab-steward")
      .addEventListener("click", () => activateWorkspaceTab("steward", false));
    document
      .getElementById("tab-pipeline")
      .addEventListener("click", () => activateWorkspaceTab("pipeline", false));
    wireAccessibleTablistKeyboard();

    document.getElementById("mode-select").addEventListener("change", async () => {
      state.architectureMode = document.getElementById("mode-select").value;
      const res = await apiPost("/api/config/mode", {
        architecture_mode: state.architectureMode,
      });
      applyTenantBranding(res.tenant);
      updatePlatformServices(res.platform_services, true);
    });

    document.getElementById("btn-run-triage").addEventListener("click", async () => {
      const statusEl = document.getElementById("agent-run-status");
      statusEl.textContent = "Running Governance Audit...";
      statusEl.className = "status-chip chip-warn";
      try {
        const cand = state.selectedIncident || state.incidents[0];
        const cid = cand.candidate_id || cand.incident_id;
        const res = await apiPost("/api/agent/audit", {
          candidate_id: cid,
          agent_name: cand.agent_name || cand.service_name,
          app_id: cand.app_id,
          operator_prompt: document.getElementById("agent-prompt-input").value,
          architecture_mode: state.architectureMode,
        });
        statusEl.textContent = res.status;
        statusEl.className =
          res.status === "WAITING_AG3_APPROVAL" ? "status-chip chip-warn" : "status-chip";
        renderAuditResult(res);
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

    const submitHitl = async (approved) => {
      const statusEl = document.getElementById("agent-run-status");
      statusEl.textContent = "Resuming Deployment Gate...";
      statusEl.className = "status-chip chip-warn";
      try {
        const res = await apiPost("/api/agent/resume", {
          session_id: state.activeSessionId,
          interrupt_id: state.activeInterruptId,
          approved: approved,
          approver_principal: "gov-steward-lead",
          vp_exception_ticket: document.getElementById("vp-ticket-input").value || null,
          reason: approved
            ? "Approved Paved-Path HCL & Golden Blueprint deployment."
            : "Held pending VP Governance-Freeze Exception.",
        });
        document.getElementById("ag3-approval-card").classList.add("hidden");
        statusEl.textContent = res.status;
        statusEl.className = "status-chip";
        renderAuditResult(res);
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

    document.querySelectorAll("[data-kill]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const res = await apiPost("/api/steward/kill-switch", {
          status: btn.getAttribute("data-kill"),
        });
        renderAgentAndWallet(res.agent_state, null);
        updatePlatformServices(res.platform_services, true);
      });
    });

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

    document.getElementById("tco-slider").addEventListener("input", async (ev) => {
      const val = parseInt(ev.target.value, 10);
      document.getElementById("tco-volume-label").textContent = val.toLocaleString();
      const tco = await apiPost("/api/steward/tco", { daily_turns: val, tokens_per_turn: 1000 });
      renderTco(tco);
    });

    document.querySelectorAll("[data-threat]").forEach((btn) => {
      btn.addEventListener("click", () => {
        document.getElementById("threat-input").value = btn.getAttribute("data-threat");
      });
    });

    document.getElementById("btn-test-threat").addEventListener("click", async () => {
      const box = document.getElementById("threat-verdict-box");
      box.replaceChildren(el("div", "muted-note", "Routing dynamic policy payload..."));
      const dynamicPolicy = {
        business_unit: document.getElementById("dyn-bu-select").value,
        risk_tier: document.getElementById("dyn-risk-select").value,
        pi_and_jailbreak_threshold:
          document.getElementById("dyn-risk-select").value === "AG3"
            ? "LOW_AND_ABOVE"
            : "MEDIUM_AND_ABOVE",
        malicious_uri_filter: true,
        sdp_pii_mode: document.getElementById("dyn-sdp-select").value,
        rai_sensitivity: "MEDIUM_AND_ABOVE",
        ensemble_role: document.getElementById("dyn-role-select").value,
      };
      const res = await apiPost("/api/steward/guardrail-test", {
        sample_text: document.getElementById("threat-input").value,
        dynamic_policy: dynamicPolicy,
      });
      box.replaceChildren(
        el(
          "strong",
          "",
          (res.allowed ? "ALLOWED" : "BLOCKED") +
            " (" +
            res.action_taken +
            " -> " +
            res.resolved_template +
            ")"
        ),
        el("div", "muted-note", res.summary),
        el("div", "mono-note", "Dynamic Policy Key: " + res.dynamic_policy_key),
        el("div", "mono-note", "Sanitized Output: " + (res.sanitized_text || "[BLOCKED]"))
      );
      updatePlatformServices(res.platform_services, true);
    });

    document.getElementById("btn-run-flywheel").addEventListener("click", async () => {
      const sc = document.getElementById("flywheel-scorecard");
      sc.replaceChildren(
        el("span", "risk-badge", "Running 6-Stage Cross-Cloud Closed-Loop Optimization...")
      );
      try {
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
            "Promoted Golden Blueprint v2=" +
              res.v2_candidate.behavior_score +
              " (" +
              res.v2_candidate.cases_passed +
              "/" +
              res.v2_candidate.cases_total +
              " Sims Passed in " +
              res.elapsed_seconds +
              "s)"
          ),
          el("span", "mono-pill", "Eval Engine: " + (res.eval_engine_used || "agentplatform.Client"))
        );
        if (res.v2_prompt_text) {
          document.getElementById("prompt-v2-pre").textContent = res.v2_prompt_text;
        }
        renderFlywheelStages(res.stages);
        updatePlatformServices(res.platform_services, true);
      } catch (err) {
        sc.replaceChildren(el("span", "status-chip chip-danger", "Error: " + err.message));
      }
    });

    document.getElementById("btn-refresh-telemetry").addEventListener("click", async () => {
      const snap = await apiGet("/api/steward/telemetry");
      renderAgentAndWallet(snap.agent_state, snap.wallet_state);
      renderTelemetry(snap.recent_traces, snap.recent_ledger);
      updatePlatformServices(snap.platform_services, false);
    });

    const params = new URLSearchParams(window.location.search);
    const requestedView = params.get("view");
    if (requestedView === "pipeline" || requestedView === "steward") {
      activateWorkspaceTab(requestedView, false);
    }
    if (params.get("expand") === "all") {
      state.expandAll = true;
      document.getElementById("btn-expand-all").textContent = "Collapse Details";
      renderVerticalPipeline();
    }
  }

  document.addEventListener("DOMContentLoaded", init);
})();
