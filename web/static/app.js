/**
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

(() => {
  "use strict";

  const STAGE_TITLES = {
    build: "Build",
    evaluate: "Evaluate",
    deploy: "Deploy",
    govern: "Govern",
  };

  const ORIGIN_LABELS = {
    google_gcp_standard: "Google Cloud Standard",
    cymbal_baseline: "Cymbal Baseline",
    custom_hybrid: "Custom Hybrid",
    imported_manifest: "Imported Manifest",
  };

  const state = {
    csrfToken: "",
    tenant: null,
    slotCatalog: [],
    slotById: {},
    templates: [],
    workingTemplate: null,
    initialScoreBaseline: 96.4,
    currentEvaluation: null,
    rubric: null,
    operationsMetrics: null,
    executiveCosts: null,
    platformServices: null,
    agentState: null,
    walletState: null,
    tcoReport: null,
    proofResults: [],
    lastGuardrailVerdict: null,
    lastOboResult: null,
    pendingHitl: null,
    activeStage: "build",
    activeGovernTab: "policies",
    selectedSlotId: null,
    agentSearchFilter: "",
    fleetSearchFilter: "",
    finopsFilters: { business_unit: "all", origin: "all" },
  };

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

  function formatUsd(val) {
    const num = Number(val || 0);
    return "$" + num.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  }

  function announcePolite(msg) {
    const box = document.getElementById("polite-announcer");
    if (box) {
      box.textContent = msg;
    }
  }

  function showToast(msg) {
    const banner = document.getElementById("status-toast-banner");
    const errBanner = document.getElementById("global-alert-banner");
    if (errBanner) {
      errBanner.hidden = true;
    }
    if (banner) {
      banner.textContent = msg;
      banner.hidden = false;
    }
    announcePolite(msg);
  }

  function showError(msg) {
    const errBanner = document.getElementById("global-alert-banner");
    const toast = document.getElementById("status-toast-banner");
    if (toast) {
      toast.hidden = true;
    }
    if (errBanner) {
      errBanner.textContent = msg;
      errBanner.hidden = false;
    }
  }

  function clearBanners() {
    const errBanner = document.getElementById("global-alert-banner");
    const toast = document.getElementById("status-toast-banner");
    if (errBanner) {
      errBanner.hidden = true;
    }
    if (toast) {
      toast.hidden = true;
    }
  }

  async function apiGet(path) {
    const resp = await fetch(path, {
      method: "GET",
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      throw new Error(body.detail || `Request failed (${resp.status})`);
    }
    return body;
  }

  async function apiPost(path, payload) {
    const resp = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        "X-CSRF-Token": state.csrfToken,
      },
      body: JSON.stringify(payload || {}),
    });
    const body = await resp.json().catch(() => ({}));
    if (body && body.platform_services) {
      state.platformServices = body.platform_services;
      renderPipelineList();
    }
    if (!resp.ok) {
      throw new Error(body.detail || `Request failed (${resp.status})`);
    }
    return body;
  }

  function customerShortName() {
    return (state.tenant && state.tenant.terminology && state.tenant.terminology.customer_provider_short) || "Cymbal";
  }

  function gcpShortName() {
    return (state.tenant && state.tenant.terminology && state.tenant.terminology.gcp_provider_short) || "Google Cloud";
  }

  function buLabel(buKey) {
    const map = (state.tenant && state.tenant.terminology && state.tenant.terminology.business_units) || {};
    return map[buKey] || buKey;
  }

  function providerBadgeInfo(provider) {
    if (provider === "google_gcp") {
      return { text: gcpShortName(), cls: "provider-pill is-gcp" };
    }
    if (provider === "cymbal_stack") {
      return { text: customerShortName(), cls: "provider-pill is-cymbal" };
    }
    return { text: "Unconfigured", cls: "provider-pill is-unconfigured" };
  }

  function cloneJson(obj) {
    return JSON.parse(JSON.stringify(obj));
  }

  function resolveInitialStageFromPath() {
    const p = window.location.pathname.toLowerCase();
    if (p.startsWith("/evaluate")) return "evaluate";
    if (p.startsWith("/deploy")) return "deploy";
    if (p.startsWith("/govern") || p.startsWith("/governance-ops") || p.startsWith("/executive")) return "govern";
    return "build";
  }

  function setStage(stage, pushHistory = true) {
    const nextStage = STAGE_TITLES[stage] ? stage : "build";
    state.activeStage = nextStage;
    clearBanners();

    const brand = (state.tenant && state.tenant.terminology && state.tenant.terminology.sidebar_brand) || "Cymbal Platform";
    document.title = `${STAGE_TITLES[nextStage]} | ${brand}`;
    if (pushHistory && window.location.pathname !== `/${nextStage}`) {
      window.history.pushState({ stage: nextStage }, "", `/${nextStage}`);
    }

    document.querySelectorAll(".lifecycle-nav-btn").forEach((btn) => {
      const active = btn.dataset.stage === nextStage;
      btn.classList.toggle("is-active", active);
      if (active) {
        btn.setAttribute("aria-current", "page");
      } else {
        btn.removeAttribute("aria-current");
      }
    });

    const pinned = document.getElementById("pinned-template-section");
    if (pinned) {
      pinned.hidden = nextStage === "govern";
    }
    const customActions = document.getElementById("strip-custom-actions");
    if (customActions) {
      customActions.hidden = nextStage !== "build";
    }

    renderHeaderAndRail();
    renderTenTileStrip();
    renderStageBody();
  }

  function renderHeaderAndRail() {
    const terms = (state.tenant && state.tenant.terminology) || {};
    const brandEl = document.getElementById("sidebar-brand-title");
    if (brandEl && terms.sidebar_brand) {
      brandEl.textContent = terms.sidebar_brand;
    }

    const tpl = state.workingTemplate;
    const ev = state.currentEvaluation;
    if (tpl) {
      const railName = document.getElementById("rail-agent-name");
      const railMeta = document.getElementById("rail-agent-meta");
      const ctxPill = document.getElementById("active-agent-summary-pill");
      const scoreText = ev ? `${ev.overall_score.toFixed(1)}/100` : "--";
      if (railName) railName.textContent = tpl.agent_name;
      if (railMeta) railMeta.textContent = `${String(tpl.risk_tier).toLowerCase()} | Score ${scoreText}`;
      if (ctxPill) {
        ctxPill.textContent = `${tpl.agent_name} | ${buLabel(tpl.business_unit)} | ${String(tpl.risk_tier).toLowerCase()}`;
      }

      const gcpRadio = document.getElementById("mode-google-gcp");
      const customRadio = document.getElementById("mode-custom");
      if (gcpRadio && customRadio) {
        gcpRadio.checked = tpl.template_mode === "google_gcp";
        customRadio.checked = tpl.template_mode !== "google_gcp";
      }

      const helper = document.getElementById("strip-helper-bar");
      if (helper) {
        if (tpl.template_mode === "google_gcp") {
          helper.textContent =
            "Google Cloud template active: all 10 functional capabilities use Google Cloud Agent Platform components. Switch to Custom to mix Cymbal and Google Cloud components.";
        } else {
          helper.textContent = `Custom template active: select any functional component tile to choose between ${customerShortName()} and ${gcpShortName()} components or configure policy settings.`;
        }
      }
    }

    const evalBadge = document.getElementById("nav-eval-badge");
    if (evalBadge && ev) {
      evalBadge.hidden = false;
      evalBadge.textContent = `${Math.round(ev.overall_score)}`;
    }
  }

  function renderTenTileStrip() {
    const container = document.getElementById("ten-tile-strip");
    if (!container || !state.workingTemplate) return;
    container.replaceChildren();

    const tpl = state.workingTemplate;
    const slotStatuses = (state.currentEvaluation && state.currentEvaluation.slot_statuses) || {};
    const highlightEval = state.activeStage === "evaluate" || state.activeStage === "deploy";

    state.slotCatalog.forEach((spec) => {
      const sid = spec.slot_id;
      const comp = (tpl.components && tpl.components[sid]) || {
        slot_id: sid,
        provider: "unconfigured",
        enabled: false,
      };
      const prov = comp.enabled === false ? "unconfigured" : comp.provider;
      const pInfo = providerBadgeInfo(prov);
      const implLabel = (spec.provider_labels && spec.provider_labels[prov]) || "Unconfigured";
      const st = slotStatuses[sid] || "PASSED";

      const li = el("li", "tile-list-item");
      const btn = el("button", "component-tile");
      btn.type = "button";
      btn.dataset.slotId = sid;
      if (state.selectedSlotId === sid) {
        btn.classList.add("is-selected");
      }
      if (highlightEval) {
        if (st === "FAILED") {
          btn.classList.add("tile-status-failed");
        } else if (st === "ADVISORY") {
          btn.classList.add("tile-status-advisory");
        } else {
          btn.classList.add("tile-status-passed", "eval-highlight");
        }
      }

      const topRow = el("span", "tile-badge-row");
      topRow.appendChild(el("span", pInfo.cls, pInfo.text));
      if (highlightEval) {
        const sym = st === "FAILED" ? "[!]" : st === "ADVISORY" ? "[~]" : "[OK]";
        topRow.appendChild(el("span", "provider-pill", sym));
      }

      const titleSpan = el("span", "tile-functional-name", spec.functional_name);
      const subSpan = el("span", "tile-impl-caption", implLabel);

      btn.append(topRow, titleSpan, subSpan);
      btn.addEventListener("click", () => openSlotInspector(sid));
      li.appendChild(btn);
      container.appendChild(li);
    });
  }

  async function refreshEvaluation(silent = true) {
    if (!state.workingTemplate) return;
    try {
      const res = await apiPost("/api/templates/evaluate", { template: state.workingTemplate });
      state.currentEvaluation = res.evaluation;
      renderHeaderAndRail();
      renderTenTileStrip();
      if (!silent) {
        renderStageBody();
      } else if (state.activeStage === "evaluate" || state.activeStage === "deploy") {
        renderStageBody();
      }
    } catch (err) {
      showError(err.message);
    }
  }

  async function selectAgentTemplate(tplObj, announce = true) {
    state.workingTemplate = cloneJson(tplObj);
    const res = await apiPost("/api/templates/evaluate", { template: state.workingTemplate });
    state.currentEvaluation = res.evaluation;
    state.initialScoreBaseline = res.evaluation.overall_score;
    renderHeaderAndRail();
    renderTenTileStrip();
    renderStageBody();
    if (announce) {
      showToast(`Loaded agent '${state.workingTemplate.agent_name}' into deployment template.`);
    }
  }

  async function handleTemplateProfileSwitch(mode) {
    if (!state.workingTemplate) return;
    if (mode === "google_gcp") {
      state.workingTemplate.template_mode = "google_gcp";
      state.workingTemplate.origin = "google_gcp_standard";
      state.slotCatalog.forEach((spec) => {
        state.workingTemplate.components[spec.slot_id] = {
          slot_id: spec.slot_id,
          provider: "google_gcp",
          enabled: true,
          enterprise_sync_enabled: true,
          parameters: {},
        };
      });
      state.workingTemplate.uap_cel_per_tool_enforced = true;
      if (state.workingTemplate.sdp_pii_mode === "NONE") {
        state.workingTemplate.sdp_pii_mode = "DEIDENTIFY_INLINE";
      }
      await refreshEvaluation(false);
      showToast("Applied Google Cloud template across all 10 functional capabilities.");
    } else {
      state.workingTemplate.template_mode = "custom";
      if (state.workingTemplate.origin === "google_gcp_standard") {
        state.workingTemplate.origin = "custom_hybrid";
      }
      renderHeaderAndRail();
      renderTenTileStrip();
      showToast("Custom mode enabled. Click any component tile to choose Cymbal or Google Cloud.");
    }
  }

  async function applyCymbalBaselineAllSlots() {
    if (!state.workingTemplate) return;
    state.workingTemplate.template_mode = "custom";
    state.workingTemplate.origin = "cymbal_baseline";
    state.slotCatalog.forEach((spec) => {
      state.workingTemplate.components[spec.slot_id] = {
        slot_id: spec.slot_id,
        provider: "cymbal_stack",
        enabled: true,
        enterprise_sync_enabled: true,
        parameters: {},
      };
    });
    await refreshEvaluation(false);
    showToast(`Applied ${customerShortName()} baseline components across all 10 capabilities.`);
  }

  async function saveCurrentTemplate() {
    if (!state.workingTemplate) return;
    try {
      const res = await apiPost("/api/agents/save", state.workingTemplate);
      state.workingTemplate = res.template;
      state.templates = res.templates;
      state.currentEvaluation = res.evaluation;
      renderHeaderAndRail();
      renderTenTileStrip();
      renderStageBody();
      showToast(`Saved agent template '${state.workingTemplate.agent_name}'.`);
    } catch (err) {
      showError(err.message);
    }
  }

  function exportCurrentTemplateYaml() {
    if (!state.workingTemplate) return;
    const t = state.workingTemplate;
    const lines = [
      `template_id: "${t.template_id}"`,
      `agent_name: "${t.agent_name}"`,
      `app_id: "${t.app_id}"`,
      `intake_id: "${t.intake_id || ""}"`,
      `business_unit: "${t.business_unit}"`,
      `risk_tier: "${t.risk_tier}"`,
      `runtime_cloud: "${t.runtime_cloud}"`,
      `estimated_monthly_turns_millions: ${t.estimated_monthly_turns_millions}`,
      `uap_cel_per_tool_enforced: ${Boolean(t.uap_cel_per_tool_enforced)}`,
      `sdp_pii_mode: "${t.sdp_pii_mode}"`,
      `prompt_version: "${t.prompt_version}"`,
      `behavior_score: ${t.behavior_score}`,
      "components:",
    ];
    state.slotCatalog.forEach((spec) => {
      const c = (t.components && t.components[spec.slot_id]) || { provider: "unconfigured" };
      lines.push(`  ${spec.slot_id}: "${c.provider}"`);
    });
    const blob = new Blob([lines.join("\n") + "\n"], { type: "text/yaml;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${t.agent_name}.yaml`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    showToast(`Exported ${t.agent_name}.yaml manifest.`);
  }

  /* Stage Renderers */
  function renderStageBody() {
    const root = document.getElementById("stage-body-content");
    if (!root) return;
    root.replaceChildren();

    if (state.activeStage === "build") {
      renderBuildStage(root);
    } else if (state.activeStage === "evaluate") {
      renderEvaluateStage(root);
    } else if (state.activeStage === "deploy") {
      renderDeployStage(root);
    } else {
      renderGovernStage(root);
    }
  }

  function renderBuildStage(root) {
    const terms = (state.tenant && state.tenant.terminology) || {};
    const toolbar = el("div", "toolbar-row");
    const left = el("div", "toolbar-left");
    left.appendChild(el("h2", "section-heading", "Registered & Draft Agents"));

    const filterLabel = el("label", "visually-hidden", "Filter agents");
    filterLabel.setAttribute("for", "agent-table-filter");
    const filterInput = el("input", "search-input");
    filterInput.type = "search";
    filterInput.id = "agent-table-filter";
    filterInput.placeholder = "Filter by Agent ID, BU, or App ID...";
    filterInput.value = state.agentSearchFilter;
    filterInput.addEventListener("input", (e) => {
      state.agentSearchFilter = e.target.value;
      renderStageBody();
      const restored = document.getElementById("agent-table-filter");
      if (restored) {
        restored.focus();
        restored.setSelectionRange(restored.value.length, restored.value.length);
      }
    });
    left.append(filterLabel, filterInput);

    const right = el("div", "toolbar-right");
    const newBtn = el("button", "secondary-btn", "+ New Agent");
    newBtn.type = "button";
    newBtn.addEventListener("click", () => openNewAgentModal());

    const metaBtn = el("button", "secondary-btn", "Edit Agent Metadata");
    metaBtn.type = "button";
    metaBtn.addEventListener("click", () => openMetadataInspector());

    const saveBtn = el("button", "secondary-btn", "Save Template");
    saveBtn.type = "button";
    saveBtn.addEventListener("click", () => saveCurrentTemplate());

    const evalBtn = el("button", "primary-btn", "Evaluate Agent ->");
    evalBtn.type = "button";
    evalBtn.addEventListener("click", async () => {
      await refreshEvaluation(true);
      setStage("evaluate");
    });

    right.append(newBtn, metaBtn, saveBtn, evalBtn);
    toolbar.append(left, right);
    root.appendChild(toolbar);

    const tableWrap = el("div", "table-wrap");
    const table = el("table", "data-table");
    table.appendChild(
      el(
        "caption",
        "",
        "Select any agent row to load its 10 functional component selections into the Agent Deployment Template above."
      )
    );

    const thead = el("thead");
    const hr = el("tr");
    const cols = [
      "Agent ID",
      "Last Updated",
      "Business Unit",
      terms.cmdb_col_label || "ServiceAtlas CMDB App ID",
      terms.intake_col_label || "ATLAS Intake ID",
      terms.risk_col_label || "SENTINEL Agency Tier",
    ];
    cols.forEach((c) => {
      const th = el("th", "", c);
      th.scope = "col";
      hr.appendChild(th);
    });
    thead.appendChild(hr);
    table.appendChild(thead);

    const tbody = el("tbody");
    const q = state.agentSearchFilter.trim().toLowerCase();
    const filtered = state.templates.filter((item) => {
      if (!q) return true;
      return (
        String(item.agent_name).toLowerCase().includes(q) ||
        String(item.business_unit_label || "").toLowerCase().includes(q) ||
        String(item.app_id || "").toLowerCase().includes(q) ||
        String(item.intake_id || "").toLowerCase().includes(q)
      );
    });

    filtered.forEach((item) => {
      const tr = el("tr", "clickable-row");
      const isSel =
        state.workingTemplate && state.workingTemplate.template_id === item.template_id;
      if (isSel) {
        tr.classList.add("is-selected-row");
      }

      const tdId = el("td");
      const selBtn = el("button", "row-select-btn", item.agent_name);
      selBtn.type = "button";
      selBtn.addEventListener("click", (ev) => {
        ev.stopPropagation();
        selectAgentTemplate(item);
      });
      tdId.appendChild(selBtn);
      if (isSel) {
        tdId.appendChild(document.createTextNode(" "));
        tdId.appendChild(el("span", "status-badge status-ok", "Selected"));
      }

      const tdUpd = el("td", "", item.updated_display || item.updated_at || "--");
      const tdBu = el("td", "", item.business_unit_label || buLabel(item.business_unit));
      const tdApp = el("td", "", item.app_id);
      const tdIntake = el("td", "", item.intake_id || "Pending");
      const tdRisk = el("td", "", String(item.risk_tier || "AG2").toLowerCase());

      tr.append(tdId, tdUpd, tdBu, tdApp, tdIntake, tdRisk);
      tr.addEventListener("click", () => selectAgentTemplate(item));
      tbody.appendChild(tr);
    });

    table.appendChild(tbody);
    tableWrap.appendChild(table);
    root.appendChild(tableWrap);
  }

  function renderEvaluateStage(root) {
    const ev = state.currentEvaluation;
    const tpl = state.workingTemplate;
    if (!ev || !tpl) return;

    const kpiRow = el("div", "kpi-grid-5");
    const mainScoreCard = el("div", "surface-card");
    mainScoreCard.appendChild(el("p", "kpi-label", "Overall Governance Readiness"));
    mainScoreCard.appendChild(el("p", "kpi-value", `${ev.overall_score.toFixed(1)} / 100`));
    const gateBadge = el(
      "span",
      ev.gate_passed ? "status-badge status-ok" : "status-badge status-err",
      ev.gate_passed ? "[OK] Gate Passed" : `[!] ${ev.mandatory_failures_count} Blocking Gate(s)`
    );
    mainScoreCard.appendChild(gateBadge);
    mainScoreCard.appendChild(
      el(
        "p",
        "kpi-sub",
        `Required: >= ${ev.passing_threshold.toFixed(1)} | Est. Run-Rate: ${formatUsd(
          ev.cost_estimate.monthly_run_rate_usd
        )}/mo`
      )
    );
    kpiRow.appendChild(mainScoreCard);

    ["Control", "Intelligence", "Economics", "Experience"].forEach((pillar) => {
      const pData = (ev.pillar_scores && ev.pillar_scores[pillar]) || {
        earned_pts: 0,
        possible_pts: 0,
        pct: 100,
      };
      const pCard = el("div", "surface-card");
      pCard.appendChild(el("p", "kpi-label", `${pillar} Pillar`));
      pCard.appendChild(el("p", "kpi-value", `${pData.pct.toFixed(0)}%`));
      const meter = el("progress", "meter-bar");
      meter.max = 100;
      meter.value = pData.pct;
      pCard.appendChild(meter);
      pCard.appendChild(
        el("p", "kpi-sub", `${pData.earned_pts} / ${pData.possible_pts} rubric pts`)
      );
      kpiRow.appendChild(pCard);
    });
    root.appendChild(kpiRow);

    // Action Bar for Prompt Optimization, Deep Audit, and Advancing to Deploy
    const actionCard = el("div", "surface-card toolbar-row");
    const leftInfo = el("div", "toolbar-left");
    leftInfo.appendChild(
      el(
        "span",
        "status-badge status-ok",
        `Prompt ${tpl.prompt_version} | Quality Score ${tpl.behavior_score.toFixed(1)}/100`
      )
    );
    leftInfo.appendChild(
      el(
        "span",
        "field-hint",
        "Run closed-loop trace evaluation or inspect component findings below."
      )
    );

    const rightBtns = el("div", "toolbar-right");
    const optBtn = el("button", "secondary-btn", "Optimize Prompt & Traces");
    optBtn.type = "button";
    optBtn.addEventListener("click", async () => {
      optBtn.disabled = true;
      try {
        const fly = await apiPost("/api/steward/closed-loop-eval", {});
        state.workingTemplate.prompt_version = "v2";
        state.workingTemplate.behavior_score = fly.v2_candidate.behavior_score;
        state.workingTemplate.components.eval_optimization = {
          slot_id: "eval_optimization",
          provider: "google_gcp",
          enabled: true,
          enterprise_sync_enabled: true,
          parameters: { promoted_blueprint: "v2" },
        };
        await refreshEvaluation(false);
        showToast(
          `Promoted v2 instructions via Gemini 3.8 Flash (${fly.v1_baseline.behavior_score} -> ${fly.v2_candidate.behavior_score}/100).`
        );
      } catch (err) {
        showError(err.message);
      } finally {
        optBtn.disabled = false;
      }
    });

    const auditBtn = el("button", "secondary-btn", "Run ADK Workflow Audit");
    auditBtn.type = "button";
    auditBtn.addEventListener("click", async () => {
      auditBtn.disabled = true;
      try {
        const auditRes = await apiPost("/api/agent/audit", {
          candidate_id: "CAND-101",
          agent_name: tpl.agent_name,
          app_id: tpl.app_id,
          operator_prompt: `Verify governance readiness and synthesize Terraform module for ${tpl.agent_name} (${tpl.app_id}).`,
          architecture_mode: tpl.template_mode === "google_gcp" ? "google_native" : "enterprise_hybrid",
        });
        state.pendingHitl = auditRes.pending_approval
          ? {
              session_id: auditRes.session_id,
              interrupt_id: auditRes.pending_approval.interrupt_id,
            }
          : null;
        showToast(
          auditRes.status === "WAITING_AG3_APPROVAL"
            ? `ADK 2.0 workflow audit complete; AG3 approval checkpoint '${auditRes.pending_approval.interrupt_id}' staged for Deploy.`
            : "ADK 2.0 workflow audit completed with zero blocking interrupts."
        );
        openPipelineDrawer();
      } catch (err) {
        showError(err.message);
      } finally {
        auditBtn.disabled = false;
      }
    });

    const toDeployBtn = el("button", "primary-btn", "Proceed to Deploy ->");
    toDeployBtn.type = "button";
    toDeployBtn.addEventListener("click", () => setStage("deploy"));

    rightBtns.append(optBtn, auditBtn, toDeployBtn);
    actionCard.append(leftInfo, rightBtns);
    root.appendChild(actionCard);

    // Remediation Queue
    const recs = ev.recommendations || [];
    if (recs.length > 0) {
      root.appendChild(
        el("h2", "section-heading", `Remediation Queue (${recs.length} Open Finding(s))`)
      );
      const grid = el("div", "remediation-list");
      recs.forEach((rec) => {
        const card = el(
          "div",
          rec.severity === "MANDATORY_GATE"
            ? "remediation-card is-mandatory"
            : "remediation-card is-advisory"
        );
        const top = el("div", "toolbar-row");
        top.appendChild(
          el(
            "span",
            rec.severity === "MANDATORY_GATE"
              ? "status-badge status-err"
              : "status-badge status-warn",
            rec.severity === "MANDATORY_GATE" ? "[!] Mandatory Gate" : "[~] Advisory"
          )
        );
        const deltaSign = rec.monthly_cost_delta_usd >= 0 ? "+" : "";
        top.appendChild(
          el(
            "span",
            "field-hint",
            `${rec.pillar} | +${rec.score_uplift_pts} pts | ${deltaSign}${formatUsd(
              rec.monthly_cost_delta_usd
            )}/mo`
          )
        );

        card.appendChild(top);
        card.appendChild(el("strong", "", `${rec.functional_name}: ${rec.title}`));
        card.appendChild(el("p", "kpi-sub", rec.finding_detail));
        card.appendChild(
          el(
            "p",
            "field-hint",
            `Recommended: ${rec.recommended_provider_label} - ${rec.recommendation_summary}`
          )
        );

        const btnRow = el("div", "toolbar-left");
        const fixBtn = el("button", "primary-btn sm-btn", "Apply Recommended Fix");
        fixBtn.type = "button";
        fixBtn.addEventListener("click", async () => {
          fixBtn.disabled = true;
          try {
            const r = await apiPost("/api/templates/remediate", {
              template: state.workingTemplate,
              rule_id: rec.rule_id,
              action: "accept",
            });
            state.workingTemplate = r.template;
            state.currentEvaluation = r.evaluation;
            renderHeaderAndRail();
            renderTenTileStrip();
            renderStageBody();
            showToast(`Applied ${rec.rule_id} fix (${rec.recommended_provider_label}).`);
          } catch (err) {
            showError(err.message);
          } finally {
            fixBtn.disabled = false;
          }
        });

        const cfgBtn = el("button", "secondary-btn sm-btn", "Configure in Drawer");
        cfgBtn.type = "button";
        cfgBtn.addEventListener("click", () => openSlotInspector(rec.slot_id));

        const excToggleBtn = el("button", "secondary-btn sm-btn", "Record Exception");
        excToggleBtn.type = "button";

        const excBox = el("div", "form-stack");
        excBox.hidden = true;
        const excId = `exc-input-${rec.rule_id}`;
        const excLbl = el("label", "", "Policy Exception Justification");
        excLbl.setAttribute("for", excId);
        const excInput = el("input");
        excInput.type = "text";
        excInput.id = excId;
        excInput.required = true;
        excInput.value = "Approved architecture variance ticket GOV-2026-412";
        const excSubmit = el("button", "secondary-btn sm-btn", "Confirm Exception");
        excSubmit.type = "button";
        excSubmit.addEventListener("click", async () => {
          try {
            const r = await apiPost("/api/templates/remediate", {
              template: state.workingTemplate,
              rule_id: rec.rule_id,
              action: "exception",
              exception_reason: excInput.value,
            });
            state.workingTemplate = r.template;
            state.currentEvaluation = r.evaluation;
            renderHeaderAndRail();
            renderTenTileStrip();
            renderStageBody();
            showToast(`Recorded policy exception for ${rec.rule_id}.`);
          } catch (err) {
            showError(err.message);
          }
        });
        const excField = el("div", "field-group");
        excField.append(excLbl, excInput);
        excBox.append(excField, excSubmit);

        excToggleBtn.addEventListener("click", () => {
          excBox.hidden = !excBox.hidden;
        });

        btnRow.append(fixBtn, cfgBtn, excToggleBtn);
        card.append(btnRow, excBox);
        grid.appendChild(card);
      });
      root.appendChild(grid);
    }

    // Complete 10-Rule Governance Scorecard Table
    const wrap = el("div", "table-wrap deferred-below-fold");
    const tbl = el("table", "data-table");
    tbl.appendChild(el("caption", "", `${ev.rubric_name} - All 10 Functional Capability Checks`));
    const thead = el("thead");
    const hr = el("tr");
    ["Rule", "Component", "Pillar / Workstream", "Selected Provider", "Weight", "Status"].forEach(
      (h) => {
        const th = el("th", "", h);
        th.scope = "col";
        hr.appendChild(th);
      }
    );
    thead.appendChild(hr);
    tbl.appendChild(thead);

    const tbody = el("tbody");
    (ev.rule_results || []).forEach((r) => {
      const tr = el("tr", "clickable-row");
      tr.appendChild(el("td", "", r.rule_id));
      tr.appendChild(el("td", "", r.functional_name));
      tr.appendChild(el("td", "", `${r.pillar} - ${r.workstream}`));
      tr.appendChild(el("td", "", r.current_provider_label));
      tr.appendChild(el("td", "", `${r.weight_points} pts`));
      const tdSt = el("td");
      const cls =
        r.status === "PASSED"
          ? "status-badge status-ok"
          : r.status === "EXCEPTION_APPROVED"
          ? "status-badge status-warn"
          : "status-badge status-err";
      tdSt.appendChild(el("span", cls, r.status));
      tr.appendChild(tdSt);
      tr.addEventListener("click", () => openSlotInspector(r.slot_id));
      tbody.appendChild(tr);
    });
    tbl.appendChild(tbody);
    wrap.appendChild(tbl);
    root.appendChild(wrap);
  }

  function renderDeployStage(root) {
    const ev = state.currentEvaluation;
    const tpl = state.workingTemplate;
    if (!ev || !tpl) return;

    const gateCard = el("div", "surface-card form-stack");
    const topBar = el("div", "toolbar-row");
    const left = el("div", "toolbar-left");
    left.appendChild(el("h2", "section-heading", `Release & Deployment Gate: ${tpl.agent_name}`));
    left.appendChild(
      el(
        "span",
        ev.gate_passed ? "status-badge status-ok" : "status-badge status-err",
        ev.gate_passed
          ? `[OK] Ready for Production (${ev.overall_score.toFixed(1)}/100)`
          : `[!] Gate Blocked (${ev.overall_score.toFixed(1)} / ${ev.passing_threshold.toFixed(1)})`
      )
    );
    topBar.appendChild(left);
    gateCard.appendChild(topBar);

    const kpis = el("div", "kpi-grid-4");
    const cEst = ev.cost_estimate;
    [
      ["Projected Monthly Run-Rate", formatUsd(cEst.monthly_run_rate_usd), `${cEst.estimated_monthly_turns_millions}M turns/mo`],
      ["One-Time Onboarding & Eval", formatUsd(cEst.onboarding_eval_cost_usd), "Initial provisioning & benchmarks"],
      ["Monthly Consolidation Delta", formatUsd(cEst.monthly_savings_usd), `vs. ${customerShortName()} baseline`],
      ["SENTINEL Agency Tier", tpl.risk_tier, tpl.risk_tier === "AG3" || tpl.risk_tier === "AG4" ? "Reviewer sign-off enforced" : "Automated release eligible"],
    ].forEach(([lbl, val, sub]) => {
      const c = el("div", "surface-card");
      c.append(el("p", "kpi-label", lbl), el("p", "kpi-value", val), el("p", "kpi-sub", sub));
      kpis.appendChild(c);
    });
    gateCard.appendChild(kpis);

    const deployForm = el("form", "form-grid-2");
    const appGrp = el("div", "field-group");
    const appLbl = el("label", "", "Approver Principal");
    appLbl.setAttribute("for", "deploy-approver-input");
    const appInp = el("input");
    appInp.type = "text";
    appInp.id = "deploy-approver-input";
    appInp.required = true;
    appInp.value = "platform-governance-lead";
    appGrp.append(appLbl, appInp);

    const tktGrp = el("div", "field-group");
    const tktLbl = el("label", "", "Release Change / Approval Ticket");
    tktLbl.setAttribute("for", "deploy-ticket-input");
    const tktInp = el("input");
    tktInp.type = "text";
    tktInp.id = "deploy-ticket-input";
    tktInp.value = "CHG-2026-8841";
    tktGrp.append(tktLbl, tktInp);

    const submitWrap = el("div", "toolbar-left");
    const deployBtn = el("button", "primary-btn", "Deploy Agent to Fleet");
    deployBtn.type = "submit";

    if (!ev.gate_passed) {
      const backBtn = el("button", "secondary-btn", "<- Return to Evaluate to Remediate");
      backBtn.type = "button";
      backBtn.addEventListener("click", () => setStage("evaluate"));
      submitWrap.appendChild(backBtn);
    }

    if (state.pendingHitl) {
      const hitlBtn = el(
        "button",
        "secondary-btn",
        `Approve ADK Checkpoint (${state.pendingHitl.interrupt_id})`
      );
      hitlBtn.type = "button";
      hitlBtn.addEventListener("click", async () => {
        hitlBtn.disabled = true;
        try {
          await apiPost("/api/agent/resume", {
            session_id: state.pendingHitl.session_id,
            interrupt_id: state.pendingHitl.interrupt_id,
            approved: true,
            approver_principal: appInp.value || "platform-governance-lead",
            vp_exception_ticket: tktInp.value || null,
            reason: "Approved via Cymbal Platform Deploy Release Gate.",
          });
          state.pendingHitl = null;
          renderStageBody();
          showToast("Resumed and completed ADK 2.0 AG3 deployment checkpoint.");
        } catch (err) {
          showError(err.message);
        } finally {
          hitlBtn.disabled = false;
        }
      });
      submitWrap.appendChild(hitlBtn);
    }

    submitWrap.appendChild(deployBtn);
    deployForm.append(appGrp, tktGrp, submitWrap);

    deployForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      deployBtn.disabled = true;
      try {
        const depRes = await apiPost("/api/templates/deploy", {
          template: state.workingTemplate,
          initial_score: state.initialScoreBaseline,
          approver_principal: appInp.value || "platform-governance-lead",
          vp_exception_ticket: tktInp.value || null,
        });
        state.operationsMetrics = depRes.operations_metrics;
        state.executiveCosts = depRes.executive_costs;
        state.walletState = depRes.wallet_state;
        renderStageBody();
        showToast(
          `Deployed ${depRes.deployment.agent_name} (${depRes.deployment.deployment_id}) at ${formatUsd(
            depRes.deployment.monthly_run_rate_usd
          )}/mo.`
        );
      } catch (err) {
        showError(err.message);
      } finally {
        deployBtn.disabled = false;
      }
    });

    gateCard.appendChild(deployForm);
    root.appendChild(gateCard);

    // Terraform HCL & Guardrail JSON Split
    const split = el("div", "split-2-col");
    const tfCard = el("div", "surface-card");
    const tfHead = el("div", "toolbar-row");
    tfHead.appendChild(el("strong", "", "Generated Terraform Module (infra/terraform)"));
    const copyTfBtn = el("button", "secondary-btn sm-btn", "Copy HCL");
    copyTfBtn.type = "button";
    copyTfBtn.addEventListener("click", () => {
      if (navigator.clipboard) {
        navigator.clipboard.writeText(ev.terraform_paved_path_hcl || "");
        showToast("Copied Terraform HCL module configuration.");
      }
    });
    tfHead.appendChild(copyTfBtn);
    tfCard.append(tfHead, el("pre", "code-block", ev.terraform_paved_path_hcl || ""));

    const polCard = el("div", "surface-card");
    const polHead = el("div", "toolbar-row");
    polHead.appendChild(el("strong", "", "Dynamic Guardrail Policy Payload"));
    const polJson = JSON.stringify(ev.dynamic_guardrail_policy_preview || {}, null, 2);
    const copyPolBtn = el("button", "secondary-btn sm-btn", "Copy JSON");
    copyPolBtn.type = "button";
    copyPolBtn.addEventListener("click", () => {
      if (navigator.clipboard) {
        navigator.clipboard.writeText(polJson);
        showToast("Copied Dynamic Guardrail Policy JSON.");
      }
    });
    polHead.appendChild(copyPolBtn);
    polCard.append(polHead, el("pre", "code-block", polJson));

    split.append(tfCard, polCard);
    root.appendChild(split);

    // Active Deployments Table
    const deps = (state.operationsMetrics && state.operationsMetrics.deployments) || [];
    root.appendChild(buildDeploymentsTable(deps, "Active Production Fleet Deployments (Click any row for 10-component cost breakdown)"));
  }

  function buildDeploymentsTable(deps, captionText) {
    const wrap = el("div", "table-wrap deferred-below-fold");
    const tbl = el("table", "data-table");
    tbl.appendChild(el("caption", "", captionText));
    const thead = el("thead");
    const hr = el("tr");
    [
      "Deployment ID",
      "Agent ID",
      "Business Unit",
      "Agency Tier",
      "Template Profile",
      "Score (Init -> Final)",
      "Monthly Run-Rate",
      "Cumulative Spend",
    ].forEach((h) => {
      const th = el("th", "", h);
      th.scope = "col";
      hr.appendChild(th);
    });
    thead.appendChild(hr);
    tbl.appendChild(thead);

    const tbody = el("tbody");
    deps.forEach((d) => {
      const tr = el("tr", "clickable-row");
      tr.appendChild(el("td", "", d.deployment_id));
      tr.appendChild(el("td", "", d.agent_name));
      tr.appendChild(el("td", "", d.business_unit_label || buLabel(d.business_unit)));
      tr.appendChild(el("td", "", String(d.risk_tier).toLowerCase()));
      tr.appendChild(el("td", "", ORIGIN_LABELS[d.origin] || d.origin));
      tr.appendChild(el("td", "", `${d.initial_eval_score} -> ${d.final_eval_score}`));
      tr.appendChild(el("td", "", formatUsd(d.monthly_run_rate_usd)));
      tr.appendChild(el("td", "", formatUsd(d.historical_cumulative_usd)));
      tr.addEventListener("click", () => openDeploymentInspector(d));
      tbody.appendChild(tr);
    });
    tbl.appendChild(tbody);
    wrap.appendChild(tbl);
    return wrap;
  }

  function renderGovernStage(root) {
    const headRow = el("div", "toolbar-row");
    headRow.appendChild(
      el("h1", "strip-title", "Platform Governance, Fleet Operations & FinOps")
    );
    root.appendChild(headRow);

    const tabDefs = [
      ["policies", "Policies & Rubric"],
      ["fleet", "Fleet Operations"],
      ["finops", "FinOps & Economics"],
      ["controls", "Runtime Controls"],
    ];

    const tabBar = el("div", "subtab-bar");
    tabBar.setAttribute("role", "tablist");
    tabBar.setAttribute("aria-label", "Governance Sections");

    tabDefs.forEach(([id, label], idx) => {
      const btn = el("button", "subtab-btn", label);
      btn.type = "button";
      btn.id = `gov-tab-${id}`;
      btn.setAttribute("role", "tab");
      const active = state.activeGovernTab === id;
      btn.classList.toggle("is-active", active);
      btn.setAttribute("aria-selected", active ? "true" : "false");
      btn.tabIndex = active ? 0 : -1;
      btn.addEventListener("click", () => {
        state.activeGovernTab = id;
        renderStageBody();
      });
      btn.addEventListener("keydown", (e) => {
        if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
        e.preventDefault();
        const delta = e.key === "ArrowRight" ? 1 : -1;
        const nextIdx = (idx + delta + tabDefs.length) % tabDefs.length;
        state.activeGovernTab = tabDefs[nextIdx][0];
        renderStageBody();
        const nextBtn = document.getElementById(`gov-tab-${state.activeGovernTab}`);
        if (nextBtn) nextBtn.focus();
      });
      tabBar.appendChild(btn);
    });
    root.appendChild(tabBar);

    const panel = el("div", "form-stack");
    panel.setAttribute("role", "tabpanel");
    panel.setAttribute("aria-labelledby", `gov-tab-${state.activeGovernTab}`);

    if (state.activeGovernTab === "policies") {
      renderGovernPoliciesTab(panel);
    } else if (state.activeGovernTab === "fleet") {
      renderGovernFleetTab(panel);
    } else if (state.activeGovernTab === "finops") {
      renderGovernFinopsTab(panel);
    } else {
      renderGovernControlsTab(panel);
    }
    root.appendChild(panel);
  }

  function renderGovernPoliciesTab(panel) {
    if (!state.rubric) return;
    const rub = cloneJson(state.rubric);

    const form = el("form", "form-stack");
    const topCard = el("div", "surface-card toolbar-row");
    const threshGrp = el("div", "field-group");
    const threshLbl = el("label", "", "Passing Readiness Score Threshold (50 - 100)");
    threshLbl.setAttribute("for", "rubric-threshold-input");
    const threshInp = el("input");
    threshInp.type = "number";
    threshInp.id = "rubric-threshold-input";
    threshInp.min = "50";
    threshInp.max = "100";
    threshInp.step = "0.5";
    threshInp.value = String(rub.passing_score_threshold);
    threshGrp.append(threshLbl, threshInp);

    const saveBtn = el("button", "primary-btn", "Save Governance Policies");
    saveBtn.type = "submit";
    topCard.append(threshGrp, saveBtn);
    form.appendChild(topCard);

    const wrap = el("div", "table-wrap");
    const tbl = el("table", "data-table");
    tbl.appendChild(
      el(
        "caption",
        "",
        "Live Governance Rubric Rules (Updates immediately govern Evaluate and Deploy gates)"
      )
    );
    const thead = el("thead");
    const hr = el("tr");
    ["Rule ID", "Pillar / Workstream", "Policy Requirement", "Mandatory Gate", "Weight (Pts)", "Default Fix Target", "Enabled"].forEach(
      (h) => {
        const th = el("th", "", h);
        th.scope = "col";
        hr.appendChild(th);
      }
    );
    thead.appendChild(hr);
    tbl.appendChild(thead);

    const tbody = el("tbody");
    rub.rules.forEach((rule, idx) => {
      const tr = el("tr");
      tr.appendChild(el("td", "", rule.rule_id));
      tr.appendChild(el("td", "", `${rule.pillar} - ${rule.workstream}`));
      tr.appendChild(el("td", "", rule.title));

      const tdMand = el("td");
      const mandChk = el("input");
      mandChk.type = "checkbox";
      mandChk.checked = Boolean(rule.mandatory);
      mandChk.setAttribute("aria-label", `${rule.rule_id} mandatory gate`);
      mandChk.addEventListener("change", () => {
        rub.rules[idx].mandatory = mandChk.checked;
      });
      tdMand.appendChild(mandChk);

      const tdW = el("td");
      const wInp = el("input");
      wInp.type = "number";
      wInp.min = "1";
      wInp.max = "40";
      wInp.value = String(rule.weight_points);
      wInp.setAttribute("aria-label", `${rule.rule_id} weight points`);
      wInp.addEventListener("change", () => {
        rub.rules[idx].weight_points = Number(wInp.value || 10);
      });
      tdW.appendChild(wInp);

      const tdProv = el("td");
      const pSel = el("select");
      pSel.setAttribute("aria-label", `${rule.rule_id} remediation target`);
      [
        ["google_gcp", gcpShortName()],
        ["cymbal_stack", customerShortName()],
      ].forEach(([val, txt]) => {
        const o = el("option", "", txt);
        o.value = val;
        if (rule.remediation_provider === val) o.selected = true;
        pSel.appendChild(o);
      });
      pSel.addEventListener("change", () => {
        rub.rules[idx].remediation_provider = pSel.value;
      });
      tdProv.appendChild(pSel);

      const tdEn = el("td");
      const enChk = el("input");
      enChk.type = "checkbox";
      enChk.checked = Boolean(rule.enabled);
      enChk.setAttribute("aria-label", `${rule.rule_id} enabled`);
      enChk.addEventListener("change", () => {
        rub.rules[idx].enabled = enChk.checked;
      });
      tdEn.appendChild(enChk);

      tr.append(tdMand, tdW, tdProv, tdEn);
      tbody.appendChild(tr);
    });
    tbl.appendChild(tbody);
    wrap.appendChild(tbl);
    form.appendChild(wrap);

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      rub.passing_score_threshold = Number(threshInp.value || 85);
      try {
        const res = await apiPost("/api/ops/rubric", rub);
        state.rubric = res.rubric;
        state.templates = res.templates;
        await refreshEvaluation(true);
        showToast(
          `Saved governance rubric (Passing threshold: >= ${state.rubric.passing_score_threshold}).`
        );
      } catch (err) {
        showError(err.message);
      }
    });

    panel.appendChild(form);
  }

  function renderGovernFleetTab(panel) {
    const m = state.operationsMetrics;
    if (!m) return;

    const ob = m.origin_breakdown || {};
    const kpis = el("div", "kpi-grid-4");
    [
      ["Active Fleet Deployments", String(m.total_deployments), `${m.clean_first_pass_count} clean first-pass`],
      [
        "Remediated Prior to Deploy",
        `${m.remediated_prior_to_deploy_pct}%`,
        `${m.remediated_prior_to_deploy_count} of ${m.total_deployments} deployments`,
      ],
      [
        "Average Score Uplift",
        `+${m.avg_score_uplift} pts`,
        `Initial ${m.avg_initial_eval_score} -> Final ${m.avg_final_eval_score}`,
      ],
      [
        "Template Profile Mix",
        `${ob.google_gcp_standard || 0} GCP | ${ob.cymbal_baseline || 0} ${customerShortName()}`,
        `${ob.custom_hybrid || 0} Custom Hybrid | ${ob.imported_manifest || 0} Imported`,
      ],
    ].forEach(([l, v, s]) => {
      const c = el("div", "surface-card");
      c.append(el("p", "kpi-label", l), el("p", "kpi-value", v), el("p", "kpi-sub", s));
      kpis.appendChild(c);
    });
    panel.appendChild(kpis);

    const wrap = el("div", "table-wrap");
    const tbl = el("table", "data-table");
    tbl.appendChild(
      el(
        "caption",
        "",
        `Component Adoption Across All 10 Functional Capabilities (${customerShortName()} vs. ${gcpShortName()})`
      )
    );
    const thead = el("thead");
    const hr = el("tr");
    [
      "Functional Capability",
      "Governance Pillar",
      "Workstream",
      `${customerShortName()} Deployments`,
      `${gcpShortName()} Deployments`,
      `${gcpShortName()} Share`,
    ].forEach((h) => {
      const th = el("th", "", h);
      th.scope = "col";
      hr.appendChild(th);
    });
    thead.appendChild(hr);
    tbl.appendChild(thead);

    const tbody = el("tbody");
    (m.component_adoption || []).forEach((row) => {
      const tr = el("tr");
      tr.appendChild(el("td", "", row.functional_name));
      tr.appendChild(el("td", "", row.pillar));
      tr.appendChild(el("td", "", row.workstream));
      tr.appendChild(
        el("td", "", `${row.counts.cymbal_stack} (${row.provider_labels.cymbal_stack})`)
      );
      tr.appendChild(
        el("td", "", `${row.counts.google_gcp} (${row.provider_labels.google_gcp})`)
      );
      const tdPct = el("td");
      tdPct.appendChild(el("span", "", `${row.google_gcp_pct}%`));
      const meter = el("progress", "meter-bar");
      meter.max = 100;
      meter.value = row.google_gcp_pct;
      tdPct.appendChild(meter);
      tr.appendChild(tdPct);
      tbody.appendChild(tr);
    });
    tbl.appendChild(tbody);
    wrap.appendChild(tbl);
    panel.appendChild(wrap);

    panel.appendChild(
      buildDeploymentsTable(m.deployments || [], "Fleet Deployment Audit Log (Click any row to inspect)")
    );
  }

  function renderGovernFinopsTab(panel) {
    const ec = state.executiveCosts;
    if (!ec) return;

    // Filter bar
    const filterCard = el("div", "surface-card toolbar-row");
    const fLeft = el("div", "toolbar-left");

    const buGrp = el("div", "field-group");
    const buLbl = el("label", "", "Business Unit");
    buLbl.setAttribute("for", "finops-bu-select");
    const buSel = el("select");
    buSel.id = "finops-bu-select";
    [
      ["all", "All Business Units"],
      ["core_cable", buLabel("core_cable")],
      ["media_studio", buLabel("media_studio")],
      ["intl_sky", buLabel("intl_sky")],
      ["enterprise_shared", buLabel("enterprise_shared")],
    ].forEach(([val, txt]) => {
      const o = el("option", "", txt);
      o.value = val;
      if (state.finopsFilters.business_unit === val) o.selected = true;
      buSel.appendChild(o);
    });
    buGrp.append(buLbl, buSel);

    const origGrp = el("div", "field-group");
    const origLbl = el("label", "", "Template Profile");
    origLbl.setAttribute("for", "finops-origin-select");
    const origSel = el("select");
    origSel.id = "finops-origin-select";
    [
      ["all", "All Template Profiles"],
      ["google_gcp_standard", "Google Cloud Standard"],
      ["cymbal_baseline", `${customerShortName()} Baseline`],
      ["custom_hybrid", "Custom Hybrid"],
      ["imported_manifest", "Imported Manifest"],
    ].forEach(([val, txt]) => {
      const o = el("option", "", txt);
      o.value = val;
      if (state.finopsFilters.origin === val) o.selected = true;
      origSel.appendChild(o);
    });
    origGrp.append(origLbl, origSel);

    const reloadFinops = async () => {
      state.finopsFilters.business_unit = buSel.value;
      state.finopsFilters.origin = origSel.value;
      try {
        const params = new URLSearchParams(state.finopsFilters);
        state.executiveCosts = await apiGet(`/api/executive/costs?${params.toString()}`);
        renderStageBody();
      } catch (err) {
        showError(err.message);
      }
    };
    buSel.addEventListener("change", reloadFinops);
    origSel.addEventListener("change", reloadFinops);

    fLeft.append(buGrp, origGrp);
    filterCard.appendChild(fLeft);
    panel.appendChild(filterCard);

    const kpis = el("div", "kpi-grid-4");
    [
      ["Historical Cumulative Spend", formatUsd(ec.total_historical_cumulative_usd), `${ec.deployment_count} deployments`],
      ["Current Monthly Run-Rate", formatUsd(ec.total_monthly_run_rate_usd), `Avg ${formatUsd(ec.avg_cost_per_deployment_monthly_usd)} / agent`],
      ["Projected Annual Run-Rate", formatUsd(ec.projected_annual_run_rate_usd), "12-month annualized"],
      ["Annual Consolidation Savings", formatUsd(ec.projected_annual_consolidation_savings_usd), `vs. 100% ${customerShortName()} baseline`],
    ].forEach(([l, v, s]) => {
      const c = el("div", "surface-card");
      c.append(el("p", "kpi-label", l), el("p", "kpi-value", v), el("p", "kpi-sub", s));
      kpis.appendChild(c);
    });
    panel.appendChild(kpis);

    // 4 Governance Pillars Spend Summary
    const pillarGrid = el("div", "kpi-grid-4");
    (ec.pillar_cost_rollup || []).forEach((p) => {
      const c = el("div", "surface-card");
      c.append(
        el("p", "kpi-label", `${p.pillar} Pillar Spend`),
        el("p", "kpi-value", formatUsd(p.historical_cumulative_usd)),
        el("p", "kpi-sub", `${formatUsd(p.monthly_run_rate_usd)}/mo (${p.share_of_total_pct}% share)`)
      );
      pillarGrid.appendChild(c);
    });
    panel.appendChild(pillarGrid);

    // 10-Component Historical Spend Table
    const compWrap = el("div", "table-wrap");
    const compTbl = el("table", "data-table");
    compTbl.appendChild(
      el(
        "caption",
        "",
        "Aggregate Historical Spend Across All 10 Functional Components (Click any component row to inspect top agents)"
      )
    );
    const ch = el("thead");
    const chr = el("tr");
    [
      "Functional Component",
      "Pillar",
      `${customerShortName()} Spend`,
      `${gcpShortName()} Spend`,
      "Monthly Run-Rate",
      "Historical Total",
      "Share",
    ].forEach((h) => {
      const th = el("th", "", h);
      th.scope = "col";
      chr.appendChild(th);
    });
    ch.appendChild(chr);
    compTbl.appendChild(ch);

    const cbody = el("tbody");
    (ec.component_cost_rollup || []).forEach((comp) => {
      const tr = el("tr", "clickable-row");
      tr.appendChild(el("td", "", comp.functional_name));
      tr.appendChild(el("td", "", comp.pillar));
      tr.appendChild(el("td", "", formatUsd(comp.spend_by_provider_usd.cymbal_stack)));
      tr.appendChild(el("td", "", formatUsd(comp.spend_by_provider_usd.google_gcp)));
      tr.appendChild(el("td", "", formatUsd(comp.monthly_run_rate_usd)));
      tr.appendChild(el("td", "", formatUsd(comp.historical_cumulative_usd)));
      tr.appendChild(el("td", "", `${comp.share_of_total_pct}%`));
      tr.addEventListener("click", () => openComponentFinopsInspector(comp));
      cbody.appendChild(tr);
    });
    compTbl.appendChild(cbody);
    compWrap.appendChild(compTbl);
    panel.appendChild(compWrap);

    // Per-Agent Deployment Cost Ledger
    panel.appendChild(
      buildDeploymentsTable(
        ec.deployments || [],
        "Per-Agent Deployment Cost Ledger (Click any row for 10-component cost attribution)"
      )
    );

    // Scale Economics Simulator
    const tcoCard = el("div", "surface-card form-stack deferred-below-fold");
    tcoCard.appendChild(el("h3", "section-heading", "Guardrail Scale Economics Simulator (1M - 50M Daily Turns)"));
    const tcoRow = el("div", "toolbar-row");
    const turnsGrp = el("div", "field-group");
    const turnsLbl = el("label", "", "Daily Fleet Turns");
    turnsLbl.setAttribute("for", "tco-daily-turns-select");
    const turnsSel = el("select");
    turnsSel.id = "tco-daily-turns-select";
    [
      [1000000, "1,000,000 turns/day"],
      [5000000, "5,000,000 turns/day"],
      [10000000, "10,000,000 turns/day"],
      [25000000, "25,000,000 turns/day"],
      [50000000, "50,000,000 turns/day"],
    ].forEach(([val, txt]) => {
      const o = el("option", "", txt);
      o.value = String(val);
      if (state.tcoReport && state.tcoReport.daily_turns === val) o.selected = true;
      turnsSel.appendChild(o);
    });
    turnsGrp.append(turnsLbl, turnsSel);

    const calcBtn = el("button", "secondary-btn", "Recalculate Scale Model");
    calcBtn.type = "button";
    calcBtn.addEventListener("click", async () => {
      try {
        state.tcoReport = await apiPost("/api/steward/tco", {
          daily_turns: Number(turnsSel.value),
          tokens_per_turn: 1000,
        });
        renderStageBody();
      } catch (err) {
        showError(err.message);
      }
    });
    tcoRow.append(turnsGrp, calcBtn);
    tcoCard.appendChild(tcoRow);

    if (state.tcoReport) {
      const t = state.tcoReport;
      const tGrid = el("div", "kpi-grid-4");
      [
        ["Model Armor Tier-0 Annual", formatUsd(t.model_armor_only_annual_usd), "$0.10 / 1M tokens"],
        ["20% Ensemble Annual", formatUsd(t.ensemble_20pct_annual_usd), "Tier-0 + 20% secondary voter"],
        ["Legacy 3-Model Voter Annual", formatUsd(t.three_llm_voter_annual_usd), "100% 3-LLM ensemble"],
        ["Annual Savings (Model Armor)", formatUsd(t.annual_savings_model_armor_vs_voter_usd), `${t.savings_pct_model_armor_vs_voter}% reduction`],
      ].forEach(([l, v, s]) => {
        const c = el("div", "surface-card");
        c.append(el("p", "kpi-label", l), el("p", "kpi-value", v), el("p", "kpi-sub", s));
        tGrid.appendChild(c);
      });
      tcoCard.appendChild(tGrid);
    }
    panel.appendChild(tcoCard);
  }

  function renderGovernControlsTab(panel) {
    const split = el("div", "split-2-col");

    // 1. Kill Switch & Atomic Budget Cap
    const killCard = el("div", "surface-card form-stack");
    killCard.appendChild(el("h3", "section-heading", "Global Containment & Atomic Budget Controls"));
    const curStatus = (state.agentState && state.agentState.status) || "ACTIVE";
    killCard.appendChild(
      el(
        "span",
        curStatus === "ACTIVE" ? "status-badge status-ok" : "status-badge status-err",
        `Fleet Runtime State: ${curStatus}`
      )
    );

    const killBtns = el("div", "toolbar-left");
    ["ACTIVE", "PAUSED", "DISABLED"].forEach((st) => {
      const b = el("button", st === curStatus ? "primary-btn sm-btn" : "secondary-btn sm-btn", st);
      b.type = "button";
      b.addEventListener("click", async () => {
        try {
          const res = await apiPost("/api/steward/kill-switch", { status: st });
          state.agentState = res.agent_state;
          renderStageBody();
          showToast(`Global runtime kill switch updated to ${st}.`);
        } catch (err) {
          showError(err.message);
        }
      });
      killBtns.appendChild(b);
    });
    killCard.appendChild(killBtns);

    const spentUsd = ((state.walletState && state.walletState.spent_nano_usd) || 0) / 1e9;
    const capUsd = ((state.walletState && state.walletState.monthly_cap_nano_usd) || 15000000000) / 1e9;
    const capGrp = el("div", "field-group");
    const capLbl = el("label", "", `Atomic Budget Ceiling USD (Current Spend: $${spentUsd.toFixed(6)})`);
    capLbl.setAttribute("for", "wallet-cap-usd-input");
    const capInp = el("input");
    capInp.type = "number";
    capInp.id = "wallet-cap-usd-input";
    capInp.step = "0.01";
    capInp.min = "0";
    capInp.value = String(capUsd);
    capGrp.append(capLbl, capInp);

    const capBtns = el("div", "toolbar-left");
    const updCapBtn = el("button", "secondary-btn sm-btn", "Update Ceiling");
    updCapBtn.type = "button";
    updCapBtn.addEventListener("click", async () => {
      try {
        const nano = Math.round(Number(capInp.value || 0) * 1e9);
        const r = await apiPost("/api/steward/wallet-cap", {
          monthly_cap_nano_usd: nano,
          reset_spend: false,
        });
        state.walletState = r.wallet_state;
        renderStageBody();
        showToast(`Updated atomic wallet ceiling to $${Number(capInp.value || 0).toFixed(2)}.`);
      } catch (err) {
        showError(err.message);
      }
    });

    const oboBtn = el("button", "secondary-btn sm-btn", "Verify OBO Token Pair (ADR-011)");
    oboBtn.type = "button";
    oboBtn.addEventListener("click", async () => {
      try {
        state.lastOboResult = await apiPost("/api/steward/obo-verify", {});
        renderStageBody();
        showToast("Verified ADR-011 OIDC azp correlation and rejected mismatched party.");
      } catch (err) {
        showError(err.message);
      }
    });
    capBtns.append(updCapBtn, oboBtn);
    killCard.append(capGrp, capBtns);

    if (state.lastOboResult) {
      killCard.appendChild(
        el("pre", "code-block", JSON.stringify(state.lastOboResult.adr011_valid_pair, null, 2))
      );
    }

    // 2. Dynamic Guardrail Live Policy Tester
    const guardCard = el("div", "surface-card form-stack");
    guardCard.appendChild(el("h3", "section-heading", "Dynamic Guardrail & Inline PII Policy Tester"));
    const gTxtGrp = el("div", "field-group");
    const gLbl = el("label", "", "Inspection Input Payload");
    gLbl.setAttribute("for", "guardrail-test-input");
    const gTxt = el("textarea");
    gTxt.id = "guardrail-test-input";
    gTxt.rows = 3;
    gTxt.value = "Subscriber log check: SSN 123-45-6789 on gateway MAC aa:bb:cc:dd:ee:ff";
    gTxtGrp.append(gLbl, gTxt);

    const gModeGrp = el("div", "field-group");
    const gModeLbl = el("label", "", "PII Enforcement Mode");
    gModeLbl.setAttribute("for", "guardrail-sdp-select");
    const gModeSel = el("select");
    gModeSel.id = "guardrail-sdp-select";
    [
      ["DEIDENTIFY_INLINE", "DEIDENTIFY_INLINE (Mask PII & Continue)"],
      ["BLOCK_ON_MATCH", "BLOCK_ON_MATCH (Strict Regional Block)"],
    ].forEach(([val, txt]) => {
      const o = el("option", "", txt);
      o.value = val;
      gModeSel.appendChild(o);
    });
    gModeGrp.append(gModeLbl, gModeSel);

    const gRunBtn = el("button", "primary-btn sm-btn", "Inspect Payload");
    gRunBtn.type = "button";
    gRunBtn.addEventListener("click", async () => {
      try {
        state.lastGuardrailVerdict = await apiPost("/api/steward/guardrail-test", {
          sample_text: gTxt.value,
          dynamic_policy: {
            business_unit: gModeSel.value === "BLOCK_ON_MATCH" ? "intl_sky" : "core_cable",
            risk_tier: "AG3",
            sdp_pii_mode: gModeSel.value,
            ensemble_role: "tier0_prefilter",
          },
        });
        renderStageBody();
      } catch (err) {
        showError(err.message);
      }
    });
    guardCard.append(gTxtGrp, gModeGrp, gRunBtn);

    if (state.lastGuardrailVerdict) {
      const gv = state.lastGuardrailVerdict;
      guardCard.appendChild(
        el(
          "span",
          gv.allowed ? "status-badge status-ok" : "status-badge status-err",
          `${gv.action_taken} (${gv.latency_ms}ms)`
        )
      );
      guardCard.appendChild(el("pre", "code-block", gv.sanitized_text));
    }

    split.append(killCard, guardCard);
    panel.appendChild(split);

    // 3. Live Platform Verification Suite (8 Checks)
    const proofCard = el("div", "surface-card form-stack");
    const pHead = el("div", "toolbar-row");
    pHead.appendChild(el("h3", "section-heading", "Live Control Plane Verification Checks (8)"));
    const runAllBtn = el("button", "secondary-btn sm-btn", "Run All 8 Verification Checks");
    runAllBtn.type = "button";
    runAllBtn.addEventListener("click", async () => {
      runAllBtn.disabled = true;
      try {
        const res = await apiPost("/api/steward/proofs-all", {});
        state.proofResults = res.proofs || [];
        renderStageBody();
        showToast(`Passed ${res.passed_count}/${res.total_count} live verification checks.`);
      } catch (err) {
        showError(err.message);
      } finally {
        runAllBtn.disabled = false;
      }
    });
    pHead.appendChild(runAllBtn);
    proofCard.appendChild(pHead);

    if (state.proofResults.length > 0) {
      const pWrap = el("div", "table-wrap");
      const pTbl = el("table", "data-table");
      pTbl.appendChild(el("caption", "", "Measured Control Plane Verification Results"));
      const ph = el("thead");
      const phr = el("tr");
      ["#", "Capability Check", "Status", "Latency", "Measured Evidence"].forEach((h) => {
        const th = el("th", "", h);
        th.scope = "col";
        phr.appendChild(th);
      });
      ph.appendChild(phr);
      pTbl.appendChild(ph);
      const pb = el("tbody");
      state.proofResults.forEach((pr) => {
        const tr = el("tr");
        tr.appendChild(el("td", "", String(pr.proof_id)));
        tr.appendChild(el("td", "", pr.title));
        const tdS = el("td");
        tdS.appendChild(
          el(
            "span",
            pr.passed ? "status-badge status-ok" : "status-badge status-err",
            pr.passed ? "PASS" : "FAIL"
          )
        );
        tr.appendChild(tdS);
        tr.appendChild(el("td", "", `${pr.latency_ms}ms`));
        tr.appendChild(el("td", "", pr.measured_evidence));
        pb.appendChild(tr);
      });
      pTbl.appendChild(pb);
      pWrap.appendChild(pTbl);
      proofCard.appendChild(pWrap);
    }
    panel.appendChild(proofCard);
  }

  /* Right Slide-Out Drawer (<dialog>) Controllers */
  function showDrawerModal(eyebrowText, headingText, activeTab = "inspector") {
    const dlg = document.getElementById("right-inspector-drawer");
    const eye = document.getElementById("drawer-eyebrow");
    const hd = document.getElementById("drawer-heading");
    if (eye) eye.textContent = eyebrowText;
    if (hd) hd.textContent = headingText;

    setDrawerTab(activeTab);
    if (dlg && !dlg.open) {
      dlg.showModal();
    }
    const pipeBtn = document.getElementById("open-pipeline-drawer-btn");
    if (pipeBtn) pipeBtn.setAttribute("aria-expanded", "true");
  }

  function closeDrawerModal() {
    const dlg = document.getElementById("right-inspector-drawer");
    if (dlg && dlg.open) {
      dlg.close();
    }
    state.selectedSlotId = null;
    renderTenTileStrip();
    const pipeBtn = document.getElementById("open-pipeline-drawer-btn");
    if (pipeBtn) pipeBtn.setAttribute("aria-expanded", "false");
  }

  function setDrawerTab(tabName) {
    const inspBtn = document.getElementById("drawer-tab-inspector");
    const pipeBtn = document.getElementById("drawer-tab-pipeline");
    const inspPanel = document.getElementById("drawer-panel-inspector");
    const pipePanel = document.getElementById("drawer-panel-pipeline");
    const isInsp = tabName !== "pipeline";

    if (inspBtn && pipeBtn && inspPanel && pipePanel) {
      inspBtn.classList.toggle("is-active", isInsp);
      inspBtn.setAttribute("aria-selected", isInsp ? "true" : "false");
      inspBtn.tabIndex = isInsp ? 0 : -1;

      pipeBtn.classList.toggle("is-active", !isInsp);
      pipeBtn.setAttribute("aria-selected", !isInsp ? "true" : "false");
      pipeBtn.tabIndex = !isInsp ? 0 : -1;

      inspPanel.hidden = !isInsp;
      pipePanel.hidden = isInsp;
    }
    if (!isInsp) {
      renderPipelineList();
    }
  }

  function openPipelineDrawer() {
    showDrawerModal("Live Runtime Telemetry", "9-Service Control Plane Pipeline", "pipeline");
  }

  function renderPipelineList() {
    const list = document.getElementById("vertical-pipeline-list");
    const evBanner = document.getElementById("pipeline-last-event");
    if (!list || !state.platformServices) return;
    if (evBanner) {
      evBanner.textContent = state.platformServices.last_event || "Control plane active.";
    }
    list.replaceChildren();
    (state.platformServices.services || []).forEach((svc) => {
      const li = el("li", "pipeline-item");
      const top = el("div", "pipeline-item-top");
      top.appendChild(el("strong", "", `${svc.step}. ${svc.name}`));
      const ok = svc.status === "READY" || svc.status === "VERIFIED" || svc.status === "ACTIVE";
      top.appendChild(
        el(
          "span",
          ok ? "status-badge status-ok" : "status-badge status-warn",
          svc.badge_label || svc.status
        )
      );
      li.appendChild(top);
      li.appendChild(el("span", "field-hint", svc.subtitle));
      li.appendChild(el("span", "kpi-sub", svc.summary));
      list.appendChild(li);
    });
  }

  function openSlotInspector(slotId) {
    const spec = state.slotById[slotId];
    const tpl = state.workingTemplate;
    if (!spec || !tpl) return;

    state.selectedSlotId = slotId;
    renderTenTileStrip();

    const body = document.getElementById("drawer-panel-inspector");
    if (!body) return;
    body.replaceChildren();

    const comp = (tpl.components && tpl.components[slotId]) || {
      slot_id: slotId,
      provider: "unconfigured",
      enabled: false,
      parameters: {},
    };
    const curProv = comp.enabled === false ? "unconfigured" : comp.provider;
    const lockedGcp = tpl.template_mode === "google_gcp";

    const metaCard = el("div", "surface-card form-stack");
    metaCard.appendChild(
      el("span", "status-badge status-ok", `${spec.pillar} Pillar | ${spec.workstream}`)
    );
    metaCard.appendChild(el("p", "kpi-sub", `API Surface: ${spec.api_surface}`));
    metaCard.appendChild(el("p", "field-hint", `Consolidates: ${spec.consolidates}`));
    body.appendChild(metaCard);

    if (lockedGcp) {
      const lockNotice = el("div", "surface-card form-stack");
      lockNotice.appendChild(
        el(
          "p",
          "kpi-sub",
          "Template profile is currently set to Google Cloud (all 10 tiles locked to Google Cloud components)."
        )
      );
      const unlockBtn = el("button", "secondary-btn sm-btn", "Switch to Custom Mode to Edit Component");
      unlockBtn.type = "button";
      unlockBtn.addEventListener("click", async () => {
        await handleTemplateProfileSwitch("custom");
        openSlotInspector(slotId);
      });
      lockNotice.appendChild(unlockBtn);
      body.appendChild(lockNotice);
    }

    const form = el("form", "form-stack");
    const fs = el("fieldset", "radio-card-list");
    fs.disabled = lockedGcp;
    fs.appendChild(el("legend", "section-heading", "Select Solution Component"));

    const turns = Number(tpl.estimated_monthly_turns_millions || 3.5);
    [
      ["cymbal_stack", customerShortName(), spec.cymbal_name],
      ["google_gcp", gcpShortName(), spec.gcp_name],
    ].forEach(([provKey, vendorLabel, compTitle]) => {
      const rates = spec.pricing[provKey];
      const monthly = rates.base_monthly_usd + rates.per_1m_turns_usd * turns;
      const lbl = el("label", "radio-card-option");
      const rad = el("input");
      rad.type = "radio";
      rad.name = "slot_provider_choice";
      rad.value = provKey;
      rad.checked = curProv === provKey;

      const textCol = el("div", "field-group");
      textCol.appendChild(el("strong", "", `${vendorLabel}: ${compTitle}`));
      textCol.appendChild(
        el(
          "span",
          "field-hint",
          `Est. ${formatUsd(monthly)}/mo at ${turns}M turns (+${formatUsd(rates.onboarding_usd)} onboarding)`
        )
      );
      lbl.append(rad, textCol);
      fs.appendChild(lbl);
    });
    form.appendChild(fs);

    // Contextual Policy Controls per Slot
    if (slotId === "identity_access" && tpl.static_secrets_in_env && tpl.static_secrets_in_env.length > 0) {
      const secChkLbl = el("label", "radio-card-option");
      const secChk = el("input");
      secChk.type = "checkbox";
      secChk.id = "slot-clear-secrets-chk";
      secChk.checked = true;
      secChkLbl.append(
        secChk,
        el("span", "", `Remove static env credentials (${tpl.static_secrets_in_env.join(", ")})`)
      );
      form.appendChild(secChkLbl);
    }

    if (slotId === "agent_registry") {
      const inGrp = el("div", "field-group");
      const inLbl = el("label", "", (state.tenant && state.tenant.terminology.intake_col_label) || "ATLAS Intake ID");
      inLbl.setAttribute("for", "slot-intake-input");
      const inInp = el("input");
      inInp.type = "text";
      inInp.id = "slot-intake-input";
      inInp.value = tpl.intake_id || "atlas-2026-0841";
      inGrp.append(inLbl, inInp);
      form.appendChild(inGrp);
    }

    if (slotId === "ai_gateway") {
      const celLbl = el("label", "radio-card-option");
      const celChk = el("input");
      celChk.type = "checkbox";
      celChk.id = "slot-uap-cel-chk";
      celChk.checked = Boolean(tpl.uap_cel_per_tool_enforced);
      celLbl.append(celChk, el("span", "", "Enforce inline per-tool UAP Policy V2 CEL authorization"));
      form.appendChild(celLbl);
    }

    if (slotId === "safety_guardrails") {
      const sdpGrp = el("div", "field-group");
      const sdpLbl = el("label", "", "Inline PII Inspection Mode");
      sdpLbl.setAttribute("for", "slot-sdp-mode-select");
      const sdpSel = el("select");
      sdpSel.id = "slot-sdp-mode-select";
      ["DEIDENTIFY_INLINE", "BLOCK_ON_MATCH", "INSPECT_ONLY", "NONE"].forEach((m) => {
        const o = el("option", "", m);
        o.value = m;
        if (tpl.sdp_pii_mode === m) o.selected = true;
        sdpSel.appendChild(o);
      });
      sdpGrp.append(sdpLbl, sdpSel);
      form.appendChild(sdpGrp);
    }

    if (!lockedGcp) {
      const applyBtn = el("button", "primary-btn", "Apply Component Selection");
      applyBtn.type = "submit";
      form.appendChild(applyBtn);
    }

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const chosen = form.querySelector('input[name="slot_provider_choice"]:checked');
      const nextProv = chosen ? chosen.value : "google_gcp";
      tpl.template_mode = "custom";
      tpl.origin = "custom_hybrid";
      tpl.components[slotId] = {
        slot_id: slotId,
        provider: nextProv,
        enabled: true,
        enterprise_sync_enabled: true,
        parameters: {},
      };

      const secChk = document.getElementById("slot-clear-secrets-chk");
      if (secChk && secChk.checked) {
        tpl.static_secrets_in_env = [];
      }
      const inInp = document.getElementById("slot-intake-input");
      if (inInp) {
        tpl.intake_id = inInp.value.trim();
      }
      const celChk = document.getElementById("slot-uap-cel-chk");
      if (celChk) {
        tpl.uap_cel_per_tool_enforced = celChk.checked;
      }
      const sdpSel = document.getElementById("slot-sdp-mode-select");
      if (sdpSel) {
        tpl.sdp_pii_mode = sdpSel.value;
      }

      await refreshEvaluation(false);
      closeDrawerModal();
      showToast(`Updated '${spec.functional_name}' to ${providerBadgeInfo(nextProv).text}.`);
    });

    body.appendChild(form);
    showDrawerModal(`${spec.pillar} Pillar`, spec.functional_name, "inspector");
  }

  function openMetadataInspector() {
    const tpl = state.workingTemplate;
    if (!tpl) return;
    const terms = (state.tenant && state.tenant.terminology) || {};
    const body = document.getElementById("drawer-panel-inspector");
    if (!body) return;
    body.replaceChildren();

    const form = el("form", "form-stack");
    const makeField = (id, labelTxt, val, type = "text") => {
      const g = el("div", "field-group");
      const l = el("label", "", labelTxt);
      l.setAttribute("for", id);
      const inp = el("input");
      inp.type = type;
      inp.id = id;
      inp.value = String(val ?? "");
      inp.required = id !== "meta-intake-id";
      inp.addEventListener("blur", () => inp.reportValidity());
      inp.addEventListener("input", () => inp.setCustomValidity(""));
      g.append(l, inp);
      return { group: g, input: inp };
    };

    const fAgent = makeField("meta-agent-name", "Agent ID", tpl.agent_name);
    const fApp = makeField("meta-app-id", terms.cmdb_col_label || "ServiceAtlas CMDB App ID", tpl.app_id);
    const fIntake = makeField("meta-intake-id", terms.intake_col_label || "ATLAS Intake ID", tpl.intake_id);
    const fTurns = makeField("meta-turns-m", "Estimated Monthly Turns (Millions)", tpl.estimated_monthly_turns_millions, "number");
    fTurns.input.step = "0.1";
    fTurns.input.min = "0.1";

    const buGrp = el("div", "field-group");
    const buLbl = el("label", "", "Business Unit");
    buLbl.setAttribute("for", "meta-bu-select");
    const buSel = el("select");
    buSel.id = "meta-bu-select";
    ["core_cable", "media_studio", "intl_sky", "enterprise_shared"].forEach((k) => {
      const o = el("option", "", buLabel(k));
      o.value = k;
      if (tpl.business_unit === k) o.selected = true;
      buSel.appendChild(o);
    });
    buGrp.append(buLbl, buSel);

    const riskGrp = el("div", "field-group");
    const riskLbl = el("label", "", terms.risk_col_label || "SENTINEL Agency Tier");
    riskLbl.setAttribute("for", "meta-risk-select");
    const riskSel = el("select");
    riskSel.id = "meta-risk-select";
    ["AG1", "AG2", "AG3", "AG4"].forEach((r) => {
      const o = el("option", "", r.toLowerCase());
      o.value = r;
      if (tpl.risk_tier === r) o.selected = true;
      riskSel.appendChild(o);
    });
    riskGrp.append(riskLbl, riskSel);

    const sysGrp = el("div", "field-group");
    const sysLbl = el("label", "", "Agent System Instruction");
    sysLbl.setAttribute("for", "meta-sys-instruction");
    const sysTxt = el("textarea");
    sysTxt.id = "meta-sys-instruction";
    sysTxt.rows = 4;
    sysTxt.value = tpl.system_instruction || "";
    sysGrp.append(sysLbl, sysTxt);

    const saveBtn = el("button", "primary-btn", "Apply & Save Agent Metadata");
    saveBtn.type = "submit";

    form.append(
      fAgent.group,
      buGrp,
      fApp.group,
      fIntake.group,
      riskGrp,
      fTurns.group,
      sysGrp,
      saveBtn
    );

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      tpl.agent_name = fAgent.input.value.trim() || tpl.agent_name;
      tpl.name = tpl.agent_name;
      tpl.business_unit = buSel.value;
      tpl.app_id = fApp.input.value.trim() || tpl.app_id;
      tpl.intake_id = fIntake.input.value.trim();
      tpl.risk_tier = riskSel.value;
      tpl.estimated_monthly_turns_millions = Number(fTurns.input.value || 3.5);
      tpl.system_instruction = sysTxt.value;
      await saveCurrentTemplate();
      closeDrawerModal();
    });

    body.appendChild(form);
    showDrawerModal("Agent Metadata", tpl.agent_name, "inspector");
  }

  function openDeploymentInspector(dep) {
    const body = document.getElementById("drawer-panel-inspector");
    if (!body) return;
    body.replaceChildren();

    const summary = el("div", "surface-card form-stack");
    summary.appendChild(
      el(
        "span",
        "status-badge status-ok",
        `${dep.deployment_id} | ${dep.business_unit_label || buLabel(dep.business_unit)} | ${String(
          dep.risk_tier
        ).toLowerCase()}`
      )
    );
    summary.appendChild(
      el(
        "p",
        "kpi-sub",
        `Score: ${dep.initial_eval_score} -> ${dep.final_eval_score} | Monthly: ${formatUsd(
          dep.monthly_run_rate_usd
        )} | Cumulative: ${formatUsd(dep.historical_cumulative_usd)}`
      )
    );
    summary.appendChild(el("p", "field-hint", `Trace ID: ${dep.trace_id}`));
    body.appendChild(summary);

    const wrap = el("div", "table-wrap");
    const tbl = el("table", "data-table");
    tbl.appendChild(el("caption", "", "10-Component Deployment Cost Attribution"));
    const th = el("thead");
    const hr = el("tr");
    ["Component", "Selected Provider", "Monthly", "Cumulative"].forEach((c) => {
      const cell = el("th", "", c);
      cell.scope = "col";
      hr.appendChild(cell);
    });
    th.appendChild(hr);
    tbl.appendChild(th);

    const tb = el("tbody");
    (dep.component_costs || []).forEach((c) => {
      const tr = el("tr");
      tr.appendChild(el("td", "", c.functional_name || c.capability_name));
      tr.appendChild(el("td", "", c.provider_display_name));
      tr.appendChild(el("td", "", formatUsd(c.monthly_cost_usd)));
      tr.appendChild(el("td", "", formatUsd(c.historical_cumulative_usd)));
      tb.appendChild(tr);
    });
    tbl.appendChild(tb);
    wrap.appendChild(tbl);
    body.appendChild(wrap);

    showDrawerModal("Deployment Cost Ledger", dep.agent_name, "inspector");
  }

  function openComponentFinopsInspector(comp) {
    const body = document.getElementById("drawer-panel-inspector");
    if (!body) return;
    body.replaceChildren();

    const card = el("div", "surface-card form-stack");
    card.appendChild(el("span", "status-badge status-ok", `${comp.pillar} Pillar | ${comp.workstream}`));
    card.appendChild(
      el(
        "p",
        "kpi-sub",
        `Cumulative: ${formatUsd(comp.historical_cumulative_usd)} (${comp.share_of_total_pct}% of fleet) | Monthly: ${formatUsd(
          comp.monthly_run_rate_usd
        )}`
      )
    );
    card.appendChild(
      el(
        "p",
        "field-hint",
        `${customerShortName()}: ${formatUsd(comp.spend_by_provider_usd.cymbal_stack)} (${
          comp.deployments_by_provider.cymbal_stack
        } agents) | ${gcpShortName()}: ${formatUsd(comp.spend_by_provider_usd.google_gcp)} (${
          comp.deployments_by_provider.google_gcp
        } agents)`
      )
    );
    body.appendChild(card);

    const wrap = el("div", "table-wrap");
    const tbl = el("table", "data-table");
    tbl.appendChild(el("caption", "", "Top Contributing Agent Deployments"));
    const th = el("thead");
    const hr = el("tr");
    ["Agent ID", "Business Unit", "Provider", "Cumulative"].forEach((c) => {
      const cell = el("th", "", c);
      cell.scope = "col";
      hr.appendChild(cell);
    });
    th.appendChild(hr);
    tbl.appendChild(th);

    const tb = el("tbody");
    (comp.top_deployments || []).forEach((d) => {
      const tr = el("tr");
      tr.appendChild(el("td", "", d.agent_name));
      tr.appendChild(el("td", "", d.business_unit_label));
      tr.appendChild(el("td", "", providerBadgeInfo(d.provider).text));
      tr.appendChild(el("td", "", formatUsd(d.historical_cumulative_usd)));
      tb.appendChild(tr);
    });
    tbl.appendChild(tb);
    wrap.appendChild(tbl);
    body.appendChild(wrap);

    showDrawerModal("Component FinOps Attribution", comp.functional_name, "inspector");
  }

  /* Center Modal for + New Agent & Import Manifest */
  function openNewAgentModal() {
    const dlg = document.getElementById("agent-modal-dialog");
    const hd = document.getElementById("agent-modal-heading");
    const body = document.getElementById("agent-modal-body");
    if (!dlg || !body) return;
    if (hd) hd.textContent = "Register New Agent";
    body.replaceChildren();

    const terms = (state.tenant && state.tenant.terminology) || {};
    const form = el("form", "form-stack");

    const addInput = (id, label, defVal) => {
      const g = el("div", "field-group");
      const l = el("label", "", label);
      l.setAttribute("for", id);
      const i = el("input");
      i.type = "text";
      i.id = id;
      i.required = true;
      i.value = defVal;
      g.append(l, i);
      return { group: g, input: i };
    };

    const nextNum = state.templates.length + 1;
    const fName = addInput("new-agent-id", "Agent ID", `customer-care-agent-${nextNum}`);
    const fApp = addInput("new-app-id", terms.cmdb_col_label || "ServiceAtlas CMDB App ID", `svc-cymbal-${990 + nextNum}`);
    const fIntake = addInput("new-intake-id", terms.intake_col_label || "ATLAS Intake ID", `atlas-2026-08${40 + nextNum}`);

    const profGrp = el("div", "field-group");
    const profLbl = el("label", "", "Initial Template Profile");
    profLbl.setAttribute("for", "new-agent-profile");
    const profSel = el("select");
    profSel.id = "new-agent-profile";
    [
      ["google_gcp", "Google Cloud (All 10 Google Cloud components)"],
      ["custom_cymbal", `Custom (${customerShortName()} baseline components)`],
    ].forEach(([val, txt]) => {
      const o = el("option", "", txt);
      o.value = val;
      profSel.appendChild(o);
    });
    profGrp.append(profLbl, profSel);

    const createBtn = el("button", "primary-btn", "Create & Load Agent");
    createBtn.type = "submit";
    form.append(fName.group, fApp.group, fIntake.group, profGrp, createBtn);

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const slug = fName.input.value.trim().toLowerCase().replace(/[^a-z0-9_-]+/g, "-");
      const useGcp = profSel.value === "google_gcp";
      const prov = useGcp ? "google_gcp" : "cymbal_stack";
      const comps = {};
      state.slotCatalog.forEach((s) => {
        comps[s.slot_id] = {
          slot_id: s.slot_id,
          provider: prov,
          enabled: true,
          enterprise_sync_enabled: true,
          parameters: {},
        };
      });
      const payload = {
        template_id: slug,
        name: slug,
        description: "Registered via Cymbal Platform Build console.",
        template_mode: useGcp ? "google_gcp" : "custom",
        origin: useGcp ? "google_gcp_standard" : "cymbal_baseline",
        agent_name: slug,
        app_id: fApp.input.value.trim(),
        intake_id: fIntake.input.value.trim(),
        business_unit: "core_cable",
        risk_tier: "AG2",
        onboarding_path: "Path C: Greenfield",
        runtime_cloud: "gcp",
        estimated_monthly_turns_millions: 3.5,
        uap_cel_per_tool_enforced: true,
        sdp_pii_mode: "DEIDENTIFY_INLINE",
        prompt_version: "v2",
        behavior_score: 96.4,
        components: comps,
      };
      try {
        const res = await apiPost("/api/agents/save", payload);
        state.templates = res.templates;
        state.workingTemplate = res.template;
        state.currentEvaluation = res.evaluation;
        dlg.close();
        renderHeaderAndRail();
        renderTenTileStrip();
        renderStageBody();
        showToast(`Created and selected '${slug}'.`);
      } catch (err) {
        showError(err.message);
      }
    });

    body.appendChild(form);
    dlg.showModal();
  }

  function openImportManifestModal() {
    const dlg = document.getElementById("agent-modal-dialog");
    const hd = document.getElementById("agent-modal-heading");
    const body = document.getElementById("agent-modal-body");
    if (!dlg || !body) return;
    if (hd) hd.textContent = "Import Agent Deployment Manifest (.yaml / .json)";
    body.replaceChildren();

    const form = el("form", "form-stack");
    const fileGrp = el("div", "field-group");
    const fileLbl = el("label", "", "Select Manifest File (.yaml, .yml, or .json, max 512 KB)");
    fileLbl.setAttribute("for", "manifest-file-input");
    const fileInp = el("input");
    fileInp.type = "file";
    fileInp.id = "manifest-file-input";
    fileInp.accept = ".yaml,.yml,.json";
    fileGrp.append(fileLbl, fileInp);

    const txtGrp = el("div", "field-group");
    const txtLbl = el("label", "", "Manifest Content");
    txtLbl.setAttribute("for", "manifest-text-area");
    const txtArea = el("textarea");
    txtArea.id = "manifest-text-area";
    txtArea.rows = 8;
    txtArea.required = true;
    txtArea.value = [
      "agent_name: order-fulfillment-specialist",
      "app_id: svc-cymbal-740",
      "intake_id: ''",
      "business_unit: core_cable",
      "risk_tier: AG3",
      "static_secrets_in_env: ['LEGACY_API_TOKEN']",
      "destructive_mcp_tools_exposed: true",
      "uap_cel_per_tool_enforced: false",
      "sdp_pii_mode: NONE",
      "behavior_score: 62.0",
      "components:",
      "  foundation_model: cymbal_stack",
      "  runtime_sandbox: cymbal_stack",
    ].join("\n");
    txtGrp.append(txtLbl, txtArea);

    let chosenFilename = "imported_agent.yaml";
    fileInp.addEventListener("change", async () => {
      const file = fileInp.files && fileInp.files[0];
      if (!file) return;
      chosenFilename = file.name;
      txtArea.value = await file.text();
    });

    const subBtn = el("button", "primary-btn", "Import & Inspect Manifest");
    subBtn.type = "submit";
    form.append(fileGrp, txtGrp, subBtn);

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        const res = await apiPost("/api/templates/upload", {
          filename: chosenFilename,
          content: txtArea.value,
        });
        const saved = await apiPost("/api/agents/save", res.template);
        state.templates = saved.templates;
        state.workingTemplate = saved.template;
        state.currentEvaluation = saved.evaluation;
        state.initialScoreBaseline = saved.evaluation.overall_score;
        dlg.close();
        renderHeaderAndRail();
        renderTenTileStrip();
        renderStageBody();
        showToast(
          `Imported '${state.workingTemplate.agent_name}' (Readiness score: ${state.currentEvaluation.overall_score.toFixed(
            1
          )}/100).`
        );
      } catch (err) {
        showError(err.message);
      }
    });

    body.appendChild(form);
    dlg.showModal();
  }

  function wireStaticControls() {
    document.querySelectorAll(".lifecycle-nav-btn").forEach((btn) => {
      btn.addEventListener("click", () => setStage(btn.dataset.stage));
    });

    window.addEventListener("popstate", () => {
      setStage(resolveInitialStageFromPath(), false);
    });

    document.querySelectorAll('input[name="template_mode"]').forEach((radio) => {
      radio.addEventListener("change", (e) => {
        if (e.target.checked) {
          handleTemplateProfileSwitch(e.target.value);
        }
      });
    });

    const cymBtn = document.getElementById("apply-cymbal-baseline-btn");
    if (cymBtn) cymBtn.addEventListener("click", () => applyCymbalBaselineAllSlots());

    const impBtn = document.getElementById("open-import-dialog-btn");
    if (impBtn) impBtn.addEventListener("click", () => openImportManifestModal());

    const expBtn = document.getElementById("export-manifest-btn");
    if (expBtn) expBtn.addEventListener("click", () => exportCurrentTemplateYaml());

    const pipeOpenBtn = document.getElementById("open-pipeline-drawer-btn");
    if (pipeOpenBtn) pipeOpenBtn.addEventListener("click", () => openPipelineDrawer());

    const closeDrawerBtn = document.getElementById("close-drawer-btn");
    if (closeDrawerBtn) closeDrawerBtn.addEventListener("click", () => closeDrawerModal());

    const drawerDlg = document.getElementById("right-inspector-drawer");
    if (drawerDlg) {
      drawerDlg.addEventListener("click", (e) => {
        const panel = drawerDlg.querySelector(".drawer-panel");
        if (panel && !panel.contains(e.target)) {
          closeDrawerModal();
        }
      });
      drawerDlg.addEventListener("close", () => {
        state.selectedSlotId = null;
        renderTenTileStrip();
        if (pipeOpenBtn) pipeOpenBtn.setAttribute("aria-expanded", "false");
      });
    }

    const inspTab = document.getElementById("drawer-tab-inspector");
    const pipeTab = document.getElementById("drawer-tab-pipeline");
    if (inspTab) inspTab.addEventListener("click", () => setDrawerTab("inspector"));
    if (pipeTab) pipeTab.addEventListener("click", () => setDrawerTab("pipeline"));

    const modalDlg = document.getElementById("agent-modal-dialog");
    const closeModalBtn = document.getElementById("close-agent-modal-btn");
    if (closeModalBtn && modalDlg) {
      closeModalBtn.addEventListener("click", () => modalDlg.close());
      modalDlg.addEventListener("click", (e) => {
        const panel = modalDlg.querySelector(".modal-panel");
        if (panel && !panel.contains(e.target)) {
          modalDlg.close();
        }
      });
    }

    const resetBtn = document.getElementById("reset-session-btn");
    if (resetBtn) {
      resetBtn.addEventListener("click", async () => {
        try {
          await apiPost("/api/session/reset", {});
        } finally {
          state.csrfToken = "";
          window.location.href = "/build";
        }
      });
    }
  }

  async function initConsole() {
    wireStaticControls();
    try {
      const boot = await apiGet("/api/bootstrap");
      state.csrfToken = boot.csrf_token;
      state.tenant = boot.tenant;
      state.slotCatalog = boot.slot_catalog || [];
      state.slotById = {};
      state.slotCatalog.forEach((s) => {
        state.slotById[s.slot_id] = s;
      });
      state.templates = boot.templates || [];
      state.rubric = boot.rubric;
      state.operationsMetrics = boot.operations_metrics;
      state.executiveCosts = boot.executive_costs;
      state.platformServices = boot.platform_services;
      state.agentState = boot.agent_state;
      state.walletState = boot.wallet_state;
      state.tcoReport = boot.tco_default;

      const envPill = document.getElementById("runtime-env-pill");
      if (envPill && boot.runtime_environment) {
        envPill.textContent = boot.runtime_environment.badge_label;
      }

      const cymBtn = document.getElementById("apply-cymbal-baseline-btn");
      if (cymBtn) {
        cymBtn.textContent = `${customerShortName()} Baseline`;
      }

      renderPipelineList();

      if (state.templates.length > 0) {
        state.workingTemplate = cloneJson(state.templates[0]);
        const evRes = await apiPost("/api/templates/evaluate", {
          template: state.workingTemplate,
        });
        state.currentEvaluation = evRes.evaluation;
        state.initialScoreBaseline = evRes.evaluation.overall_score;
      }

      setStage(resolveInitialStageFromPath(), false);
    } catch (err) {
      showError(`Console initialization error: ${err.message}`);
    }
  }

  document.addEventListener("DOMContentLoaded", initConsole);
})();
