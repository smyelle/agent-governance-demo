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
    google_gcp_standard: "Google Cloud",
    cymbal_baseline: "Custom",
    custom_hybrid: "Custom",
    imported_manifest: "Imported Manifest",
  };

  const NUMERIC_FILTER_RE = /^(>=|<=|>|<|=)\s*(-?\d+(?:\.\d+)?)$/;

  const state = {
    csrfToken: "",
    offlineMode: false,
    liveCloudAvailable: false,
    architectureMode: "enterprise_hybrid",
    tenant: null,
    candidates: [],
    slotCatalog: [],
    slotById: {},
    templates: [],
    starterTemplates: [],
    aiglPhaseSpecs: [],
    caasRiskDomains: [],
    caas49Factors: [],
    phase5ReviewerRoles: [],
    recertificationRecords: [],
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
    selectedGovernFleetSub: "adoption",
    selectedGovernFinopsSub: "attribution",
    selectedGovernControlsSub: "killswitch",
    selectedSlotId: "identity_access",
    selectedEvalSlotId: null,
    selectedDeploySection: "approval",
    expandedAgentId: null,
    expandedEvalAgentId: null,
    expandedDeployAgentId: null,
    expandedDeploymentId: null,
    expandedFinopsSlotId: null,
    expandedGovernRuleId: null,
    expandedAdoptSlotId: null,
    expandedRecertAgentId: null,
    buildPagination: { page: 1, pageSize: 10 },
    evalPagination: { page: 1, pageSize: 10 },
    deployPagination: { page: 1, pageSize: 10 },
    governFleetPagination: { page: 1, pageSize: 10 },
    governFinopsPagination: { page: 1, pageSize: 10 },
    tableControls: {},
    pendingFocusRestore: null,
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

  function formatElapsedSeconds(ms) {
    return `${(Number(ms || 0) / 1000).toFixed(1)}s`;
  }

  function announcePolite(msg) {
    const box = document.getElementById("polite-announcer");
    if (box) {
      box.textContent = msg;
    }
  }

  function showNotice(msg) {
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

  function formatApiErrorDetail(body, status) {
    const fallback = `Request failed (${status})`;
    if (!body || body.detail === undefined || body.detail === null) {
      return fallback;
    }
    if (typeof body.detail === "string") {
      return body.detail || fallback;
    }
    if (Array.isArray(body.detail)) {
      const parts = body.detail.map((item) => {
        if (typeof item === "string") return item;
        if (item && typeof item === "object") {
          const loc = Array.isArray(item.loc) ? item.loc.slice(1).join(".") : "";
          const msg = item.msg || JSON.stringify(item);
          return loc ? `${loc}: ${msg}` : msg;
        }
        return String(item);
      });
      return parts.filter(Boolean).join("; ") || fallback;
    }
    if (typeof body.detail === "object") {
      return body.detail.message || JSON.stringify(body.detail);
    }
    return String(body.detail);
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
    }
    if (!resp.ok) {
      throw new Error(formatApiErrorDetail(body, resp.status));
    }
    return body;
  }

  async function apiPostStream(path, payload, onStep) {
    const resp = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/x-ndjson, application/json",
        "X-CSRF-Token": state.csrfToken,
      },
      body: JSON.stringify({ ...(payload || {}), stream: true }),
    });
    const contentType = (resp.headers.get("content-type") || "").toLowerCase();
    if (!resp.ok) {
      const errBody = await resp.json().catch(() => ({}));
      if (errBody && errBody.platform_services) {
        state.platformServices = errBody.platform_services;
      }
      throw new Error(formatApiErrorDetail(errBody, resp.status));
    }
    if (!contentType.includes("application/x-ndjson") || !resp.body || !resp.body.getReader) {
      const body = await resp.json().catch(() => ({}));
      if (body && body.platform_services) {
        state.platformServices = body.platform_services;
      }
      return body;
    }

    const reader = resp.body.getReader();
    const decoder = new TextDecoder("utf-8");
    let buffer = "";
    let finalPayload = null;

    const handleLine = (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      const evt = JSON.parse(trimmed);
      if (evt.type === "step") {
        if (typeof onStep === "function") {
          onStep(evt);
        }
      } else if (evt.type === "result") {
        finalPayload = evt.payload || evt;
        if (finalPayload && finalPayload.platform_services) {
          state.platformServices = finalPayload.platform_services;
        }
      } else if (evt.type === "error") {
        throw new Error(evt.detail || evt.message || "Streaming execution failed");
      }
    };

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() || "";
      for (const line of lines) {
        handleLine(line);
      }
    }
    const tail = buffer + decoder.decode();
    if (tail.trim()) {
      for (const line of tail.split("\n")) {
        handleLine(line);
      }
    }
    if (!finalPayload) {
      throw new Error("Stream ended without a final result payload.");
    }
    return finalPayload;
  }

  async function runWithLiveStepper(containerEl, { title, totalSteps, runnerFn }) {
    if (!containerEl) {
      return runnerFn(() => {});
    }
    containerEl.hidden = false;
    containerEl.replaceChildren();

    const header = el("div", "stream-progress-header");
    const titleEl = el("strong", "", title);
    const timerEl = el("span", "expander-choice-pill", "0.0s");
    header.append(titleEl, timerEl);

    const statusEl = el("p", "field-hint", "Initializing live execution stream...");
    const meter = el("progress", "meter-bar");
    meter.max = totalSteps || 1;
    meter.value = 0;

    const stepsList = el("ul", "stream-steps-list");
    containerEl.append(header, statusEl, meter, stepsList);

    const tStart = performance.now();
    const timerId = window.setInterval(() => {
      timerEl.textContent = formatElapsedSeconds(performance.now() - tStart);
    }, 100);

    try {
      const result = await runnerFn((evt) => {
        const stepNum = Number(evt.step || 0);
        const tot = Number(evt.total_steps || totalSteps || 1);
        meter.max = tot;
        meter.value = Math.min(tot, stepNum);
        const stepElapsed = evt.elapsed_ms ? formatElapsedSeconds(evt.elapsed_ms) : formatElapsedSeconds(performance.now() - tStart);
        statusEl.textContent = `[Step ${stepNum}/${tot}] ${evt.status || "Running"} - ${evt.detail || ""} (${stepElapsed})`;
        const item = el(
          "li",
          "stream-step-item",
          `[${stepNum}/${tot}] ${evt.status || "Step"} (${stepElapsed}): ${evt.detail || ""}`
        );
        stepsList.appendChild(item);
      });
      meter.value = meter.max;
      const finalSec = formatElapsedSeconds(performance.now() - tStart);
      timerEl.textContent = `${finalSec} (Done)`;
      statusEl.textContent = `Completed in ${finalSec}.`;
      return result;
    } catch (err) {
      const failSec = formatElapsedSeconds(performance.now() - tStart);
      timerEl.textContent = `${failSec} (Error)`;
      statusEl.textContent = `Failed after ${failSec}: ${err.message}`;
      throw err;
    } finally {
      window.clearInterval(timerId);
    }
  }

  function tenantTerm(key, fallback = "") {
    return (
      (state.tenant && state.tenant.terminology && state.tenant.terminology[key]) ||
      fallback
    );
  }

  function tenantDefault(key, fallback = "") {
    return (
      (state.tenant &&
        state.tenant.governance_defaults &&
        state.tenant.governance_defaults[key]) ||
      fallback
    );
  }

  function customerShortName() {
    return tenantTerm("customer_provider_short", "Third-Party / OSS");
  }

  function gcpShortName() {
    return tenantTerm("gcp_provider_short", "Google Cloud");
  }

  function buLabel(buKey) {
    const map =
      (state.tenant && state.tenant.terminology && state.tenant.terminology.business_units) || {};
    return map[buKey] || buKey;
  }

  function cloneJson(obj) {
    return JSON.parse(JSON.stringify(obj));
  }

  function resolveReleaseStateLabel(item) {
    if (item.lifecycle_status === "DEPLOYED") {
      return "Deployed";
    }
    return item.gate_passed ? "Ready to Deploy" : "Gate Blocked";
  }

  function resolveGateVerdictLabel(item) {
    return item.gate_passed ? "Ready" : "Remediation Needed";
  }

  /* =========================================================================
   * Universal Per-Column Table Sort & Inline Filter Engine
   * ========================================================================= */
  function ensureTableState(tableKey, defaultSortCol, defaultSortDir = "desc") {
    if (!state.tableControls[tableKey]) {
      state.tableControls[tableKey] = {
        sortCol: defaultSortCol || "",
        sortDir: defaultSortDir,
        filters: {},
      };
    }
    return state.tableControls[tableKey];
  }

  function clearTableFilters(tableKey, paginationState) {
    const ctrl = state.tableControls[tableKey];
    if (ctrl) {
      ctrl.filters = {};
    }
    if (paginationState) {
      paginationState.page = 1;
    }
  }

  function countActiveTableFilters(tableKey) {
    const ctrl = state.tableControls[tableKey];
    if (!ctrl || !ctrl.filters) return 0;
    return Object.values(ctrl.filters).filter((v) => String(v || "").trim() !== "").length;
  }

  function matchesColumnFilter(rawVal, displayStr, filterQuery, colType, filterType) {
    const q = String(filterQuery || "").trim();
    if (!q) return true;
    if (filterType === "select") {
      return String(rawVal ?? "") === q;
    }
    if (colType === "number") {
      const m = NUMERIC_FILTER_RE.exec(q);
      if (m) {
        const op = m[1];
        const target = Number(m[2]);
        const numVal = Number(rawVal ?? 0);
        if (op === ">=") return numVal >= target;
        if (op === "<=") return numVal <= target;
        if (op === ">") return numVal > target;
        if (op === "<") return numVal < target;
        if (op === "=") return numVal === target;
      }
    }
    const hay = `${String(rawVal ?? "")} ${String(displayStr ?? "")}`.toLowerCase();
    return hay.includes(q.toLowerCase());
  }

  function applyTableSortAndFilters(rows, columns, tableKey, defaultSortCol, defaultSortDir = "desc") {
    const ctrl = ensureTableState(tableKey, defaultSortCol, defaultSortDir);
    const colByKey = {};
    columns.forEach((c) => {
      colByKey[c.key] = c;
    });

    const filtered = rows.filter((row) =>
      columns.every((col) => {
        const fVal = ctrl.filters[col.key];
        if (!fVal || String(fVal).trim() === "") return true;
        const rawV = col.getFilterValue
          ? col.getFilterValue(row)
          : col.getValue
          ? col.getValue(row)
          : row[col.key];
        const dispV = col.getFilterText ? col.getFilterText(row) : rawV;
        return matchesColumnFilter(rawV, dispV, fVal, col.type || "string", col.filterType || "text");
      })
    );

    const sortColObj = colByKey[ctrl.sortCol];
    if (!sortColObj) {
      return filtered;
    }
    const mult = ctrl.sortDir === "asc" ? 1 : -1;
    const cType = sortColObj.type || "string";

    return [...filtered].sort((a, b) => {
      const va = sortColObj.getValue ? sortColObj.getValue(a) : a[sortColObj.key];
      const vb = sortColObj.getValue ? sortColObj.getValue(b) : b[sortColObj.key];
      if (cType === "number") {
        const na = Number(va ?? 0);
        const nb = Number(vb ?? 0);
        if (na === nb) return 0;
        return (na < nb ? -1 : 1) * mult;
      }
      const sa = String(va ?? "");
      const sb = String(vb ?? "");
      return sa.localeCompare(sb, undefined, { numeric: true, sensitivity: "base" }) * mult;
    });
  }

  function buildInteractiveTableHead({
    tableKey,
    columns,
    allRows,
    defaultSortCol,
    defaultSortDir = "desc",
    paginationState,
  }) {
    const ctrl = ensureTableState(tableKey, defaultSortCol, defaultSortDir);
    const thead = el("thead");
    const sortRow = el("tr");
    const filterRow = el("tr", "table-filter-row");

    columns.forEach((col) => {
      const th = el("th");
      th.scope = "col";
      const isSorted = ctrl.sortCol === col.key;
      th.setAttribute(
        "aria-sort",
        isSorted ? (ctrl.sortDir === "asc" ? "ascending" : "descending") : "none"
      );

      const sortBtn = el("button", "th-sort-btn");
      sortBtn.type = "button";
      sortBtn.appendChild(el("span", "", col.label));
      const arrow = isSorted ? (ctrl.sortDir === "asc" ? "\u2191" : "\u2193") : "\u2195";
      const ind = el("span", "sort-indicator", arrow);
      ind.setAttribute("aria-hidden", "true");
      sortBtn.appendChild(ind);

      sortBtn.addEventListener("click", () => {
        if (ctrl.sortCol === col.key) {
          ctrl.sortDir = ctrl.sortDir === "asc" ? "desc" : "asc";
        } else {
          ctrl.sortCol = col.key;
          ctrl.sortDir = col.type === "number" || col.type === "date" ? "desc" : "asc";
        }
        if (paginationState) {
          paginationState.page = 1;
        }
        renderStageBody();
      });
      th.appendChild(sortBtn);
      sortRow.appendChild(th);

      const fTh = el("th");
      const filterId = `tbl-flt-${tableKey}-${col.key}`;
      const srLbl = el("label", "visually-hidden", `Filter ${col.label}`);
      srLbl.setAttribute("for", filterId);
      fTh.appendChild(srLbl);

      if (col.filterType === "select") {
        const sel = el("select", "col-filter-select");
        sel.id = filterId;
        const allOpt = el("option", "", "All");
        allOpt.value = "";
        sel.appendChild(allOpt);

        let opts = col.options;
        if (!opts) {
          const uniq = Array.from(
            new Set(
              (allRows || [])
                .map((r) => String((col.getValue ? col.getValue(r) : r[col.key]) ?? ""))
                .filter((v) => v !== "")
            )
          ).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
          opts = uniq.map((v) => [v, v]);
        }
        const curVal = String(ctrl.filters[col.key] || "");
        opts.forEach(([val, txt]) => {
          const o = el("option", "", txt);
          o.value = String(val);
          if (curVal === String(val)) {
            o.selected = true;
          }
          sel.appendChild(o);
        });
        sel.addEventListener("change", () => {
          ctrl.filters[col.key] = sel.value;
          if (paginationState) {
            paginationState.page = 1;
          }
          renderStageBody();
        });
        fTh.appendChild(sel);
      } else {
        const inp = el("input", "col-filter-input");
        inp.type = "search";
        inp.id = filterId;
        inp.placeholder = col.type === "number" ? "Filter or >=..." : "Filter...";
        inp.value = String(ctrl.filters[col.key] || "");
        inp.addEventListener("input", () => {
          ctrl.filters[col.key] = inp.value;
          if (paginationState) {
            paginationState.page = 1;
          }
          state.pendingFocusRestore = {
            id: filterId,
            start: inp.selectionStart ?? inp.value.length,
            end: inp.selectionEnd ?? inp.value.length,
          };
          renderStageBody();
        });
        fTh.appendChild(inp);
      }
      filterRow.appendChild(fTh);
    });

    thead.append(sortRow, filterRow);
    return thead;
  }

  function buildActiveFiltersBanner(tableKey, filteredCount, totalCount, paginationState) {
    const activeCnt = countActiveTableFilters(tableKey);
    if (activeCnt === 0) return null;
    const bar = el("div", "table-active-filters-bar");
    bar.appendChild(
      el(
        "span",
        "",
        `${activeCnt} column filter(s) active - matching ${filteredCount} of ${totalCount} rows`
      )
    );
    const clearBtn = el("button", "secondary-btn sm-btn", "Clear Column Filters");
    clearBtn.type = "button";
    clearBtn.addEventListener("click", () => {
      clearTableFilters(tableKey, paginationState);
      renderStageBody();
    });
    bar.appendChild(clearBtn);
    return bar;
  }

  function resolveInitialStageFromPath() {
    const p = window.location.pathname.toLowerCase();
    if (p.startsWith("/evaluate")) return "evaluate";
    if (p.startsWith("/deploy")) return "deploy";
    if (
      p.startsWith("/govern") ||
      p.startsWith("/governance-ops") ||
      p.startsWith("/executive")
    ) {
      return "govern";
    }
    return "build";
  }

  function setStage(stage, pushHistory = true) {
    const nextStage = STAGE_TITLES[stage] ? stage : "build";
    state.activeStage = nextStage;
    clearBanners();

    const brand = tenantTerm(
      "platform_title",
      tenantTerm("sidebar_brand", "Cymbal Agent Governance Platform")
    );
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

    renderHeaderAndBrand();
    renderStageBody();
  }

  function jumpToAgentOnStage(targetStage, templateId) {
    const pagMap = {
      build: { pag: state.buildPagination, tableKey: "build-agents", defaultCol: "updated_at" },
      evaluate: { pag: state.evalPagination, tableKey: "eval-agents", defaultCol: "updated_at" },
      deploy: { pag: state.deployPagination, tableKey: "deploy-agents", defaultCol: "updated_at" },
    };
    const cfg = pagMap[targetStage];
    if (cfg) {
      clearTableFilters(cfg.tableKey, cfg.pag);
      ensureTableState(cfg.tableKey, cfg.defaultCol, "desc");
      state.tableControls[cfg.tableKey].sortCol = cfg.defaultCol;
      state.tableControls[cfg.tableKey].sortDir = "desc";
      const sorted = [...state.templates].sort((a, b) =>
        String(b.updated_at || "").localeCompare(String(a.updated_at || ""))
      );
      const idx = sorted.findIndex((t) => t.template_id === templateId);
      if (idx >= 0) {
        cfg.pag.page = Math.floor(idx / cfg.pag.pageSize) + 1;
      }
    }
    if (targetStage === "build") {
      state.expandedAgentId = templateId;
    } else if (targetStage === "evaluate") {
      state.expandedEvalAgentId = templateId;
    } else if (targetStage === "deploy") {
      state.expandedDeployAgentId = templateId;
    }
    setStage(targetStage);
  }

  function syncOfflineModeControl() {
    const chk = document.getElementById("offline-demo-toggle");
    const badge = document.getElementById("topbar-runtime-badge");
    const tierBadge = document.getElementById("topbar-tier-badge");
    if (chk) {
      chk.checked = Boolean(state.offlineMode);
      const lockedOffline = state.offlineMode && !state.liveCloudAvailable;
      chk.disabled = lockedOffline;
      chk.title = lockedOffline
        ? "Live Vertex AI credentials are not active on this server instance."
        : "Toggle between Live Vertex AI (gemini-3.8-flash) and Offline Demo Fallback.";
    }
    if (badge) {
      badge.className = state.offlineMode ? "status-badge status-warn" : "status-badge status-ok";
      badge.textContent = state.offlineMode
        ? "Offline Demo Fallback"
        : "Live Vertex AI (gemini-3.8-flash)";
    }
    if (tierBadge) {
      tierBadge.textContent =
        state.architectureMode === "google_native"
          ? "Google-Native Paved Path"
          : "4-Tier Coexistence";
    }
  }

  function renderHeaderAndBrand() {
    const terms = (state.tenant && state.tenant.terminology) || {};
    const fullBrand = terms.sidebar_brand || "Cymbal Agent Governance Platform";
    const wordEl = document.getElementById("sidebar-brand-wordmark");
    if (wordEl) {
      wordEl.textContent = terms.brand_wordmark || "Cymbal";
    }
    const subEl = document.getElementById("sidebar-brand-subtitle");
    if (subEl) {
      subEl.textContent =
        terms.brand_subtitle ||
        (fullBrand.toLowerCase().startsWith("cymbal ")
          ? fullBrand.slice(7)
          : "Agent Governance Platform");
    }
    const topLabel = document.getElementById("topbar-platform-label");
    if (topLabel) {
      topLabel.textContent =
        terms.platform_title || terms.platform_name || "Cymbal Agent Governance Platform";
    }
    const footBrand = document.getElementById("workspace-footer-brand");
    if (footBrand) {
      footBrand.textContent = `${
        terms.platform_title || terms.platform_name || "Cymbal Agent Governance Platform"
      } (Apache-2.0) | Foundation Model Standard: gemini-3.8-flash`;
    }
    const footDisc = document.getElementById("workspace-footer-disclaimer");
    if (footDisc && terms.tco_framing_note) {
      footDisc.textContent = `${terms.tco_framing_note}. Cost figures represent non-binding engineering capacity models.`;
    }
    syncOfflineModeControl();
  }

  /* Sync highlight between 10 horizontal blocks and 10 nested expanders */
  function syncHorizontalTilesWithOpenExpander(panelRoot, slotStateField = "selectedSlotId") {
    if (!panelRoot) return;
    const openDet = panelRoot.querySelector("details.component-expander[open]");
    const openSid = openDet ? openDet.dataset.slotId : null;
    state[slotStateField] = openSid;
    panelRoot.querySelectorAll(".component-tile").forEach((btn) => {
      const active = Boolean(openSid && btn.dataset.slotId === openSid);
      btn.classList.toggle("is-selected", active);
      btn.setAttribute("aria-pressed", active ? "true" : "false");
    });
  }

  /* Inline 10 Horizontal Functional Blocks (Build & Evaluate Expanded Rows) */
  function buildInstanceTenTileStrip(tpl, panelRoot, evalObj = null, slotStateField = "selectedSlotId") {
    const wrapper = el("div", "instance-blocks-section");
    const list = el("ul", "ten-tile-strip");
    list.setAttribute("role", "list");
    const slotStatuses = (evalObj && evalObj.slot_statuses) || {};

    state.slotCatalog.forEach((spec) => {
      const sid = spec.slot_id;
      const comp = (tpl.components && tpl.components[sid]) || {
        slot_id: sid,
        provider: "unconfigured",
        enabled: false,
      };
      const prov = comp.enabled === false ? "unconfigured" : comp.provider;
      const implLabel = (spec.provider_labels && spec.provider_labels[prov]) || "Not Configured";

      const li = el("li", "tile-list-item");
      const btn = el("button", "component-tile");
      btn.type = "button";
      btn.dataset.slotId = sid;
      const isSelected = state[slotStateField] === sid;
      if (isSelected) {
        btn.classList.add("is-selected");
      }
      btn.setAttribute("aria-pressed", isSelected ? "true" : "false");

      if (evalObj) {
        const st = slotStatuses[sid] || "PASSED";
        if (st === "FAILED") {
          btn.classList.add("tile-status-failed");
        } else if (st === "ADVISORY") {
          btn.classList.add("tile-status-advisory");
        } else {
          btn.classList.add("tile-status-passed", "eval-highlight");
        }
      }

      const topHeader = el("span", "tile-top-header");
      if (evalObj) {
        const st = slotStatuses[sid] || "PASSED";
        const sym = st === "FAILED" ? "[!]" : st === "ADVISORY" ? "[~]" : "[OK]";
        topHeader.appendChild(el("span", "tile-eval-marker", sym));
      }
      topHeader.appendChild(el("span", "tile-functional-name", spec.functional_name));
      const subSpan = el("span", "tile-impl-caption", implLabel);
      btn.append(topHeader, subSpan);

      btn.addEventListener("click", () => {
        const targetDet =
          panelRoot &&
          panelRoot.querySelector(`details.component-expander[data-slot-id="${sid}"]`);
        if (targetDet) {
          const willOpen = !targetDet.open;
          if (willOpen) {
            panelRoot.querySelectorAll("details.component-expander[open]").forEach((other) => {
              if (other !== targetDet) {
                other.open = false;
              }
            });
            targetDet.open = true;
            state[slotStateField] = sid;
            targetDet.scrollIntoView({ behavior: "smooth", block: "nearest" });
          } else {
            targetDet.open = false;
            state[slotStateField] = null;
          }
          syncHorizontalTilesWithOpenExpander(panelRoot, slotStateField);
        } else {
          state[slotStateField] = sid;
          renderStageBody();
        }
      });
      li.appendChild(btn);
      list.appendChild(li);
    });

    wrapper.appendChild(list);
    return wrapper;
  }

  /* Accessible Pagination Bar (10 / 25 / 50 rows per page) */
  function buildPaginationControls({ totalItems, paginationState, navLabel, idPrefix }) {
    const totalPages = Math.max(1, Math.ceil(totalItems / paginationState.pageSize));
    if (paginationState.page > totalPages) {
      paginationState.page = totalPages;
    }
    if (paginationState.page < 1) {
      paginationState.page = 1;
    }
    const startIdx = totalItems === 0 ? 0 : (paginationState.page - 1) * paginationState.pageSize + 1;
    const endIdx = Math.min(totalItems, paginationState.page * paginationState.pageSize);

    const nav = el("nav", "pagination-bar");
    nav.setAttribute("aria-label", navLabel);

    const meta = el("div", "pagination-meta");
    meta.appendChild(el("span", "", `Showing ${startIdx}-${endIdx} of ${totalItems} rows`));

    const sizeId = `${idPrefix}-rows-per-page`;
    const sizeLbl = el("label", "", "Rows per page");
    sizeLbl.setAttribute("for", sizeId);
    const sizeSel = el("select", "inline-select");
    sizeSel.id = sizeId;
    [10, 25, 50].forEach((sz) => {
      const o = el("option", "", String(sz));
      o.value = String(sz);
      if (paginationState.pageSize === sz) o.selected = true;
      sizeSel.appendChild(o);
    });
    sizeSel.addEventListener("change", () => {
      paginationState.pageSize = Number(sizeSel.value || 10);
      paginationState.page = 1;
      renderStageBody();
    });
    meta.append(sizeLbl, sizeSel);

    const controls = el("div", "pagination-controls");
    const prevBtn = el("button", "page-btn", "Previous");
    prevBtn.type = "button";
    prevBtn.disabled = paginationState.page <= 1;
    prevBtn.addEventListener("click", () => {
      if (paginationState.page > 1) {
        paginationState.page -= 1;
        renderStageBody();
      }
    });
    controls.appendChild(prevBtn);

    for (let p = 1; p <= totalPages; p += 1) {
      const pBtn = el("button", "page-btn", String(p));
      pBtn.type = "button";
      pBtn.setAttribute("aria-label", `Page ${p}`);
      if (p === paginationState.page) {
        pBtn.setAttribute("aria-current", "page");
      }
      pBtn.addEventListener("click", () => {
        paginationState.page = p;
        renderStageBody();
      });
      controls.appendChild(pBtn);
    }

    const nextBtn = el("button", "page-btn", "Next");
    nextBtn.type = "button";
    nextBtn.disabled = paginationState.page >= totalPages;
    nextBtn.addEventListener("click", () => {
      if (paginationState.page < totalPages) {
        paginationState.page += 1;
        renderStageBody();
      }
    });
    controls.appendChild(nextBtn);

    nav.append(meta, controls);
    return nav;
  }

  async function refreshEvaluation(reRenderStage = true) {
    if (!state.workingTemplate) return;
    try {
      const res = await apiPost("/api/templates/evaluate", {
        template: state.workingTemplate,
      });
      state.currentEvaluation = res.evaluation;
      syncWorkingTemplateIntoList();
      renderHeaderAndBrand();
      if (reRenderStage) {
        renderStageBody();
      }
    } catch (err) {
      showError(err.message);
    }
  }

  function syncWorkingTemplateIntoList() {
    if (!state.workingTemplate) return;
    const idx = state.templates.findIndex(
      (t) => t.template_id === state.workingTemplate.template_id
    );
    if (idx >= 0) {
      const merged = cloneJson(state.templates[idx]);
      Object.assign(merged, cloneJson(state.workingTemplate));
      merged.business_unit_label = buLabel(merged.business_unit);
      if (state.currentEvaluation) {
        const ev = state.currentEvaluation;
        merged.latest_eval_score = ev.overall_score;
        merged.passing_threshold = ev.passing_threshold;
        merged.gate_passed = ev.gate_passed;
        merged.gate_verdict = ev.gate_verdict;
        merged.mandatory_failures_count = ev.mandatory_failures_count;
        merged.recommendations_count = ev.recommendations_count;
        if (ev.cost_estimate) {
          merged.monthly_run_rate_usd = ev.cost_estimate.monthly_run_rate_usd;
          merged.onboarding_eval_cost_usd = ev.cost_estimate.onboarding_eval_cost_usd;
          merged.monthly_savings_usd = ev.cost_estimate.monthly_savings_usd;
          merged.historical_cumulative_usd = ev.cost_estimate.historical_cumulative_usd;
          merged.component_costs = ev.cost_estimate.component_costs;
        }
      }
      state.templates[idx] = merged;
    }
  }

  async function ensureWorkingTemplateLoaded(item) {
    if (!state.workingTemplate || state.workingTemplate.template_id !== item.template_id) {
      state.workingTemplate = cloneJson(item);
      const res = await apiPost("/api/templates/evaluate", {
        template: state.workingTemplate,
      });
      state.currentEvaluation = res.evaluation;
      state.initialScoreBaseline = res.evaluation.overall_score;
      syncWorkingTemplateIntoList();
    } else if (!state.currentEvaluation) {
      const res = await apiPost("/api/templates/evaluate", {
        template: state.workingTemplate,
      });
      state.currentEvaluation = res.evaluation;
      syncWorkingTemplateIntoList();
    }
  }

  async function toggleAgentRowExpansion(item, expandStateField = "expandedAgentId") {
    clearBanners();
    const isSameExpanded = state[expandStateField] === item.template_id;
    if (isSameExpanded) {
      state[expandStateField] = null;
      renderStageBody();
      return;
    }

    await ensureWorkingTemplateLoaded(item);
    state[expandStateField] = item.template_id;

    if (expandStateField === "expandedAgentId") {
      if (!state.selectedSlotId && state.slotCatalog.length > 0) {
        state.selectedSlotId = state.slotCatalog[0].slot_id;
      }
    } else if (expandStateField === "expandedEvalAgentId" && state.currentEvaluation) {
      const firstFail = (state.currentEvaluation.rule_results || []).find(
        (r) => r.status === "FAILED"
      );
      state.selectedEvalSlotId = firstFail
        ? firstFail.slot_id
        : state.slotCatalog[0]
        ? state.slotCatalog[0].slot_id
        : null;
    } else if (expandStateField === "expandedDeployAgentId") {
      state.selectedDeploySection = "approval";
    }

    renderHeaderAndBrand();
    renderStageBody();
  }

  function resolveTemplatePresetKey(tpl) {
    if (!tpl) return "custom";
    return tpl.template_mode === "google_gcp" ? "google_gcp" : "custom";
  }

  async function applyInstanceTemplatePreset(preset) {
    if (!state.workingTemplate) return;
    if (preset === "google_gcp") {
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
      await refreshEvaluation(true);
    } else {
      state.workingTemplate.template_mode = "custom";
      if (state.workingTemplate.origin === "google_gcp_standard") {
        state.workingTemplate.origin = "custom_hybrid";
      }
      if (!state.selectedSlotId && state.slotCatalog.length > 0) {
        state.selectedSlotId = state.slotCatalog[0].slot_id;
      }
      syncWorkingTemplateIntoList();
      renderHeaderAndBrand();
      renderStageBody();
    }
  }

  async function saveCurrentTemplate() {
    if (!state.workingTemplate) return;
    try {
      const res = await apiPost("/api/agents/save", state.workingTemplate);
      state.workingTemplate = res.template;
      state.templates = res.templates;
      state.currentEvaluation = res.evaluation;
      state.buildPagination.page = 1;
      state.expandedAgentId = state.workingTemplate.template_id;
      renderHeaderAndBrand();
      renderStageBody();
      showNotice(`Saved changes to '${state.workingTemplate.agent_name}'.`);
    } catch (err) {
      showError(err.message);
    }
  }

  async function exportCurrentTemplateYaml() {
    if (!state.workingTemplate) return;
    const t = state.workingTemplate;
    let yamlContent = "";
    let downloadName = `${t.agent_name || t.template_id || "agent-template"}.local.yaml`;
    try {
      const res = await apiPost("/api/templates/export-yaml", { template: t });
      yamlContent = res.yaml_content || "";
      if (res.filename) {
        downloadName = res.filename;
      }
    } catch (_) {
      const lines = [
        `template_id: "${t.template_id}"`,
        `agent_name: "${t.agent_name}"`,
        `app_id: "${t.app_id}"`,
        `intake_id: "${t.intake_id || ""}"`,
        `business_unit: "${t.business_unit}"`,
        `risk_tier: "${t.risk_tier}"`,
        `aegis_risk_level: "${t.aegis_risk_level || "R2"}"`,
        `aigl_phase: ${Number(t.aigl_phase || 1)}`,
        `caas_risk_level: "${t.caas_risk_level || "Level 1"}"`,
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
        lines.push(`  ${spec.slot_id}:`);
        lines.push(`    provider: "${c.provider}"`);
        lines.push(`    enabled: ${c.enabled !== false}`);
        lines.push(`    enterprise_sync_enabled: ${c.enterprise_sync_enabled !== false}`);
      });
      yamlContent = lines.join("\n") + "\n";
    }
    const blob = new Blob([yamlContent], { type: "text/yaml;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = downloadName;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    showNotice(`Exported canonical YAML manifest '${downloadName}'.`);
  }

  /* Shared Per-Slot Component Radio & Policy Controls (Zero Dropdown) */
  function populateSlotConfigurationBody(
    container,
    spec,
    tpl,
    radioGroupPrefix,
    slotStateField = "selectedSlotId"
  ) {
    const terms = (state.tenant && state.tenant.terminology) || {};
    const tcoOverrides = (terms.slot_tco_overrides && terms.slot_tco_overrides[spec.slot_id]) || {};
    container.appendChild(
      el("span", "status-badge status-ok", `${spec.pillar} Pillar | ${spec.workstream}`)
    );
    container.appendChild(
      el("p", "field-hint", `API Surface: ${spec.api_surface} | Consolidates: ${spec.consolidates}`)
    );

    const comp = (tpl.components && tpl.components[spec.slot_id]) || {
      slot_id: spec.slot_id,
      provider: "unconfigured",
      enabled: false,
      enterprise_sync_enabled: true,
    };
    const curProv = comp.enabled === false ? "unconfigured" : comp.provider;
    const lockedGcp = tpl.template_mode === "google_gcp";

    if (lockedGcp) {
      const lockBar = el("div", "toolbar-row");
      lockBar.appendChild(
        el(
          "span",
          "field-hint",
          "Google Cloud preset is active (all 10 components locked to Google Cloud)."
        )
      );
      const unlockBtn = el("button", "secondary-btn sm-btn", "Switch to Custom");
      unlockBtn.type = "button";
      unlockBtn.addEventListener("click", () => {
        state[slotStateField] = spec.slot_id;
        applyInstanceTemplatePreset("custom");
      });
      lockBar.appendChild(unlockBtn);
      container.appendChild(lockBar);
    }

    const fs = el("fieldset", "radio-card-list");
    fs.disabled = lockedGcp;
    fs.appendChild(
      el("legend", "visually-hidden", `Choose implementation for ${spec.functional_name}`)
    );

    const turns = Number(tpl.estimated_monthly_turns_millions || 3.5);
    const syncSlots = new Set(["identity_access", "agent_registry", "observability_tracing"]);
    [
      ["cymbal_stack", spec.cymbal_name],
      ["google_gcp", spec.gcp_name],
    ].forEach(([provKey, compTitle]) => {
      const baseRates = spec.pricing[provKey];
      const ov = tcoOverrides[provKey] || {};
      const infraMo = Number(
        ov.infra_monthly_usd !== undefined && ov.infra_monthly_usd !== null
          ? ov.infra_monthly_usd
          : baseRates.infra_monthly_usd !== undefined
          ? baseRates.infra_monthly_usd
          : baseRates.base_monthly_usd
      );
      const maintMo = Number(
        ov.maintenance_monthly_usd !== undefined && ov.maintenance_monthly_usd !== null
          ? ov.maintenance_monthly_usd
          : baseRates.maintenance_monthly_usd || 0
      );
      const per1m = Number(
        ov.per_1m_turns_usd !== undefined && ov.per_1m_turns_usd !== null
          ? ov.per_1m_turns_usd
          : baseRates.per_1m_turns_usd
      );
      const onboard = Number(
        ov.onboarding_usd !== undefined && ov.onboarding_usd !== null
          ? ov.onboarding_usd
          : baseRates.onboarding_usd
      );
      const syncBridge =
        provKey === "google_gcp" && syncSlots.has(spec.slot_id) && comp.enterprise_sync_enabled !== false
          ? 15.0
          : 0.0;
      const monthly = infraMo + maintMo + syncBridge + per1m * turns;
      const isChecked = curProv === provKey;
      const lbl = el(
        "label",
        isChecked ? "radio-card-option is-checked" : "radio-card-option"
      );
      const rad = el("input");
      rad.type = "radio";
      rad.name = `${radioGroupPrefix}_${tpl.template_id}_${spec.slot_id}`;
      rad.value = provKey;
      rad.checked = isChecked;

      rad.addEventListener("change", async () => {
        if (!rad.checked) return;
        state[slotStateField] = spec.slot_id;
        tpl.template_mode = "custom";
        tpl.origin = "custom_hybrid";
        const keepSync = comp.enterprise_sync_enabled !== false;
        tpl.components[spec.slot_id] = {
          slot_id: spec.slot_id,
          provider: provKey,
          enabled: true,
          enterprise_sync_enabled: keepSync,
          parameters: {},
        };
        await refreshEvaluation(true);
      });

      const textCol = el("div", "field-group");
      textCol.appendChild(el("strong", "", compTitle));
      const breakdownTxt = maintMo > 0
        ? `Est. ${formatUsd(monthly)}/mo (Infra ${formatUsd(infraMo)} + Maint ${formatUsd(maintMo)} + Usage at ${turns}M turns, +${formatUsd(onboard)} onboarding)`
        : `Est. ${formatUsd(monthly)}/mo at ${turns}M turns (+${formatUsd(onboard)} onboarding)`;
      textCol.appendChild(el("span", "field-hint", breakdownTxt));
      if (ov.tco_notes) {
        textCol.appendChild(el("span", "field-hint", ov.tco_notes));
      }
      lbl.append(rad, textCol);
      fs.appendChild(lbl);
    });
    container.appendChild(fs);

    if (syncSlots.has(spec.slot_id)) {
      const syncCopy = {
        identity_access: `Enterprise Sync: Federate ${tenantTerm("identity_provider_name", "Enterprise IdP")} via WIF during transition (+$15/mo bridge)`,
        agent_registry: `Enterprise Sync: Bi-directional sync with ${tenantTerm("registry_name", "Enterprise Registry")} (+$15/mo bridge)`,
        observability_tracing: `Enterprise Sync: Dual-export OTLP spans to ${tenantTerm("observability_name", "Enterprise OTLP")} (+$15/mo bridge)`,
      }[spec.slot_id];
      const syncLbl = el("label", "radio-card-option enterprise-sync-option");
      const syncChk = el("input");
      syncChk.type = "checkbox";
      syncChk.id = `${radioGroupPrefix}-sync-${tpl.template_id}-${spec.slot_id}`;
      syncChk.checked = comp.enterprise_sync_enabled !== false;
      syncChk.addEventListener("change", async () => {
        state[slotStateField] = spec.slot_id;
        if (!tpl.components[spec.slot_id]) {
          tpl.components[spec.slot_id] = {
            slot_id: spec.slot_id,
            provider: curProv,
            enabled: curProv !== "unconfigured",
            enterprise_sync_enabled: syncChk.checked,
            parameters: {},
          };
        } else {
          tpl.components[spec.slot_id].enterprise_sync_enabled = syncChk.checked;
        }
        await refreshEvaluation(true);
      });
      syncLbl.append(syncChk, el("span", "", syncCopy));
      container.appendChild(syncLbl);
    }

    if (
      spec.slot_id === "identity_access" &&
      tpl.static_secrets_in_env &&
      tpl.static_secrets_in_env.length > 0
    ) {
      const clearBtn = el(
        "button",
        "secondary-btn sm-btn",
        `Remove Static Env Keys (${tpl.static_secrets_in_env.join(", ")})`
      );
      clearBtn.type = "button";
      clearBtn.addEventListener("click", async () => {
        state[slotStateField] = spec.slot_id;
        tpl.static_secrets_in_env = [];
        await refreshEvaluation(true);
      });
      container.appendChild(clearBtn);
    }

    if (spec.slot_id === "ai_gateway") {
      const celLbl = el("label", "radio-card-option");
      const celChk = el("input");
      celChk.type = "checkbox";
      celChk.checked = Boolean(tpl.uap_cel_per_tool_enforced);
      celChk.addEventListener("change", async () => {
        state[slotStateField] = spec.slot_id;
        tpl.uap_cel_per_tool_enforced = celChk.checked;
        await refreshEvaluation(true);
      });
      celLbl.append(
        celChk,
        el("span", "", "Enforce inline per-tool UAP Policy V2 CEL authorization")
      );
      container.appendChild(celLbl);
    }

    if (spec.slot_id === "safety_guardrails") {
      const sdpGrp = el("div", "field-group");
      const sdpId = `${radioGroupPrefix}-sdp-${tpl.template_id}-${spec.slot_id}`;
      const sdpLbl = el("label", "", "Inline PII Inspection Mode");
      sdpLbl.setAttribute("for", sdpId);
      const sdpSel = el("select");
      sdpSel.id = sdpId;
      ["DEIDENTIFY_INLINE", "BLOCK_ON_MATCH", "INSPECT_ONLY", "NONE"].forEach((m) => {
        const o = el("option", "", m);
        o.value = m;
        if (tpl.sdp_pii_mode === m) o.selected = true;
        sdpSel.appendChild(o);
      });
      sdpSel.addEventListener("change", async () => {
        state[slotStateField] = spec.slot_id;
        tpl.sdp_pii_mode = sdpSel.value;
        await refreshEvaluation(true);
      });
      sdpGrp.append(sdpLbl, sdpSel);
      container.appendChild(sdpGrp);
    }
  }

  /* Nested Set of 10 Functional Component Expanders (Build Page) */
  function buildNestedComponentExpanders(tpl, panelRoot) {
    const card = el("div", "surface-card nested-expanders-card");
    card.appendChild(el("h3", "section-heading", "Component Choices (10 Functional Areas)"));

    const stack = el("div", "nested-expanders-stack");
    const accordionGroupName = `slot-accordion-${tpl.template_id}`;

    state.slotCatalog.forEach((spec) => {
      const sid = spec.slot_id;
      const comp = (tpl.components && tpl.components[sid]) || {
        slot_id: sid,
        provider: "unconfigured",
        enabled: false,
      };
      const prov = comp.enabled === false ? "unconfigured" : comp.provider;
      const implLabel = (spec.provider_labels && spec.provider_labels[prov]) || "Not Configured";

      const det = el("details", "component-expander");
      det.setAttribute("name", accordionGroupName);
      det.dataset.slotId = sid;
      if (state.selectedSlotId === sid) {
        det.open = true;
      }

      const summary = el("summary", "component-expander-summary");
      const titleSpan = el(
        "span",
        "expander-title-group",
        `${spec.step}. ${spec.functional_name}`
      );
      const choicePill = el("span", "expander-choice-pill", implLabel);
      summary.append(titleSpan, choicePill);

      const body = el("div", "component-expander-body");
      populateSlotConfigurationBody(body, spec, tpl, "nested_slot", "selectedSlotId");

      det.addEventListener("toggle", () => {
        if (det.open) {
          stack.querySelectorAll("details.component-expander[open]").forEach((other) => {
            if (other !== det) {
              other.open = false;
            }
          });
        }
        syncHorizontalTilesWithOpenExpander(panelRoot, "selectedSlotId");
      });

      det.append(summary, body);
      stack.appendChild(det);
    });

    card.appendChild(stack);
    return card;
  }

  /* Reusable Sortable + Filterable 10-Component Cost Breakdown Sub-Table */
  function buildSortableComponentCostSubTable(componentCosts, captionText, tableKey) {
    const subWrap = el("div", "table-wrap");
    const subTbl = el("table", "data-table");
    subTbl.appendChild(el("caption", "", captionText));

    const cols = [
      {
        key: "functional_name",
        label: "Functional Component",
        type: "string",
        filterType: "text",
        getValue: (c) => c.functional_name || c.capability_name || "",
      },
      {
        key: "pillar",
        label: "Pillar",
        type: "string",
        filterType: "select",
        getValue: (c) => c.pillar || "Control",
      },
      {
        key: "provider_display_name",
        label: "Selected Component",
        type: "string",
        filterType: "text",
        getValue: (c) => c.provider_display_name || "",
      },
      {
        key: "monthly_cost_usd",
        label: "Monthly Cost",
        type: "number",
        filterType: "text",
        getValue: (c) => Number(c.monthly_cost_usd || 0),
        getFilterText: (c) => formatUsd(c.monthly_cost_usd),
      },
      {
        key: "historical_cumulative_usd",
        label: "Cumulative Spend",
        type: "number",
        filterType: "text",
        getValue: (c) => Number(c.historical_cumulative_usd || 0),
        getFilterText: (c) => formatUsd(c.historical_cumulative_usd),
      },
    ];

    const srcRows = componentCosts || [];
    const processed = applyTableSortAndFilters(
      srcRows,
      cols,
      tableKey,
      "monthly_cost_usd",
      "desc"
    );
    const activeBanner = buildActiveFiltersBanner(tableKey, processed.length, srcRows.length, null);
    if (activeBanner) {
      subWrap.appendChild(activeBanner);
    }

    subTbl.appendChild(
      buildInteractiveTableHead({
        tableKey,
        columns: cols,
        allRows: srcRows,
        defaultSortCol: "monthly_cost_usd",
        defaultSortDir: "desc",
        paginationState: null,
      })
    );

    const stb = el("tbody");
    processed.forEach((c) => {
      const r = el("tr");
      r.appendChild(el("td", "", c.functional_name || c.capability_name));
      r.appendChild(el("td", "", c.pillar || "Control"));
      r.appendChild(el("td", "", c.provider_display_name));
      r.appendChild(el("td", "", formatUsd(c.monthly_cost_usd)));
      r.appendChild(el("td", "", formatUsd(c.historical_cumulative_usd)));
      stb.appendChild(r);
    });
    subTbl.appendChild(stb);
    subWrap.appendChild(subTbl);
    return subWrap;
  }

  /* =========================================================================
   * Stage Renderers (Build, Evaluate, Deploy, Govern)
   * ========================================================================= */
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

    if (state.pendingFocusRestore) {
      const { id, start, end } = state.pendingFocusRestore;
      state.pendingFocusRestore = null;
      const target = document.getElementById(id);
      if (target && typeof target.focus === "function") {
        target.focus();
        if (typeof target.setSelectionRange === "function") {
          try {
            target.setSelectionRange(start, end);
          } catch (_) {
            /* non-text input */
          }
        }
      }
    }
  }

  /* ------------------------------ 1. BUILD ------------------------------ */
  function renderBuildStage(root) {
    const terms = (state.tenant && state.tenant.terminology) || {};
    const toolbar = el("div", "toolbar-row");
    toolbar.appendChild(el("h1", "strip-title", "Agent Instances"));

    const right = el("div", "toolbar-right");
    const newBtn = el("button", "primary-btn", "+ New Agent");
    newBtn.type = "button";
    newBtn.addEventListener("click", () => openNewAgentModal());
    right.appendChild(newBtn);
    toolbar.appendChild(right);
    root.appendChild(toolbar);

    const tableKey = "build-agents";
    const cols = [
      {
        key: "agent_name",
        label: "Agent ID",
        type: "string",
        filterType: "text",
        getValue: (r) => r.agent_name,
      },
      {
        key: "lifecycle_status",
        label: "Status",
        type: "string",
        filterType: "select",
        options: [
          ["DEPLOYED", "Deployed"],
          ["DRAFT", "Draft"],
        ],
        getValue: (r) => r.lifecycle_status || "DRAFT",
      },
      {
        key: "updated_at",
        label: "Last Activity",
        type: "date",
        filterType: "text",
        getValue: (r) => r.updated_at || "",
        getFilterText: (r) => `${r.updated_display || ""} ${r.updated_at || ""}`,
      },
      {
        key: "business_unit_label",
        label: "Business Unit",
        type: "string",
        filterType: "select",
        getValue: (r) => r.business_unit_label || buLabel(r.business_unit),
      },
      {
        key: "app_id",
        label: tenantTerm("cmdb_col_label", "CMDB App ID"),
        type: "string",
        filterType: "text",
        getValue: (r) => r.app_id || "",
      },
      {
        key: "intake_id",
        label: tenantTerm("intake_col_label", "Intake ID"),
        type: "string",
        filterType: "text",
        getValue: (r) => r.intake_id || "Pending",
      },
      {
        key: "risk_tier",
        label: tenantTerm("agency_tier_label", tenantTerm("risk_col_label", "Agency Tier")),
        type: "string",
        filterType: "select",
        options: [
          ["ag1", "ag1"],
          ["ag2", "ag2"],
          ["ag3", "ag3"],
          ["ag4", "ag4"],
          ["ag5", "ag5"],
        ],
        getValue: (r) => String(r.risk_tier || "AG2").toLowerCase(),
      },
    ];

    const processed = applyTableSortAndFilters(
      state.templates,
      cols,
      tableKey,
      "updated_at",
      "desc"
    );

    const totalPages = Math.max(1, Math.ceil(processed.length / state.buildPagination.pageSize));
    if (state.buildPagination.page > totalPages) {
      state.buildPagination.page = totalPages;
    }
    const pageStart = (state.buildPagination.page - 1) * state.buildPagination.pageSize;
    const pagedItems = processed.slice(pageStart, pageStart + state.buildPagination.pageSize);

    const tableWrap = el("div", "table-wrap");
    const activeBanner = buildActiveFiltersBanner(
      tableKey,
      processed.length,
      state.templates.length,
      state.buildPagination
    );
    if (activeBanner) {
      tableWrap.appendChild(activeBanner);
    }

    const table = el("table", "data-table");
    table.appendChild(
      el(
        "caption",
        "",
        "Sorted newest-first by activity. Select any agent row to expand its 10 horizontal blocks, metadata, and nested component expanders."
      )
    );
    table.appendChild(
      buildInteractiveTableHead({
        tableKey,
        columns: cols,
        allRows: state.templates,
        defaultSortCol: "updated_at",
        defaultSortDir: "desc",
        paginationState: state.buildPagination,
      })
    );

    const tbody = el("tbody");
    pagedItems.forEach((item) => {
      const isExpanded = state.expandedAgentId === item.template_id;
      const isDeployed = item.lifecycle_status === "DEPLOYED";

      const tr = el("tr", "clickable-row");
      if (isExpanded) {
        tr.classList.add("is-active-agent-row", "is-expanded-parent");
      }

      const tdId = el("td");
      const selBtn = el("button", "row-select-btn");
      selBtn.type = "button";
      selBtn.setAttribute("aria-expanded", isExpanded ? "true" : "false");
      selBtn.appendChild(el("span", "row-chevron", isExpanded ? "\u25BE" : "\u25B8"));
      selBtn.appendChild(el("span", "", item.agent_name));
      selBtn.addEventListener("click", (ev) => {
        ev.stopPropagation();
        toggleAgentRowExpansion(item, "expandedAgentId");
      });
      tdId.appendChild(selBtn);

      const tdStatus = el("td");
      tdStatus.appendChild(
        el(
          "span",
          isDeployed ? "status-badge status-ok" : "status-badge status-draft",
          isDeployed ? "Deployed" : "Draft"
        )
      );

      const tdUpd = el("td", "", item.updated_display || item.updated_at || "--");
      const tdBu = el("td", "", item.business_unit_label || buLabel(item.business_unit));
      const tdApp = el("td", "", item.app_id);
      const tdIntake = el("td", "", item.intake_id || "Pending");
      const tdRisk = el("td", "", String(item.risk_tier || "AG2").toLowerCase());

      tr.append(tdId, tdStatus, tdUpd, tdBu, tdApp, tdIntake, tdRisk);
      tr.addEventListener("click", () => toggleAgentRowExpansion(item, "expandedAgentId"));
      tbody.appendChild(tr);

      if (isExpanded && state.workingTemplate) {
        tbody.appendChild(buildExpandedAgentEditorRow(state.workingTemplate));
      }
    });

    table.appendChild(tbody);
    tableWrap.appendChild(table);
    tableWrap.appendChild(
      buildPaginationControls({
        totalItems: processed.length,
        paginationState: state.buildPagination,
        navLabel: "Agent instances pages",
        idPrefix: "build-agents",
      })
    );
    root.appendChild(tableWrap);
  }

  function buildExpandedAgentEditorRow(tpl) {
    const terms = (state.tenant && state.tenant.terminology) || {};
    const expTr = el("tr", "expanded-editor-row");
    const td = el("td", "expanded-editor-cell");
    td.colSpan = 7;

    const panel = el("div", "expanded-instance-panel");
    const evalObj = state.currentEvaluation;

    if (tpl.risk_tier === "AG5" || (evalObj && evalObj.ag5_prohibited_blocked)) {
      const ag5Banner = el("div", "alert-banner ag5-block-banner");
      ag5Banner.setAttribute("role", "alert");
      ag5Banner.appendChild(
        el(
          "strong",
          "",
          `[X] ${tenantTerm("prohibited_risk_tier", "AG5")} (Fully Autonomous) Prohibited: `
        )
      );
      ag5Banner.appendChild(
        el(
          "span",
          "",
          "Enterprise policy prohibits AG5 deployment without human intervention. Reclassify to AG1-AG4 with HITL and kill-switch controls."
        )
      );
      panel.appendChild(ag5Banner);
    }

    // 1. Instance-Scoped Toolbar: Template [Google Cloud | Custom] + Import / Export / Save / Evaluate
    const bar = el("div", "instance-toolbar");
    const activePreset = resolveTemplatePresetKey(tpl);
    const fs = el("fieldset", "segmented-radio-group");
    fs.appendChild(el("legend", "visually-hidden", `Template preset for ${tpl.agent_name}`));
    const inlineLbl = el("span", "control-inline-label", "Template:");
    inlineLbl.setAttribute("aria-hidden", "true");
    fs.appendChild(inlineLbl);

    [
      ["google_gcp", gcpShortName()],
      ["custom", "Custom"],
    ].forEach(([key, labelText]) => {
      const radioId = `inst-tpl-${tpl.template_id}-${key}`;
      const rad = el("input", "segmented-radio-input");
      rad.type = "radio";
      rad.id = radioId;
      rad.name = `inst_tpl_mode_${tpl.template_id}`;
      rad.value = key;
      rad.checked = activePreset === key;
      rad.addEventListener("change", () => {
        if (rad.checked) {
          applyInstanceTemplatePreset(key);
        }
      });
      const lbl = el("label", "segmented-radio-label", labelText);
      lbl.setAttribute("for", radioId);
      fs.append(rad, lbl);
    });

    const actionRight = el("div", "toolbar-right");
    const impBtn = el("button", "secondary-btn sm-btn", "Import Manifest");
    impBtn.type = "button";
    impBtn.addEventListener("click", () => openImportManifestModal(true));

    const expBtn = el("button", "secondary-btn sm-btn", "Export YAML");
    expBtn.type = "button";
    expBtn.addEventListener("click", () => exportCurrentTemplateYaml());

    const saveBtn = el("button", "secondary-btn sm-btn", "Save");
    saveBtn.type = "button";
    saveBtn.addEventListener("click", () => saveCurrentTemplate());

    const evalBtn = el("button", "primary-btn sm-btn", "Evaluate Agent ->");
    evalBtn.type = "button";
    evalBtn.addEventListener("click", async () => {
      await refreshEvaluation(false);
      if (state.currentEvaluation) {
        const firstFail = (state.currentEvaluation.rule_results || []).find(
          (r) => r.status === "FAILED"
        );
        state.selectedEvalSlotId = firstFail ? firstFail.slot_id : "identity_access";
      }
      jumpToAgentOnStage("evaluate", tpl.template_id);
    });

    actionRight.append(impBtn, expBtn, saveBtn, evalBtn);
    bar.append(fs, actionRight);
    panel.appendChild(bar);

    // 2. Full-Width 10 Horizontal Functional Blocks
    panel.appendChild(buildInstanceTenTileStrip(tpl, panel, null, "selectedSlotId"));

    // 3. Two-Column Body: Left = Instance Metadata | Right = 10 Nested Functional Component Expanders
    const twoCol = el("div", "instance-2col-grid");
    const metaCard = el("div", "surface-card form-stack");
    metaCard.appendChild(el("h3", "section-heading", "Agent Instance Metadata"));

    const makeField = (idSuffix, labelTxt, val, onCommit, type = "text") => {
      const g = el("div", "field-group");
      const fullId = `inst-${tpl.template_id}-${idSuffix}`;
      const l = el("label", "", labelTxt);
      l.setAttribute("for", fullId);
      const inp = el("input");
      inp.type = type;
      inp.id = fullId;
      inp.value = String(val ?? "");
      inp.addEventListener("blur", () => {
        inp.reportValidity();
        onCommit(inp.value);
      });
      inp.addEventListener("input", () => inp.setCustomValidity(""));
      g.append(l, inp);
      return { group: g, input: inp };
    };

    const gridTop = el("div", "form-grid-2");
    const fName = makeField("agent-name", "Agent ID", tpl.agent_name, (v) => {
      tpl.agent_name = v.trim() || tpl.agent_name;
      tpl.name = tpl.agent_name;
      syncWorkingTemplateIntoList();
      renderHeaderAndBrand();
    });

    const buGrp = el("div", "field-group");
    const buId = `inst-${tpl.template_id}-bu`;
    const buLbl = el("label", "", "Business Unit");
    buLbl.setAttribute("for", buId);
    const buSel = el("select");
    buSel.id = buId;
    ["core_cable", "media_studio", "intl_sky", "enterprise_shared"].forEach((k) => {
      const o = el("option", "", buLabel(k));
      o.value = k;
      if (tpl.business_unit === k) o.selected = true;
      buSel.appendChild(o);
    });
    buSel.addEventListener("change", async () => {
      tpl.business_unit = buSel.value;
      await refreshEvaluation(true);
    });
    buGrp.append(buLbl, buSel);
    gridTop.append(fName.group, buGrp);

    const gridMid = el("div", "form-grid-2");
    const fApp = makeField(
      "app-id",
      tenantTerm("cmdb_col_label", "CMDB App ID"),
      tpl.app_id,
      (v) => {
        tpl.app_id = v.trim() || tpl.app_id;
        syncWorkingTemplateIntoList();
      }
    );
    const fIntake = makeField(
      "intake-id",
      tenantTerm("intake_col_label", "Intake ID"),
      tpl.intake_id,
      async (v) => {
        tpl.intake_id = v.trim();
        await refreshEvaluation(true);
      }
    );
    gridMid.append(fApp.group, fIntake.group);

    const gridBot = el("div", "form-grid-2");
    const riskGrp = el("div", "field-group");
    const riskId = `inst-${tpl.template_id}-risk`;
    const riskLbl = el(
      "label",
      "",
      tenantTerm("agency_tier_label", tenantTerm("risk_col_label", "Agency Tier"))
    );
    riskLbl.setAttribute("for", riskId);
    const riskSel = el("select");
    riskSel.id = riskId;
    [
      ["AG1", "ag1"],
      ["AG2", "ag2"],
      ["AG3", "ag3"],
      ["AG4", "ag4"],
      ["AG5", "ag5 (Prohibited - Fully Autonomous)"],
    ].forEach(([r, txt]) => {
      const o = el("option", "", txt);
      o.value = r;
      if (tpl.risk_tier === r) o.selected = true;
      riskSel.appendChild(o);
    });
    riskSel.addEventListener("change", async () => {
      tpl.risk_tier = riskSel.value;
      await refreshEvaluation(true);
    });
    riskGrp.append(riskLbl, riskSel);

    const fTurns = makeField(
      "turns",
      "Monthly Turns (Millions)",
      tpl.estimated_monthly_turns_millions,
      async (v) => {
        tpl.estimated_monthly_turns_millions = Math.max(0.1, Number(v || 3.5));
        await refreshEvaluation(true);
      },
      "number"
    );
    fTurns.input.step = "0.1";
    fTurns.input.min = "0.1";
    gridBot.append(riskGrp, fTurns.group);

    const sysGrp = el("div", "field-group");
    const sysId = `inst-${tpl.template_id}-sys`;
    const sysLbl = el("label", "", "System Instruction");
    sysLbl.setAttribute("for", sysId);
    const sysTxt = el("textarea");
    sysTxt.id = sysId;
    sysTxt.rows = 3;
    sysTxt.value = tpl.system_instruction || "";
    sysTxt.addEventListener("blur", () => {
      tpl.system_instruction = sysTxt.value;
    });
    sysGrp.append(sysLbl, sysTxt);

    const aiglBuildStrip = el("div", "aigl-phase-strip");
    aiglBuildStrip.appendChild(
      el(
        "p",
        "field-hint",
        `AIGL Phases 1-3 | AEGIS ${tpl.aegis_risk_level || "R2"} | CaaS ${(evalObj && evalObj.caas_matrix && evalObj.caas_matrix.effective_caas_level) || tpl.caas_risk_level || "Level 1"}`
      )
    );
    const buildPhases =
      (evalObj && evalObj.aigl_lifecycle && evalObj.aigl_lifecycle.phases) ||
      state.aiglPhaseSpecs ||
      [];
    const phaseChips = el("div", "aigl-phase-chips");
    buildPhases.slice(0, 3).forEach((ph) => {
      const chip = el("div", "aigl-phase-chip");
      chip.appendChild(el("strong", "", `Phase ${ph.phase}: ${ph.name}`));
      chip.appendChild(el("span", "field-hint", `${(ph.owners || []).join(", ")} (${ph.status || "ACTIVE"})`));
      phaseChips.appendChild(chip);
    });
    aiglBuildStrip.appendChild(phaseChips);

    metaCard.append(gridTop, gridMid, gridBot, sysGrp, aiglBuildStrip);

    const compCard = buildNestedComponentExpanders(tpl, panel);
    twoCol.append(metaCard, compCard);
    panel.appendChild(twoCol);

    td.appendChild(panel);
    expTr.appendChild(td);
    return expTr;
  }

  /* ----------------------------- 2. EVALUATE ---------------------------- */
  function renderEvaluateStage(root) {
    const terms = (state.tenant && state.tenant.terminology) || {};
    const headRow = el("div", "toolbar-row");
    headRow.appendChild(el("h1", "strip-title", "Governance Readiness & Evaluation"));
    root.appendChild(headRow);

    const tableKey = "eval-agents";
    const cols = [
      {
        key: "agent_name",
        label: "Agent ID",
        type: "string",
        filterType: "text",
        getValue: (r) => r.agent_name,
      },
      {
        key: "lifecycle_status",
        label: "Status",
        type: "string",
        filterType: "select",
        options: [
          ["DEPLOYED", "Deployed"],
          ["DRAFT", "Draft"],
        ],
        getValue: (r) => r.lifecycle_status || "DRAFT",
      },
      {
        key: "updated_at",
        label: "Last Activity",
        type: "date",
        filterType: "text",
        getValue: (r) => r.updated_at || "",
        getFilterText: (r) => `${r.updated_display || ""} ${r.updated_at || ""}`,
      },
      {
        key: "business_unit_label",
        label: "Business Unit",
        type: "string",
        filterType: "select",
        getValue: (r) => r.business_unit_label || buLabel(r.business_unit),
      },
      {
        key: "risk_tier",
        label: tenantTerm("agency_tier_label", tenantTerm("risk_col_label", "Agency Tier")),
        type: "string",
        filterType: "select",
        options: [
          ["ag1", "ag1"],
          ["ag2", "ag2"],
          ["ag3", "ag3"],
          ["ag4", "ag4"],
          ["ag5", "ag5"],
        ],
        getValue: (r) => String(r.risk_tier || "AG2").toLowerCase(),
      },
      {
        key: "latest_eval_score",
        label: "Readiness Score",
        type: "number",
        filterType: "text",
        getValue: (r) => Number(r.latest_eval_score ?? 0),
        getFilterText: (r) => `${Number(r.latest_eval_score ?? 0).toFixed(1)}`,
      },
      {
        key: "gate_verdict_label",
        label: "Gate Verdict",
        type: "string",
        filterType: "select",
        options: [
          ["Ready", "Ready"],
          ["Remediation Needed", "Remediation Needed"],
        ],
        getValue: (r) => resolveGateVerdictLabel(r),
      },
      {
        key: "recommendations_count",
        label: "Open Findings",
        type: "number",
        filterType: "text",
        getValue: (r) => Number(r.recommendations_count ?? 0),
      },
    ];

    const processed = applyTableSortAndFilters(
      state.templates,
      cols,
      tableKey,
      "updated_at",
      "desc"
    );

    const totalPages = Math.max(1, Math.ceil(processed.length / state.evalPagination.pageSize));
    if (state.evalPagination.page > totalPages) {
      state.evalPagination.page = totalPages;
    }
    const pageStart = (state.evalPagination.page - 1) * state.evalPagination.pageSize;
    const pagedItems = processed.slice(pageStart, pageStart + state.evalPagination.pageSize);

    const tableWrap = el("div", "table-wrap");
    const activeBanner = buildActiveFiltersBanner(
      tableKey,
      processed.length,
      state.templates.length,
      state.evalPagination
    );
    if (activeBanner) {
      tableWrap.appendChild(activeBanner);
    }

    const table = el("table", "data-table");
    table.appendChild(
      el(
        "caption",
        "",
        "Select any agent instance row to expand its readiness KPIs, 10 horizontal status blocks, and 10 nested Rule & Remediation expanders."
      )
    );
    table.appendChild(
      buildInteractiveTableHead({
        tableKey,
        columns: cols,
        allRows: state.templates,
        defaultSortCol: "updated_at",
        defaultSortDir: "desc",
        paginationState: state.evalPagination,
      })
    );

    const tbody = el("tbody");
    pagedItems.forEach((item) => {
      const isExpanded = state.expandedEvalAgentId === item.template_id;
      const isDeployed = item.lifecycle_status === "DEPLOYED";
      const scoreVal = Number(item.latest_eval_score ?? 0);
      const gateOk = Boolean(item.gate_passed);
      const recCnt = Number(item.recommendations_count ?? 0);

      const tr = el("tr", "clickable-row");
      if (isExpanded) {
        tr.classList.add("is-active-agent-row", "is-expanded-parent");
      }

      const tdId = el("td");
      const selBtn = el("button", "row-select-btn");
      selBtn.type = "button";
      selBtn.setAttribute("aria-expanded", isExpanded ? "true" : "false");
      selBtn.appendChild(el("span", "row-chevron", isExpanded ? "\u25BE" : "\u25B8"));
      selBtn.appendChild(el("span", "", item.agent_name));
      selBtn.addEventListener("click", (ev) => {
        ev.stopPropagation();
        toggleAgentRowExpansion(item, "expandedEvalAgentId");
      });
      tdId.appendChild(selBtn);

      const tdStatus = el("td");
      tdStatus.appendChild(
        el(
          "span",
          isDeployed ? "status-badge status-ok" : "status-badge status-draft",
          isDeployed ? "Deployed" : "Draft"
        )
      );

      const tdUpd = el("td", "", item.updated_display || item.updated_at || "--");
      const tdBu = el("td", "", item.business_unit_label || buLabel(item.business_unit));
      const tdRisk = el("td", "", String(item.risk_tier || "AG2").toLowerCase());
      const tdScore = el("td", "", `${scoreVal.toFixed(1)} / 100`);

      const tdGate = el("td");
      tdGate.appendChild(
        el(
          "span",
          gateOk ? "status-badge status-ok" : "status-badge status-err",
          gateOk ? "[OK] Ready" : "[!] Remediation Needed"
        )
      );

      const tdRecs = el("td", "", recCnt > 0 ? `${recCnt} open` : "0");

      tr.append(tdId, tdStatus, tdUpd, tdBu, tdRisk, tdScore, tdGate, tdRecs);
      tr.addEventListener("click", () => toggleAgentRowExpansion(item, "expandedEvalAgentId"));
      tbody.appendChild(tr);

      if (isExpanded && state.workingTemplate && state.currentEvaluation) {
        tbody.appendChild(buildExpandedEvaluateRow(state.workingTemplate, state.currentEvaluation));
      }
    });

    table.appendChild(tbody);
    tableWrap.appendChild(table);
    tableWrap.appendChild(
      buildPaginationControls({
        totalItems: processed.length,
        paginationState: state.evalPagination,
        navLabel: "Evaluation instances pages",
        idPrefix: "eval-agents",
      })
    );
    root.appendChild(tableWrap);
  }

  function buildCaasMatrixCard(tpl, ev) {
    const matrix = ev.caas_matrix;
    if (!matrix) return null;
    const card = el("div", "surface-card caas-matrix-card");

    const head = el("div", "toolbar-row");
    const left = el("div", "toolbar-left");
    left.appendChild(
      el(
        "h3",
        "section-heading",
        `AIGL Phase 4: ${matrix.total_domains}-Domain / ${matrix.total_factors}-Factor CaaS Risk Matrix`
      )
    );
    left.appendChild(
      el(
        "span",
        matrix.effective_caas_level === "Prohibited"
          ? "status-badge status-err"
          : matrix.collapsed_from_level_2
          ? "status-badge status-ok"
          : "status-badge status-warn",
        matrix.collapse_summary || `${matrix.baseline_caas_level} -> ${matrix.effective_caas_level}`
      )
    );
    head.appendChild(left);
    head.appendChild(
      el("span", "field-hint", `Review SLA: ${matrix.review_sla_estimate || "Standard"}`)
    );
    card.appendChild(head);

    const kpiStrip = el("div", "kpi-grid-4");
    [
      ["Baseline CaaS Level", matrix.baseline_caas_level || "Level 2", "Before platform certification"],
      ["Effective CaaS Level", matrix.effective_caas_level || "Level 1", matrix.collapsed_from_level_2 ? "Collapsed from Level 2" : "Active tier"],
      ["Google-Certified Controls", `${matrix.platform_covered_count || 0} / ${matrix.total_factors || 49}`, `${matrix.custom_control_count || 0} enterprise baseline`],
      ["Manual / Gap Factors", `${matrix.manual_review_count || 0} / ${matrix.total_factors || 49}`, "Remaining human-review items"],
    ].forEach(([l, v, s]) => {
      const c = el("div", "surface-card");
      c.append(el("p", "kpi-label", l), el("p", "kpi-value", v), el("p", "kpi-sub", s));
      kpiStrip.appendChild(c);
    });
    card.appendChild(kpiStrip);

    const domGrid = el("div", "caas-domain-grid");
    (matrix.domains || []).forEach((dom) => {
      const dCard = el("div", "caas-domain-card");
      const top = el("div", "pipeline-item-top");
      top.appendChild(el("strong", "", dom.name));
      const dCls =
        dom.status === "CERTIFIED_AUTOMATED"
          ? "status-badge status-ok"
          : dom.status === "PROHIBITED"
          ? "status-badge status-err"
          : "status-badge status-warn";
      top.appendChild(
        el(
          "span",
          dCls,
          dom.status === "CERTIFIED_AUTOMATED"
            ? `${dom.google_certified_count}/${dom.factor_count} Auto`
            : dom.status === "PROHIBITED"
            ? "PROHIBITED"
            : `${dom.manual_or_gap_count}/${dom.factor_count} Gap`
        )
      );
      dCard.appendChild(top);
      dCard.appendChild(el("span", "field-hint", dom.google_certified_control || ""));
      domGrid.appendChild(dCard);
    });
    card.appendChild(domGrid);

    const fDet = el("details", "caas-factors-expander");
    const fSum = el("summary", "component-expander-summary");
    fSum.append(
      el("span", "expander-title-group", `Inspect All ${matrix.total_factors || 49} CaaS Risk Factors`),
      el("span", "expander-choice-pill", `${matrix.platform_covered_count || 0} Auto | ${matrix.custom_control_count || 0} Baseline | ${matrix.manual_review_count || 0} Manual`)
    );
    const fBody = el("div", "component-expander-body");
    const fList = el("ul", "caas-factors-list");
    (matrix.factors || []).forEach((fac) => {
      const li = el("li", "caas-factor-row");
      li.appendChild(el("strong", "", `${fac.factor_id}: ${fac.name}`));
      li.appendChild(el("span", "field-hint", `${fac.nist_ai_rmf} | ${fac.assessment_mode} | ${fac.provider_label}`));
      const stBadgeCls =
        fac.coverage_state === "google_certified_automated"
          ? "status-badge status-ok"
          : fac.coverage_state === "prohibited_ag5"
          ? "status-badge status-err"
          : "status-badge status-warn";
      li.appendChild(el("span", stBadgeCls, fac.coverage_state));
      fList.appendChild(li);
    });
    fBody.appendChild(fList);
    fDet.append(fSum, fBody);
    card.appendChild(fDet);

    return card;
  }

  function buildExpandedEvaluateRow(tpl, ev) {
    const expTr = el("tr", "expanded-editor-row");
    const td = el("td", "expanded-editor-cell");
    td.colSpan = 8;

    const panel = el("div", "expanded-instance-panel");
    const streamPanel = el("div", "stream-progress-panel");
    streamPanel.id = "eval-stream-progress";
    streamPanel.setAttribute("aria-live", "polite");
    streamPanel.hidden = true;

    if (ev.ag5_prohibited_blocked || tpl.risk_tier === "AG5") {
      const ag5Banner = el("div", "alert-banner ag5-block-banner");
      ag5Banner.setAttribute("role", "alert");
      const msgWrap = el("div", "toolbar-row");
      const msgTxt = el(
        "span",
        "",
        `[X] ${tenantTerm("prohibited_risk_tier", "AG5")} (Fully Autonomous) is unconditionally prohibited and cannot pass evaluation or be exempted.`
      );
      const reclassBtn = el("button", "secondary-btn sm-btn", "Reclassify to AG3");
      reclassBtn.type = "button";
      reclassBtn.addEventListener("click", async () => {
        tpl.risk_tier = "AG3";
        await refreshEvaluation(true);
      });
      msgWrap.append(msgTxt, reclassBtn);
      ag5Banner.appendChild(msgWrap);
      panel.appendChild(ag5Banner);
    }

    // 1. Instance Action Bar
    const bar = el("div", "instance-toolbar");
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
        "Select any horizontal block or nested rule expander below to remediate or configure."
      )
    );

    const rightBtns = el("div", "toolbar-right");
    const openBuildBtn = el("button", "secondary-btn sm-btn", "Open in Build");
    openBuildBtn.type = "button";
    openBuildBtn.addEventListener("click", () => jumpToAgentOnStage("build", tpl.template_id));

    const optBtn = el("button", "secondary-btn sm-btn", "Optimize Prompt & Traces");
    optBtn.type = "button";
    optBtn.addEventListener("click", async () => {
      optBtn.disabled = true;
      try {
        const fly = await runWithLiveStepper(streamPanel, {
          title: "Live 6-Stage Closed-Loop Prompt & Trace Optimization",
          totalSteps: 6,
          runnerFn: (onStep) => apiPostStream("/api/steward/closed-loop-eval", {}, onStep),
        });
        state.workingTemplate.prompt_version = (fly.v2_candidate && fly.v2_candidate.prompt_version) || "v2";
        state.workingTemplate.behavior_score = fly.v2_candidate.behavior_score;
        state.workingTemplate.components.eval_optimization = {
          slot_id: "eval_optimization",
          provider: "google_gcp",
          enabled: true,
          enterprise_sync_enabled: true,
          parameters: { promoted_blueprint: state.workingTemplate.prompt_version },
        };
        await refreshEvaluation(true);
        showNotice(
          `Promoted v2 instructions via Gemini 3.8 Flash (${fly.v1_baseline.behavior_score} -> ${fly.v2_candidate.behavior_score}/100).`
        );
      } catch (err) {
        showError(err.message);
      } finally {
        optBtn.disabled = false;
      }
    });

    const auditBtn = el("button", "secondary-btn sm-btn", "Run ADK Workflow Audit");
    auditBtn.type = "button";
    auditBtn.addEventListener("click", async () => {
      auditBtn.disabled = true;
      try {
        const matchedCand = (state.candidates || []).find(
          (c) =>
            c.agent_name === tpl.agent_name ||
            c.candidate_id === tpl.candidate_id ||
            c.candidate_id === tpl.template_id
        );
        const resolvedCandidateId = String(
          (matchedCand && matchedCand.candidate_id) ||
            tpl.candidate_id ||
            tpl.template_id ||
            tpl.agent_name
        ).slice(0, 32);
        const auditRes = await runWithLiveStepper(streamPanel, {
          title: `Live ADK 2.0 Governance Workflow Audit (${resolvedCandidateId})`,
          totalSteps: 7,
          runnerFn: (onStep) =>
            apiPostStream(
              "/api/agent/audit",
              {
                candidate_id: resolvedCandidateId,
                agent_name: tpl.agent_name,
                app_id: tpl.app_id,
                risk_tier: tpl.risk_tier,
                operator_prompt: `Verify governance readiness and synthesize Terraform module for ${tpl.agent_name} (${tpl.app_id}).`,
                architecture_mode:
                  tpl.template_mode === "google_gcp" ? "google_native" : "enterprise_hybrid",
              },
              onStep
            ),
        });
        state.pendingHitl = auditRes.pending_approval
          ? {
              session_id: auditRes.session_id,
              interrupt_id: auditRes.pending_approval.interrupt_id,
            }
          : null;
        if (auditRes.status === "BLOCKED_PROHIBITED_AG5") {
          showError(
            (auditRes.remediation_outcome && auditRes.remediation_outcome.summary) ||
              "Blocked unconditionally: AEGIS AG5 (Fully Autonomous) is prohibited."
          );
        } else {
          showNotice(
            auditRes.status === "WAITING_AG3_APPROVAL"
              ? `ADK 2.0 workflow audit complete; AG3 approval checkpoint '${auditRes.pending_approval.interrupt_id}' staged for Deploy.`
              : "ADK 2.0 workflow audit completed with zero blocking interrupts."
          );
        }
      } catch (err) {
        showError(err.message);
      } finally {
        auditBtn.disabled = false;
      }
    });

    const toDeployBtn = el("button", "primary-btn sm-btn", "Proceed to Deploy ->");
    toDeployBtn.type = "button";
    toDeployBtn.addEventListener("click", () => {
      state.selectedDeploySection = "approval";
      jumpToAgentOnStage("deploy", tpl.template_id);
    });

    rightBtns.append(openBuildBtn, optBtn, auditBtn, toDeployBtn);
    bar.append(leftInfo, rightBtns);
    panel.append(bar, streamPanel);

    // 2. Compact 5-KPI Readiness & Pillar Strip
    const kpiRow = el("div", "kpi-grid-5");
    const mainScoreCard = el("div", "surface-card hero-metric-card");
    mainScoreCard.appendChild(el("p", "kpi-label", "Overall Governance Readiness"));
    mainScoreCard.appendChild(el("p", "kpi-value", `${ev.overall_score.toFixed(1)} / 100`));
    mainScoreCard.appendChild(
      el(
        "span",
        ev.gate_passed ? "status-badge status-ok" : "status-badge status-err",
        ev.ag5_prohibited_blocked
          ? "[X] PROHIBITED (AG5 BLOCKED)"
          : ev.gate_passed
          ? "[OK] Gate Passed"
          : `[!] ${ev.mandatory_failures_count} Blocking Gate(s)`
      )
    );
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
    panel.appendChild(kpiRow);

    // 3. 10 Horizontal Functional Status Blocks
    panel.appendChild(buildInstanceTenTileStrip(tpl, panel, ev, "selectedEvalSlotId"));

    // 4. 10 Nested Rule & Remediation Expanders
    panel.appendChild(buildNestedEvaluateExpanders(tpl, ev, panel));

    // 5. AIGL Phase 4: 12-Domain / 49-Factor CaaS Matrix
    const caasCard = buildCaasMatrixCard(tpl, ev);
    if (caasCard) {
      panel.appendChild(caasCard);
    }

    td.appendChild(panel);
    expTr.appendChild(td);
    return expTr;
  }

  function buildNestedEvaluateExpanders(tpl, ev, panelRoot) {
    const card = el("div", "surface-card nested-expanders-card");
    const openCnt = (ev.recommendations || []).length;
    card.appendChild(
      el(
        "h3",
        "section-heading",
        `${ev.rubric_name} - 10 Governance Rules (${openCnt} Open Finding(s))`
      )
    );

    const recByRule = {};
    (ev.recommendations || []).forEach((rec) => {
      recByRule[rec.rule_id] = rec;
    });

    const stack = el("div", "nested-expanders-stack");
    const groupName = `eval-accordion-${tpl.template_id}`;

    (ev.rule_results || []).forEach((r) => {
      const spec = state.slotById[r.slot_id] || state.slotCatalog[0];
      const rec = recByRule[r.rule_id] || null;

      const det = el("details", "component-expander");
      det.setAttribute("name", groupName);
      det.dataset.slotId = r.slot_id;
      if (state.selectedEvalSlotId === r.slot_id) {
        det.open = true;
      }

      const summary = el("summary", "component-expander-summary");
      const titleSpan = el(
        "span",
        "expander-title-group",
        `${r.rule_id} (${r.functional_name}): ${r.title}`
      );

      const rightMeta = el("span", "expander-summary-right");
      rightMeta.appendChild(el("span", "expander-choice-pill", `${r.weight_points} pts`));
      rightMeta.appendChild(el("span", "expander-choice-pill", r.current_provider_label));
      const badgeCls =
        r.status === "PASSED"
          ? "status-badge status-ok"
          : r.status === "EXCEPTION_APPROVED" || r.status === "ADVISORY"
          ? "status-badge status-warn"
          : r.status === "BLOCKED"
          ? "status-badge status-err"
          : r.mandatory
          ? "status-badge status-err"
          : "status-badge status-warn";
      const badgeTxt =
        r.status === "PASSED"
          ? "PASSED"
          : r.status === "EXCEPTION_APPROVED"
          ? "EXCEPTION"
          : r.status === "ADVISORY"
          ? "[~] ADVISORY"
          : r.status === "BLOCKED"
          ? "[X] PROHIBITED"
          : r.mandatory
          ? "[!] MANDATORY GATE"
          : "[~] ADVISORY";
      rightMeta.appendChild(el("span", badgeCls, badgeTxt));
      summary.append(titleSpan, rightMeta);

      const body = el("div", "component-expander-body");
      if (rec && rec.rule_id !== "AEGIS-AG5") {
        const callout = el(
          "div",
          rec.severity === "MANDATORY_GATE"
            ? "finding-callout is-mandatory"
            : "finding-callout is-advisory"
        );
        const deltaSign = rec.monthly_cost_delta_usd >= 0 ? "+" : "";
        callout.appendChild(
          el(
            "strong",
            "",
            `Finding (+${rec.score_uplift_pts} pts | ${deltaSign}${formatUsd(
              rec.monthly_cost_delta_usd
            )}/mo): ${rec.finding_detail}`
          )
        );
        callout.appendChild(
          el(
            "span",
            "field-hint",
            `Recommended: ${rec.recommended_provider_label} - ${rec.recommendation_summary}`
          )
        );
        if (rec.capability_delta) {
          callout.appendChild(el("span", "field-hint", `Capability Delta: ${rec.capability_delta}`));
        }

        const btnRow = el("div", "toolbar-left");
        const fixBtn = el("button", "primary-btn sm-btn", "Apply Recommended Fix");
        fixBtn.type = "button";
        fixBtn.addEventListener("click", async () => {
          fixBtn.disabled = true;
          try {
            state.selectedEvalSlotId = r.slot_id;
            const res = await apiPost("/api/templates/remediate", {
              template: state.workingTemplate,
              rule_id: rec.rule_id,
              action: "accept",
            });
            state.workingTemplate = res.template;
            state.currentEvaluation = res.evaluation;
            syncWorkingTemplateIntoList();
            renderHeaderAndBrand();
            renderStageBody();
          } catch (err) {
            showError(err.message);
          } finally {
            fixBtn.disabled = false;
          }
        });

        const excToggleBtn = el("button", "secondary-btn sm-btn", "Record Exception");
        excToggleBtn.type = "button";

        const excBox = el("div", "form-stack");
        excBox.hidden = true;
        const excId = `exc-input-${tpl.template_id}-${rec.rule_id}`;
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
            state.selectedEvalSlotId = r.slot_id;
            const res = await apiPost("/api/templates/remediate", {
              template: state.workingTemplate,
              rule_id: rec.rule_id,
              action: "exception",
              exception_reason: excInput.value,
            });
            state.workingTemplate = res.template;
            state.currentEvaluation = res.evaluation;
            syncWorkingTemplateIntoList();
            renderHeaderAndBrand();
            renderStageBody();
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

        btnRow.append(fixBtn, excToggleBtn);
        callout.append(btnRow, excBox);
        body.appendChild(callout);
      } else if (r.exception_note) {
        body.appendChild(
          el("p", "field-hint", `Approved Exception Recorded: ${r.exception_note}`)
        );
      }

      if (spec) {
        populateSlotConfigurationBody(
          body,
          spec,
          tpl,
          `eval_nested_${r.rule_id}`,
          "selectedEvalSlotId"
        );
      }

      det.addEventListener("toggle", () => {
        if (det.open) {
          stack.querySelectorAll("details.component-expander[open]").forEach((other) => {
            if (other !== det) {
              other.open = false;
            }
          });
        }
        syncHorizontalTilesWithOpenExpander(panelRoot, "selectedEvalSlotId");
      });

      det.append(summary, body);
      stack.appendChild(det);
    });

    card.appendChild(stack);
    return card;
  }

  /* ------------------------------ 3. DEPLOY ----------------------------- */
  function renderDeployStage(root) {
    const terms = (state.tenant && state.tenant.terminology) || {};
    const headRow = el("div", "toolbar-row");
    headRow.appendChild(el("h1", "strip-title", "Release & Deployment Gate"));
    root.appendChild(headRow);

    const tableKey = "deploy-agents";
    const cols = [
      {
        key: "agent_name",
        label: "Agent ID",
        type: "string",
        filterType: "text",
        getValue: (r) => r.agent_name,
      },
      {
        key: "release_state",
        label: "Release State",
        type: "string",
        filterType: "select",
        options: [
          ["Deployed", "Deployed"],
          ["Ready to Deploy", "Ready to Deploy"],
          ["Gate Blocked", "Gate Blocked"],
        ],
        getValue: (r) => resolveReleaseStateLabel(r),
      },
      {
        key: "latest_deployment_id",
        label: "Deployment ID",
        type: "string",
        filterType: "text",
        getValue: (r) => r.latest_deployment_id || "Pending",
      },
      {
        key: "updated_at",
        label: "Last Activity",
        type: "date",
        filterType: "text",
        getValue: (r) => r.updated_at || "",
        getFilterText: (r) => `${r.updated_display || ""} ${r.updated_at || ""}`,
      },
      {
        key: "business_unit_label",
        label: "Business Unit",
        type: "string",
        filterType: "select",
        getValue: (r) => r.business_unit_label || buLabel(r.business_unit),
      },
      {
        key: "risk_tier",
        label: tenantTerm("agency_tier_label", tenantTerm("risk_col_label", "Agency Tier")),
        type: "string",
        filterType: "select",
        options: [
          ["ag1", "ag1"],
          ["ag2", "ag2"],
          ["ag3", "ag3"],
          ["ag4", "ag4"],
          ["ag5", "ag5"],
        ],
        getValue: (r) => String(r.risk_tier || "AG2").toLowerCase(),
      },
      {
        key: "latest_eval_score",
        label: "Readiness Score",
        type: "number",
        filterType: "text",
        getValue: (r) => Number(r.latest_eval_score ?? 0),
        getFilterText: (r) => `${Number(r.latest_eval_score ?? 0).toFixed(1)}`,
      },
      {
        key: "monthly_run_rate_usd",
        label: "Monthly Run-Rate",
        type: "number",
        filterType: "text",
        getValue: (r) => Number(r.monthly_run_rate_usd ?? 0),
        getFilterText: (r) => formatUsd(r.monthly_run_rate_usd),
      },
    ];

    const processed = applyTableSortAndFilters(
      state.templates,
      cols,
      tableKey,
      "updated_at",
      "desc"
    );

    const totalPages = Math.max(1, Math.ceil(processed.length / state.deployPagination.pageSize));
    if (state.deployPagination.page > totalPages) {
      state.deployPagination.page = totalPages;
    }
    const pageStart = (state.deployPagination.page - 1) * state.deployPagination.pageSize;
    const pagedItems = processed.slice(pageStart, pageStart + state.deployPagination.pageSize);

    const tableWrap = el("div", "table-wrap");
    const activeBanner = buildActiveFiltersBanner(
      tableKey,
      processed.length,
      state.templates.length,
      state.deployPagination
    );
    if (activeBanner) {
      tableWrap.appendChild(activeBanner);
    }

    const table = el("table", "data-table");
    table.appendChild(
      el(
        "caption",
        "",
        "Sorted newest-first. Select any agent row to expand its Release Gate, Generated Terraform Module, Dynamic Guardrail Policy, and 10-Component Cost Attribution."
      )
    );
    table.appendChild(
      buildInteractiveTableHead({
        tableKey,
        columns: cols,
        allRows: state.templates,
        defaultSortCol: "updated_at",
        defaultSortDir: "desc",
        paginationState: state.deployPagination,
      })
    );

    const tbody = el("tbody");
    pagedItems.forEach((item) => {
      const isExpanded = state.expandedDeployAgentId === item.template_id;
      const relState = resolveReleaseStateLabel(item);
      const scoreVal = Number(item.latest_eval_score ?? 0);

      const tr = el("tr", "clickable-row");
      if (isExpanded) {
        tr.classList.add("is-active-agent-row", "is-expanded-parent");
      }

      const tdId = el("td");
      const selBtn = el("button", "row-select-btn");
      selBtn.type = "button";
      selBtn.setAttribute("aria-expanded", isExpanded ? "true" : "false");
      selBtn.appendChild(el("span", "row-chevron", isExpanded ? "\u25BE" : "\u25B8"));
      selBtn.appendChild(el("span", "", item.agent_name));
      selBtn.addEventListener("click", (ev) => {
        ev.stopPropagation();
        toggleAgentRowExpansion(item, "expandedDeployAgentId");
      });
      tdId.appendChild(selBtn);

      const tdState = el("td");
      const stCls =
        relState === "Deployed"
          ? "status-badge status-ok"
          : relState === "Ready to Deploy"
          ? "status-badge status-draft"
          : "status-badge status-err";
      tdState.appendChild(el("span", stCls, relState));

      const tdDepId = el("td", "", item.latest_deployment_id || "Pending");
      const tdUpd = el("td", "", item.updated_display || item.updated_at || "--");
      const tdBu = el("td", "", item.business_unit_label || buLabel(item.business_unit));
      const tdRisk = el("td", "", String(item.risk_tier || "AG2").toLowerCase());
      const tdScore = el("td", "", `${scoreVal.toFixed(1)} / 100`);
      const tdCost = el("td", "", formatUsd(item.monthly_run_rate_usd));

      tr.append(tdId, tdState, tdDepId, tdUpd, tdBu, tdRisk, tdScore, tdCost);
      tr.addEventListener("click", () => toggleAgentRowExpansion(item, "expandedDeployAgentId"));
      tbody.appendChild(tr);

      if (isExpanded && state.workingTemplate && state.currentEvaluation) {
        tbody.appendChild(buildExpandedDeployRow(state.workingTemplate, state.currentEvaluation));
      }
    });

    table.appendChild(tbody);
    tableWrap.appendChild(table);
    tableWrap.appendChild(
      buildPaginationControls({
        totalItems: processed.length,
        paginationState: state.deployPagination,
        navLabel: "Release and deployment instances pages",
        idPrefix: "deploy-agents",
      })
    );
    root.appendChild(tableWrap);
  }

  function buildExpandedDeployRow(tpl, ev) {
    const expTr = el("tr", "expanded-editor-row");
    const td = el("td", "expanded-editor-cell");
    td.colSpan = 8;

    const panel = el("div", "expanded-instance-panel");
    const isAg5Blocked = Boolean(ev.ag5_prohibited_blocked || tpl.risk_tier === "AG5");
    if (isAg5Blocked) {
      const ag5Banner = el("div", "alert-banner ag5-block-banner");
      ag5Banner.setAttribute("role", "alert");
      ag5Banner.appendChild(
        el(
          "strong",
          "",
          `[X] ${tenantTerm("prohibited_risk_tier", "AG5")} Deployment Unconditionally Blocked: `
        )
      );
      ag5Banner.appendChild(
        el(
          "span",
          "",
          "Fully autonomous (AG5) agents cannot be deployed or exempted. Reclassify to AG1-AG4 in Build."
        )
      );
      panel.appendChild(ag5Banner);
    }

    const bar = el("div", "instance-toolbar");
    const left = el("div", "toolbar-left");
    left.appendChild(
      el(
        "span",
        ev.gate_passed && !isAg5Blocked ? "status-badge status-ok" : "status-badge status-err",
        isAg5Blocked
          ? "[X] PROHIBITED (AG5 BLOCKED)"
          : ev.gate_passed
          ? `[OK] Ready for Production (${ev.overall_score.toFixed(1)}/100)`
          : `[!] Gate Blocked (${ev.overall_score.toFixed(1)} / ${ev.passing_threshold.toFixed(1)})`
      )
    );
    if (tpl.latest_deployment_id) {
      left.appendChild(
        el("span", "agent-context-pill", `Active Deployment: ${tpl.latest_deployment_id}`)
      );
    }

    const right = el("div", "toolbar-right");
    const openBuildBtn = el("button", "secondary-btn sm-btn", "Open in Build");
    openBuildBtn.type = "button";
    openBuildBtn.addEventListener("click", () => jumpToAgentOnStage("build", tpl.template_id));

    const backEvalBtn = el("button", "secondary-btn sm-btn", "<- Open in Evaluate");
    backEvalBtn.type = "button";
    backEvalBtn.addEventListener("click", () => jumpToAgentOnStage("evaluate", tpl.template_id));

    right.append(openBuildBtn, backEvalBtn);
    bar.append(left, right);
    panel.appendChild(bar);

    const stack = el("div", "nested-expanders-stack");
    const groupName = `deploy-accordion-${tpl.template_id}`;
    const cEst = ev.cost_estimate;

    const makeDeployExpander = (sectionKey, titleText, pillText, buildBodyFn) => {
      const det = el("details", "component-expander");
      det.setAttribute("name", groupName);
      det.dataset.sectionKey = sectionKey;
      if (state.selectedDeploySection === sectionKey) {
        det.open = true;
      }
      const sum = el("summary", "component-expander-summary");
      sum.append(
        el("span", "expander-title-group", titleText),
        el("span", "expander-choice-pill", pillText)
      );
      const body = el("div", "component-expander-body");
      buildBodyFn(body);
      det.addEventListener("toggle", () => {
        if (det.open) {
          state.selectedDeploySection = sectionKey;
          stack.querySelectorAll("details.component-expander[open]").forEach((other) => {
            if (other !== det) {
              other.open = false;
            }
          });
        }
      });
      det.append(sum, body);
      return det;
    };

    // Nested Expander 1: Release Gate & Production Approval
    stack.appendChild(
      makeDeployExpander(
        "approval",
        "1. Release Gate & Production Approval",
        tpl.lifecycle_status === "DEPLOYED"
          ? `Deployed (${tpl.latest_deployment_id || "Active"})`
          : ev.gate_passed
          ? "Ready to Deploy"
          : "Gate Blocked",
        (body) => {
          const kpis = el("div", "kpi-grid-4");
          [
            [
              "Projected Monthly Run-Rate",
              formatUsd(cEst.monthly_run_rate_usd),
              `${cEst.estimated_monthly_turns_millions}M turns/mo`,
            ],
            [
              "One-Time Onboarding & Eval",
              formatUsd(cEst.onboarding_eval_cost_usd),
              "Initial provisioning & benchmarks",
            ],
            [
              "Monthly Consolidation Delta",
              formatUsd(cEst.monthly_savings_usd),
              `vs. ${customerShortName()} baseline`,
            ],
            [
              tenantTerm("agency_tier_label", tenantTerm("risk_col_label", "Agency Tier")),
              tpl.risk_tier,
              tpl.risk_tier === "AG5"
                ? "PROHIBITED - Deployment Blocked"
                : tpl.risk_tier === "AG3" || tpl.risk_tier === "AG4"
                ? "Reviewer sign-off enforced"
                : "Automated release eligible",
            ],
          ].forEach(([lbl, val, sub], idx) => {
            const c = el("div", idx === 0 ? "surface-card hero-metric-card" : "surface-card");
            c.append(
              el("p", "kpi-label", lbl),
              el("p", "kpi-value", val),
              el("p", "kpi-sub", sub)
            );
            kpis.appendChild(c);
          });
          body.appendChild(kpis);

          const p5Gate = ev.phase5_reviewer_gate;
          if (p5Gate) {
            const p5Panel = el("div", "surface-card phase5-gate-panel");
            const p5Head = el("div", "toolbar-row");
            const p5Left = el("div", "toolbar-left");
            p5Left.appendChild(
              el(
                "h4",
                "section-heading",
                `AIGL Phase 5: 7-Reviewer Governance Board (${p5Gate.approved_count || 0}/${p5Gate.total_reviewers || 7} Approved)`
              )
            );
            const p5Cls =
              p5Gate.verdict === "APPROVED"
                ? "status-badge status-ok"
                : p5Gate.verdict === "DENIED"
                ? "status-badge status-err"
                : "status-badge status-warn";
            p5Left.appendChild(el("span", p5Cls, p5Gate.verdict || "PENDING_REVIEW"));
            p5Head.appendChild(p5Left);

            if (!isAg5Blocked && p5Gate.verdict !== "APPROVED") {
              const approveAllBtn = el("button", "secondary-btn sm-btn", "Record 7-Reviewer Sign-Off");
              approveAllBtn.type = "button";
              approveAllBtn.addEventListener("click", async () => {
                approveAllBtn.disabled = true;
                try {
                  let latestTpl = state.workingTemplate;
                  let latestEval = state.currentEvaluation;
                  const roles = (p5Gate.reviewers || []).filter(
                    (r) => r.status !== "Approved" && r.status !== "Approved with Conditions"
                  );
                  for (const rev of roles) {
                    const res = await apiPost("/api/templates/phase5-reviewers", {
                      template: latestTpl,
                      role: rev.role,
                      status: "Approved",
                      notes: "Parallel board sign-off recorded in Deploy.",
                      reviewer_principal: appInp.value || "gov-steward-lead",
                    });
                    latestTpl = res.template;
                    latestEval = res.evaluation;
                    if (res.templates) {
                      state.templates = res.templates;
                    }
                  }
                  state.workingTemplate = latestTpl;
                  state.currentEvaluation = latestEval;
                  syncWorkingTemplateIntoList();
                  renderStageBody();
                  showNotice("Recorded Phase 5 7-Reviewer board sign-offs.");
                } catch (err) {
                  showError(err.message);
                } finally {
                  approveAllBtn.disabled = false;
                }
              });
              p5Head.appendChild(approveAllBtn);
            }
            p5Panel.appendChild(p5Head);

            const revGrid = el("div", "phase5-reviewer-grid");
            (p5Gate.reviewers || []).forEach((rev) => {
              const rCard = el("div", "phase5-reviewer-card");
              const rTop = el("div", "pipeline-item-top");
              rTop.appendChild(el("strong", "", rev.role));
              const rCls =
                rev.status === "Approved" || rev.status === "Approved with Conditions"
                  ? "status-badge status-ok"
                  : rev.status === "Denied"
                  ? "status-badge status-err"
                  : "status-badge status-draft";
              rTop.appendChild(el("span", rCls, rev.status));
              rCard.appendChild(rTop);

              const rSel = el("select", "col-filter-select");
              rSel.setAttribute("aria-label", `${rev.role} Phase 5 sign-off status`);
              rSel.disabled = isAg5Blocked;
              ["Pending", "Approved", "Approved with Conditions", "Denied"].forEach((opt) => {
                const o = el("option", "", opt);
                o.value = opt;
                if (rev.status === opt) o.selected = true;
                rSel.appendChild(o);
              });
              rSel.addEventListener("change", async () => {
                try {
                  const res = await apiPost("/api/templates/phase5-reviewers", {
                    template: state.workingTemplate,
                    role: rev.role,
                    status: rSel.value,
                    notes: `Updated ${rev.role} review to ${rSel.value}.`,
                    reviewer_principal: appInp.value || "gov-steward-lead",
                  });
                  state.workingTemplate = res.template;
                  state.currentEvaluation = res.evaluation;
                  if (res.templates) state.templates = res.templates;
                  syncWorkingTemplateIntoList();
                  renderStageBody();
                } catch (err) {
                  showError(err.message);
                }
              });
              rCard.appendChild(rSel);
              if (rev.notes) {
                rCard.appendChild(el("span", "field-hint", rev.notes));
              }
              revGrid.appendChild(rCard);
            });
            p5Panel.appendChild(revGrid);
            body.appendChild(p5Panel);
          }

          const deployForm = el("form", "inline-action-form");
          const appGrp = el("div", "field-group");
          const appId = `deploy-approver-${tpl.template_id}`;
          const appLbl = el("label", "", "Approver Principal");
          appLbl.setAttribute("for", appId);
          const appInp = el("input");
          appInp.type = "text";
          appInp.id = appId;
          appInp.name = "approver_principal";
          appInp.required = true;
          appInp.value = "platform-governance-lead";
          appGrp.append(appLbl, appInp);

          const tktGrp = el("div", "field-group");
          const tktId = `deploy-ticket-${tpl.template_id}`;
          const tktLbl = el("label", "", "Release Change / Approval Ticket");
          tktLbl.setAttribute("for", tktId);
          const tktInp = el("input");
          tktInp.type = "text";
          tktInp.id = tktId;
          tktInp.name = "approval_ticket";
          tktInp.value = "CHG-2026-8841";
          tktGrp.append(tktLbl, tktInp);

          const submitWrap = el("div", "form-actions-end");
          const deployBtn = el("button", "primary-btn", "Deploy Agent to Fleet");
          deployBtn.type = "submit";
          if (isAg5Blocked || (p5Gate && p5Gate.verdict === "DENIED")) {
            deployBtn.disabled = true;
          }

          if (!ev.gate_passed) {
            const fixFirstBtn = el("button", "secondary-btn", "<- Remediate in Evaluate");
            fixFirstBtn.type = "button";
            fixFirstBtn.addEventListener("click", () =>
              jumpToAgentOnStage("evaluate", tpl.template_id)
            );
            submitWrap.appendChild(fixFirstBtn);
          }

          if (state.pendingHitl && !isAg5Blocked) {
            const hitlBtn = el(
              "button",
              "secondary-btn",
              `Approve ADK Checkpoint (${state.pendingHitl.interrupt_id})`
            );
            hitlBtn.type = "button";
            hitlBtn.addEventListener("click", async () => {
              hitlBtn.disabled = true;
              try {
                const res = await apiPost("/api/agent/resume", {
                  session_id: state.pendingHitl.session_id,
                  interrupt_id: state.pendingHitl.interrupt_id,
                  approved: true,
                  approver_principal: appInp.value || "platform-governance-lead",
                  vp_exception_ticket: tktInp.value || null,
                  reason: `Approved via ${tenantTerm("platform_name", "Agent Governance Platform")} Deploy Gate.`,
                });
                state.pendingHitl = null;
                renderStageBody();
                const remStatus = res.remediation_outcome && res.remediation_outcome.status;
                if (remStatus === "HELD_FOR_GOVERNANCE_EXCEPTION") {
                  showError(
                    (res.remediation_outcome && res.remediation_outcome.summary) ||
                      "Held pending VP Governance-Freeze exception ticket."
                  );
                } else {
                  showNotice("Resumed and completed ADK 2.0 AG3 deployment checkpoint.");
                }
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
              if (depRes.templates) {
                state.templates = depRes.templates;
                const refreshed = state.templates.find(
                  (t) => t.template_id === state.workingTemplate.template_id
                );
                if (refreshed) {
                  state.workingTemplate = cloneJson(refreshed);
                }
              }
              if (depRes.recertification_records) {
                state.recertificationRecords = depRes.recertification_records;
              }
              state.operationsMetrics = depRes.operations_metrics;
              state.executiveCosts = depRes.executive_costs;
              state.walletState = depRes.wallet_state;
              clearTableFilters("deploy-agents", state.deployPagination);
              state.deployPagination.page = 1;
              state.buildPagination.page = 1;
              state.expandedDeployAgentId = state.workingTemplate.template_id;
              state.selectedDeploySection = "costs";
              renderStageBody();
              showNotice(
                `Deployed ${depRes.deployment.agent_name} (${depRes.deployment.deployment_id}) at ${formatUsd(
                  depRes.deployment.monthly_run_rate_usd
                )}/mo.`
              );
            } catch (err) {
              showError(err.message);
            } finally {
              if (!isAg5Blocked) {
                deployBtn.disabled = false;
              }
            }
          });

          body.appendChild(deployForm);
        }
      )
    );

    // Nested Expander 2: Generated Terraform Module (HCL)
    stack.appendChild(
      makeDeployExpander(
        "terraform",
        "2. Generated Terraform Module (infra/terraform)",
        "Paved-Path HCL",
        (body) => {
          const tfHead = el("div", "toolbar-row");
          tfHead.appendChild(
            el("span", "field-hint", "Standardized Terraform module bound to this agent instance")
          );
          const copyTfBtn = el("button", "secondary-btn sm-btn", "Copy HCL");
          copyTfBtn.type = "button";
          copyTfBtn.addEventListener("click", () => {
            if (navigator.clipboard) {
              navigator.clipboard.writeText(ev.terraform_paved_path_hcl || "");
            }
          });
          tfHead.appendChild(copyTfBtn);
          body.append(tfHead, el("pre", "code-block", ev.terraform_paved_path_hcl || ""));
        }
      )
    );

    // Nested Expander 3: Dynamic Guardrail Policy Payload (JSON)
    const polJson = JSON.stringify(ev.dynamic_guardrail_policy_preview || {}, null, 2);
    stack.appendChild(
      makeDeployExpander(
        "guardrail",
        "3. Dynamic Guardrail Policy Payload",
        `${tpl.sdp_pii_mode} | ${tpl.risk_tier}`,
        (body) => {
          const polHead = el("div", "toolbar-row");
          polHead.appendChild(
            el("span", "field-hint", "Compiled per-request Google Model Armor + Cloud SDP payload")
          );
          const copyPolBtn = el("button", "secondary-btn sm-btn", "Copy JSON");
          copyPolBtn.type = "button";
          copyPolBtn.addEventListener("click", () => {
            if (navigator.clipboard) {
              navigator.clipboard.writeText(polJson);
            }
          });
          polHead.appendChild(copyPolBtn);
          body.append(polHead, el("pre", "code-block", polJson));
        }
      )
    );

    // Nested Expander 4: 10-Component Cost & Consolidation Attribution
    stack.appendChild(
      makeDeployExpander(
        "costs",
        "4. 10-Component Cost & Consolidation Attribution",
        `${formatUsd(cEst.monthly_run_rate_usd)}/mo`,
        (body) => {
          body.appendChild(
            buildSortableComponentCostSubTable(
              cEst.component_costs || [],
              `10-Component Cost Attribution for ${tpl.agent_name}`,
              `deploy-sub-cost-${tpl.template_id}`
            )
          );
        }
      )
    );

    panel.appendChild(stack);
    td.appendChild(panel);
    expTr.appendChild(td);
    return expTr;
  }

  /* Govern Shared Fleet Deployments Audit & Cost Ledger Table */
  function buildDeploymentsTable(deps, captionText, paginationState, tableKey) {
    const pag = paginationState || state.governFleetPagination;
    const cols = [
      {
        key: "deployment_id",
        label: "Deployment ID",
        type: "string",
        filterType: "text",
        getValue: (d) => d.deployment_id,
      },
      {
        key: "deployed_at",
        label: "Deployed At",
        type: "date",
        filterType: "text",
        getValue: (d) => d.deployed_at || "",
        getFilterText: (d) => (d.deployed_at ? d.deployed_at.slice(0, 10) : ""),
      },
      {
        key: "agent_name",
        label: "Agent ID",
        type: "string",
        filterType: "text",
        getValue: (d) => d.agent_name,
      },
      {
        key: "business_unit_label",
        label: "Business Unit",
        type: "string",
        filterType: "select",
        getValue: (d) => d.business_unit_label || buLabel(d.business_unit),
      },
      {
        key: "risk_tier",
        label: tenantTerm("agency_tier_label", tenantTerm("risk_col_label", "Agency Tier")),
        type: "string",
        filterType: "select",
        options: [
          ["ag1", "ag1"],
          ["ag2", "ag2"],
          ["ag3", "ag3"],
          ["ag4", "ag4"],
          ["ag5", "ag5"],
        ],
        getValue: (d) => String(d.risk_tier || "AG2").toLowerCase(),
      },
      {
        key: "origin_label",
        label: "Template Profile",
        type: "string",
        filterType: "select",
        options: [
          ["Google Cloud", "Google Cloud"],
          ["Custom", "Custom"],
          ["Imported Manifest", "Imported Manifest"],
        ],
        getValue: (d) => ORIGIN_LABELS[d.origin] || d.origin,
      },
      {
        key: "final_eval_score",
        label: "Score (Init -> Final)",
        type: "number",
        filterType: "text",
        getValue: (d) => Number(d.final_eval_score ?? 0),
        getFilterText: (d) => `${d.initial_eval_score} -> ${d.final_eval_score}`,
      },
      {
        key: "monthly_run_rate_usd",
        label: "Monthly Run-Rate",
        type: "number",
        filterType: "text",
        getValue: (d) => Number(d.monthly_run_rate_usd ?? 0),
        getFilterText: (d) => formatUsd(d.monthly_run_rate_usd),
      },
      {
        key: "historical_cumulative_usd",
        label: "Cumulative Spend",
        type: "number",
        filterType: "text",
        getValue: (d) => Number(d.historical_cumulative_usd ?? 0),
        getFilterText: (d) => formatUsd(d.historical_cumulative_usd),
      },
    ];

    const processed = applyTableSortAndFilters(deps, cols, tableKey, "deployed_at", "desc");
    const totalPages = Math.max(1, Math.ceil(processed.length / pag.pageSize));
    if (pag.page > totalPages) {
      pag.page = totalPages;
    }
    const startIdx = (pag.page - 1) * pag.pageSize;
    const pagedDeps = processed.slice(startIdx, startIdx + pag.pageSize);

    const wrap = el("div", "table-wrap deferred-below-fold");
    const activeBanner = buildActiveFiltersBanner(tableKey, processed.length, deps.length, pag);
    if (activeBanner) {
      wrap.appendChild(activeBanner);
    }

    const tbl = el("table", "data-table");
    tbl.appendChild(el("caption", "", captionText));
    tbl.appendChild(
      buildInteractiveTableHead({
        tableKey,
        columns: cols,
        allRows: deps,
        defaultSortCol: "deployed_at",
        defaultSortDir: "desc",
        paginationState: pag,
      })
    );

    const tbody = el("tbody");
    pagedDeps.forEach((d) => {
      const isExp = state.expandedDeploymentId === d.deployment_id;
      const tr = el("tr", isExp ? "clickable-row is-expanded-parent" : "clickable-row");

      const toggleDep = () => {
        state.expandedDeploymentId = isExp ? null : d.deployment_id;
        renderStageBody();
      };

      const tdDep = el("td");
      const btn = el("button", "row-select-btn");
      btn.type = "button";
      btn.setAttribute("aria-expanded", isExp ? "true" : "false");
      btn.append(
        el("span", "row-chevron", isExp ? "\u25BE" : "\u25B8"),
        el("span", "", d.deployment_id)
      );
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        toggleDep();
      });
      tdDep.appendChild(btn);

      const depDate = d.deployed_at ? d.deployed_at.slice(0, 10) : "--";
      tr.appendChild(tdDep);
      tr.appendChild(el("td", "", depDate));
      tr.appendChild(el("td", "", d.agent_name));
      tr.appendChild(el("td", "", d.business_unit_label || buLabel(d.business_unit)));
      tr.appendChild(el("td", "", String(d.risk_tier).toLowerCase()));
      tr.appendChild(el("td", "", ORIGIN_LABELS[d.origin] || d.origin));
      tr.appendChild(el("td", "", `${d.initial_eval_score} -> ${d.final_eval_score}`));
      tr.appendChild(el("td", "", formatUsd(d.monthly_run_rate_usd)));
      tr.appendChild(el("td", "", formatUsd(d.historical_cumulative_usd)));
      tr.addEventListener("click", toggleDep);
      tbody.appendChild(tr);

      if (isExp) {
        const expTr = el("tr", "expanded-editor-row");
        const expTd = el("td", "expanded-editor-cell");
        expTd.colSpan = 9;
        const panel = el("div", "expanded-instance-panel");
        panel.appendChild(
          el(
            "p",
            "field-hint",
            `Approver: ${d.approver_principal} | Trace ID: ${d.trace_id} | Volume: ${d.estimated_monthly_turns_millions}M turns/mo`
          )
        );
        panel.appendChild(
          buildSortableComponentCostSubTable(
            d.component_costs || [],
            `10-Component Cost Attribution for ${d.agent_name}`,
            `${tableKey}-sub-${d.deployment_id}`
          )
        );
        expTd.appendChild(panel);
        expTr.appendChild(expTd);
        tbody.appendChild(expTr);
      }
    });
    tbl.appendChild(tbody);
    wrap.appendChild(tbl);
    wrap.appendChild(
      buildPaginationControls({
        totalItems: processed.length,
        paginationState: pag,
        navLabel: `${tableKey} pages`,
        idPrefix: tableKey,
      })
    );
    return wrap;
  }

  /* ------------------------------ 4. GOVERN ----------------------------- */
  function buildSegmentedPillRadios(groupLegend, radioName, currentValue, options, onChange) {
    const fs = el("fieldset", "segmented-radio-group");
    fs.appendChild(el("legend", "visually-hidden", groupLegend));
    fs.appendChild(el("span", "control-inline-label", `${groupLegend}:`));
    options.forEach(([val, labelTxt]) => {
      const rid = `seg-${radioName}-${String(val).replace(/[^a-zA-Z0-9_-]/g, "_")}`;
      const r = el("input", "segmented-radio-input");
      r.type = "radio";
      r.name = radioName;
      r.id = rid;
      r.value = String(val);
      r.checked = String(currentValue) === String(val);
      r.addEventListener("change", () => {
        if (r.checked) {
          onChange(val);
        }
      });
      const lbl = el("label", "segmented-radio-label", labelTxt);
      lbl.setAttribute("for", rid);
      fs.append(r, lbl);
    });
    return fs;
  }

  function makeExclusiveSubExpanderList(groupName, stateKey, defs) {
    const stack = el("div", "nested-expanders-stack");
    const siblings = [];
    defs.forEach(([subKey, titleText, pillText, buildBodyFn]) => {
      const det = el("details", "component-expander");
      det.setAttribute("name", groupName);
      det.dataset.subKey = subKey;
      if (state[stateKey] === subKey) {
        det.open = true;
      }
      const sum = el("summary", "component-expander-summary");
      sum.append(
        el("span", "expander-title-group", titleText),
        el("span", "expander-choice-pill", pillText)
      );
      const body = el("div", "component-expander-body");
      buildBodyFn(body);
      det.addEventListener("toggle", (ev) => {
        if (ev.target !== det) return;
        if (det.open) {
          state[stateKey] = subKey;
          siblings.forEach((other) => {
            if (other !== det && other.open) {
              other.open = false;
            }
          });
        }
      });
      det.append(sum, body);
      siblings.push(det);
      stack.appendChild(det);
    });
    return stack;
  }

  function renderGovernStage(root) {
    const headRow = el("div", "toolbar-row");
    headRow.appendChild(
      el("h1", "strip-title", "Platform Governance, Fleet Operations & FinOps")
    );
    const recerts = state.recertificationRecords || [];
    const dueOrExpCnt = recerts.filter(
      (r) => r.lifecycle_state === "DUE_SOON" || r.lifecycle_state === "EXPIRED" || r.activity_status === "INACTIVE"
    ).length;
    const recertJumpBtn = el(
      "button",
      "secondary-btn sm-btn",
      `Manage ADR-004 Recertification & Offboarding (${dueOrExpCnt} Action)`
    );
    recertJumpBtn.type = "button";
    recertJumpBtn.addEventListener("click", () => {
      state.activeGovernTab = "fleet";
      state.selectedGovernFleetSub = "recertification";
      renderStageBody();
    });
    headRow.appendChild(recertJumpBtn);
    root.appendChild(headRow);

    const aiglGovernBanner = el("div", "aigl-phase-strip surface-card");
    const govChips = el("div", "aigl-phase-chips");
    (state.aiglPhaseSpecs || []).slice(5, 7).forEach((ph) => {
      const chip = el("div", "aigl-phase-chip");
      chip.appendChild(el("strong", "", `AIGL Phase ${ph.phase}: ${ph.name}`));
      chip.appendChild(el("span", "field-hint", (ph.key_tasks || []).join(" | ")));
      govChips.appendChild(chip);
    });
    aiglGovernBanner.appendChild(govChips);
    root.appendChild(aiglGovernBanner);

    const rub = state.rubric;
    const m = state.operationsMetrics;
    const ec = state.executiveCosts;
    const curStatus = (state.agentState && state.agentState.status) || "ACTIVE";
    const capUsd =
      ((state.walletState && state.walletState.monthly_cap_nano_usd) || 15000000000) / 1e9;
    const rules = (rub && rub.rules) || [];
    const enabledRulesCnt = rules.filter((r) => r.enabled).length;
    const mandatoryRulesCnt = rules.filter((r) => r.enabled && r.mandatory).length;

    const domainDefs = [
      {
        id: "policies",
        stepTitle: "1. Policies & Rubric",
        marker: `>= ${rub ? rub.passing_score_threshold : 85} Gate`,
        caption: `${enabledRulesCnt} active rules (${mandatoryRulesCnt} mandatory gates) governing Evaluate & Deploy`,
        pill: `${enabledRulesCnt} Active Rules | Threshold >= ${rub ? rub.passing_score_threshold : 85}`,
        populate: populateGovernPoliciesBody,
      },
      {
        id: "fleet",
        stepTitle: "2. Fleet Operations",
        marker: `${m ? m.total_deployments : 0} Deployed`,
        caption: `${m ? m.remediated_prior_to_deploy_pct : 0}% remediated pre-deploy | +${
          m ? m.avg_score_uplift : 0
        } pts avg uplift`,
        pill: `${m ? m.total_deployments : 0} Fleet Deployments`,
        populate: populateGovernFleetBody,
      },
      {
        id: "finops",
        stepTitle: "3. FinOps & Economics",
        marker: `${ec ? formatUsd(ec.total_monthly_run_rate_usd) : "$0.00"}/mo`,
        caption: `${
          ec ? formatUsd(ec.projected_annual_consolidation_savings_usd) : "$0.00"
        }/yr consolidation savings`,
        pill: `${ec ? formatUsd(ec.total_historical_cumulative_usd) : "$0.00"} Cumulative`,
        populate: populateGovernFinopsBody,
      },
      {
        id: "controls",
        stepTitle: "4. Runtime Controls",
        marker: curStatus,
        caption: `Kill switch, $${capUsd.toFixed(2)} atomic ceiling, inline PII & 8 live checks`,
        pill: `Fleet ${curStatus} | Ceiling $${capUsd.toFixed(2)}`,
        populate: populateGovernControlsBody,
      },
    ];

    const domainStrip = el("ol", "four-tile-strip");
    domainStrip.setAttribute("aria-label", "Governance Domains");
    const tileBtnById = {};
    const domainDetById = {};

    const syncTileHighlight = (selectedId) => {
      Object.entries(tileBtnById).forEach(([id, btn]) => {
        const active = id === selectedId;
        btn.classList.toggle("is-selected", active);
        btn.setAttribute("aria-pressed", active ? "true" : "false");
      });
    };

    domainDefs.forEach((def) => {
      const li = el("li", "tile-list-item");
      const btn = el("button", "component-tile");
      btn.type = "button";
      btn.dataset.governDomain = def.id;
      if (def.id === "controls" && curStatus !== "ACTIVE") {
        btn.classList.add("tile-status-failed");
      }
      const isActive = state.activeGovernTab === def.id;
      btn.classList.toggle("is-selected", isActive);
      btn.setAttribute("aria-pressed", isActive ? "true" : "false");

      const top = el("span", "tile-top-header");
      top.append(
        el("span", "tile-functional-name", def.stepTitle),
        el("span", "tile-eval-marker", def.marker)
      );
      btn.append(top, el("span", "tile-impl-caption", def.caption));

      btn.addEventListener("click", () => {
        state.activeGovernTab = def.id;
        syncTileHighlight(def.id);
        const targetDet = domainDetById[def.id];
        if (targetDet) {
          targetDet.open = true;
        }
      });

      tileBtnById[def.id] = btn;
      li.appendChild(btn);
      domainStrip.appendChild(li);
    });
    root.appendChild(domainStrip);

    const expandersCard = el("div", "surface-card nested-expanders-card");
    const domainStack = el("div", "nested-expanders-stack");

    domainDefs.forEach((def) => {
      const det = el("details", "component-expander");
      det.setAttribute("name", "govern-domain-accordion");
      det.dataset.governDomain = def.id;
      if (state.activeGovernTab === def.id) {
        det.open = true;
      }

      const sum = el("summary", "component-expander-summary");
      const rightMeta = el("span", "expander-summary-right");
      rightMeta.appendChild(el("span", "expander-choice-pill", def.pill));
      if (def.id === "controls") {
        rightMeta.appendChild(
          el(
            "span",
            curStatus === "ACTIVE" ? "status-badge status-ok" : "status-badge status-err",
            curStatus
          )
        );
      }
      sum.append(el("span", "expander-title-group", def.stepTitle), rightMeta);

      const body = el("div", "component-expander-body");
      def.populate(body);

      det.addEventListener("toggle", (ev) => {
        if (ev.target !== det) return;
        if (det.open) {
          state.activeGovernTab = def.id;
          syncTileHighlight(def.id);
          Object.entries(domainDetById).forEach(([otherId, otherDet]) => {
            if (otherId !== def.id && otherDet.open) {
              otherDet.open = false;
            }
          });
        } else {
          const stillOpen = Object.entries(domainDetById).find(([, d]) => d.open);
          syncTileHighlight(stillOpen ? stillOpen[0] : null);
        }
      });

      det.append(sum, body);
      domainDetById[def.id] = det;
      domainStack.appendChild(det);
    });

    expandersCard.appendChild(domainStack);
    root.appendChild(expandersCard);
  }

  async function persistGovernanceRubric(threshInp) {
    if (!state.rubric) return;
    if (threshInp) {
      state.rubric.passing_score_threshold = Number(threshInp.value || 85);
    }
    try {
      const res = await apiPost("/api/ops/rubric", state.rubric);
      state.rubric = res.rubric;
      state.templates = res.templates;
      await refreshEvaluation(false);
      state.activeGovernTab = "policies";
      renderStageBody();
      showNotice(
        `Saved governance rubric (Passing threshold: >= ${state.rubric.passing_score_threshold}).`
      );
    } catch (err) {
      showError(err.message);
    }
  }

  function populateGovernPoliciesBody(panel) {
    if (!state.rubric) return;
    const rub = state.rubric;

    const threshForm = el("form", "surface-card inline-single-action-row");
    const threshGrp = el("div", "field-group");
    const threshLbl = el("label", "", "Passing Readiness Score Threshold (50 - 100)");
    threshLbl.setAttribute("for", "rubric-threshold-input");
    const threshInp = el("input");
    threshInp.type = "number";
    threshInp.id = "rubric-threshold-input";
    threshInp.name = "passing_score_threshold";
    threshInp.min = "50";
    threshInp.max = "100";
    threshInp.step = "0.5";
    threshInp.value = String(rub.passing_score_threshold);
    threshInp.addEventListener("change", () => {
      rub.passing_score_threshold = Number(threshInp.value || 85);
    });
    threshGrp.append(threshLbl, threshInp);

    const threshAct = el("div", "form-actions-end");
    const saveBtn = el("button", "primary-btn", "Save Governance Policies");
    saveBtn.type = "submit";
    threshAct.appendChild(saveBtn);
    threshForm.append(threshGrp, threshAct);
    threshForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      await persistGovernanceRubric(threshInp);
    });
    panel.appendChild(threshForm);

    const tableKey = "gov-policies";
    const cols = [
      {
        key: "rule_id",
        label: "Rule ID",
        type: "string",
        filterType: "text",
        getValue: (r) => r.rule_id,
      },
      {
        key: "capability",
        label: "Functional Capability",
        type: "string",
        filterType: "select",
        getValue: (r) => {
          const sp = state.slotById[r.slot_id];
          return sp ? sp.functional_name : r.slot_id;
        },
      },
      {
        key: "pillar",
        label: "Pillar / Workstream",
        type: "string",
        filterType: "select",
        options: [
          ["Control", "Control"],
          ["Intelligence", "Intelligence"],
          ["Economics", "Economics"],
          ["Experience", "Experience"],
        ],
        getValue: (r) => r.pillar,
        getFilterText: (r) => `${r.pillar} - ${r.workstream}`,
      },
      {
        key: "title",
        label: "Policy Requirement",
        type: "string",
        filterType: "text",
        getValue: (r) => r.title,
      },
      {
        key: "mandatory",
        label: "Gate Type",
        type: "string",
        filterType: "select",
        options: [
          ["Mandatory Gate", "Mandatory Gate"],
          ["Advisory", "Advisory"],
        ],
        getValue: (r) => (r.mandatory ? "Mandatory Gate" : "Advisory"),
      },
      {
        key: "weight_points",
        label: "Weight (Pts)",
        type: "number",
        filterType: "text",
        getValue: (r) => Number(r.weight_points || 0),
      },
      {
        key: "remediation_provider",
        label: "Default Fix Target",
        type: "string",
        filterType: "select",
        options: [
          ["google_gcp", gcpShortName()],
          ["cymbal_stack", customerShortName()],
        ],
        getValue: (r) => r.remediation_provider,
      },
      {
        key: "enabled",
        label: "Status",
        type: "string",
        filterType: "select",
        options: [
          ["Enabled", "Enabled"],
          ["Disabled", "Disabled"],
        ],
        getValue: (r) => (r.enabled ? "Enabled" : "Disabled"),
      },
    ];

    const processed = applyTableSortAndFilters(rub.rules, cols, tableKey, "rule_id", "asc");

    const wrap = el("div", "table-wrap");
    const activeBanner = buildActiveFiltersBanner(tableKey, processed.length, rub.rules.length, null);
    if (activeBanner) {
      wrap.appendChild(activeBanner);
    }

    const tbl = el("table", "data-table");
    tbl.appendChild(
      el(
        "caption",
        "",
        "Select any rule row to expand its gate policy, scoring weight, default remediation target, and requirement text."
      )
    );
    tbl.appendChild(
      buildInteractiveTableHead({
        tableKey,
        columns: cols,
        allRows: rub.rules,
        defaultSortCol: "rule_id",
        defaultSortDir: "asc",
        paginationState: null,
      })
    );

    const tbody = el("tbody");
    processed.forEach((rule) => {
      const isExp = state.expandedGovernRuleId === rule.rule_id;
      const spec = state.slotById[rule.slot_id];
      const capName = spec ? spec.functional_name : rule.slot_id;
      const tr = el(
        "tr",
        isExp ? "clickable-row is-active-agent-row is-expanded-parent" : "clickable-row"
      );

      const toggleRule = () => {
        state.activeGovernTab = "policies";
        state.expandedGovernRuleId = isExp ? null : rule.rule_id;
        renderStageBody();
      };

      const tdId = el("td");
      const selBtn = el("button", "row-select-btn");
      selBtn.type = "button";
      selBtn.setAttribute("aria-expanded", isExp ? "true" : "false");
      selBtn.append(
        el("span", "row-chevron", isExp ? "\u25BE" : "\u25B8"),
        el("span", "", rule.rule_id)
      );
      selBtn.addEventListener("click", (ev) => {
        ev.stopPropagation();
        toggleRule();
      });
      tdId.appendChild(selBtn);

      const tdGate = el("td");
      tdGate.appendChild(
        el(
          "span",
          rule.mandatory ? "status-badge status-err" : "status-badge status-warn",
          rule.mandatory ? "Mandatory Gate" : "Advisory"
        )
      );

      const tdTarget = el(
        "td",
        "",
        rule.remediation_provider === "google_gcp" ? gcpShortName() : customerShortName()
      );

      const tdStatus = el("td");
      tdStatus.appendChild(
        el(
          "span",
          rule.enabled ? "status-badge status-ok" : "status-badge status-draft",
          rule.enabled ? "Enabled" : "Disabled"
        )
      );

      tr.append(
        tdId,
        el("td", "", capName),
        el("td", "", `${rule.pillar} - ${rule.workstream}`),
        el("td", "", rule.title),
        tdGate,
        el("td", "", `${rule.weight_points} pts`),
        tdTarget,
        tdStatus
      );
      tr.addEventListener("click", toggleRule);
      tbody.appendChild(tr);

      if (isExp) {
        const expTr = el("tr", "expanded-editor-row");
        const expTd = el("td", "expanded-editor-cell");
        expTd.colSpan = 8;
        const editorPanel = el("div", "expanded-instance-panel");

        const topBar = el("div", "instance-toolbar");
        const leftMeta = el("div", "toolbar-left");
        leftMeta.append(
          el("span", "status-badge status-draft", `${rule.pillar} | ${capName}`),
          el(
            "span",
            "field-hint",
            spec ? `API Surface: ${spec.api_surface}` : rule.workstream
          )
        );

        const rightPills = el("div", "toolbar-right");
        rightPills.appendChild(
          buildSegmentedPillRadios(
            "Gate",
            `rule-mand-${rule.rule_id}`,
            rule.mandatory ? "true" : "false",
            [
              ["true", "Mandatory Gate"],
              ["false", "Advisory"],
            ],
            (val) => {
              rule.mandatory = val === "true";
            }
          )
        );
        rightPills.appendChild(
          buildSegmentedPillRadios(
            "Fix Target",
            `rule-prov-${rule.rule_id}`,
            rule.remediation_provider,
            [
              ["google_gcp", gcpShortName()],
              ["cymbal_stack", customerShortName()],
            ],
            (val) => {
              rule.remediation_provider = val;
            }
          )
        );
        rightPills.appendChild(
          buildSegmentedPillRadios(
            "Rule",
            `rule-en-${rule.rule_id}`,
            rule.enabled ? "true" : "false",
            [
              ["true", "Enabled"],
              ["false", "Disabled"],
            ],
            (val) => {
              rule.enabled = val === "true";
            }
          )
        );
        topBar.append(leftMeta, rightPills);
        editorPanel.appendChild(topBar);

        const gridTop = el("div", "form-grid-2");
        const titleGrp = el("div", "field-group");
        const titleId = `rule-title-${rule.rule_id}`;
        const titleLbl = el("label", "", "Policy Requirement Title");
        titleLbl.setAttribute("for", titleId);
        const titleInp = el("input");
        titleInp.type = "text";
        titleInp.id = titleId;
        titleInp.name = `${rule.rule_id}_title`;
        titleInp.value = rule.title || "";
        titleInp.addEventListener("input", () => {
          rule.title = titleInp.value;
        });
        titleGrp.append(titleLbl, titleInp);

        const wtGrp = el("div", "field-group");
        const wtId = `rule-wt-${rule.rule_id}`;
        const wtLbl = el("label", "", "Weight Points (1 - 40)");
        wtLbl.setAttribute("for", wtId);
        const wtInp = el("input");
        wtInp.type = "number";
        wtInp.id = wtId;
        wtInp.name = `${rule.rule_id}_weight`;
        wtInp.min = "1";
        wtInp.max = "40";
        wtInp.value = String(rule.weight_points);
        wtInp.addEventListener("change", () => {
          rule.weight_points = Number(wtInp.value || 10);
        });
        wtGrp.append(wtLbl, wtInp);
        gridTop.append(titleGrp, wtGrp);
        editorPanel.appendChild(gridTop);

        const gridBot = el("div", "form-grid-2");
        const descGrp = el("div", "field-group");
        const descId = `rule-desc-${rule.rule_id}`;
        const descLbl = el("label", "", "Policy Requirement Description");
        descLbl.setAttribute("for", descId);
        const descInp = el("input");
        descInp.type = "text";
        descInp.id = descId;
        descInp.name = `${rule.rule_id}_description`;
        descInp.value = rule.description || "";
        descInp.addEventListener("input", () => {
          rule.description = descInp.value;
        });
        descGrp.append(descLbl, descInp);

        const remGrp = el("div", "field-group");
        const remId = `rule-rem-${rule.rule_id}`;
        const remLbl = el("label", "", "Recommended Remediation Guidance");
        remLbl.setAttribute("for", remId);
        const remInp = el("input");
        remInp.type = "text";
        remInp.id = remId;
        remInp.name = `${rule.rule_id}_remediation`;
        remInp.value = rule.remediation_summary || "";
        remInp.addEventListener("input", () => {
          rule.remediation_summary = remInp.value;
        });
        remGrp.append(remLbl, remInp);
        gridBot.append(descGrp, remGrp);
        editorPanel.appendChild(gridBot);

        const actRow = el("div", "form-actions-end");
        const rowSaveBtn = el("button", "primary-btn sm-btn", "Save Rule & Rubric");
        rowSaveBtn.type = "button";
        rowSaveBtn.addEventListener("click", async () => {
          await persistGovernanceRubric(threshInp);
        });
        actRow.appendChild(rowSaveBtn);
        editorPanel.appendChild(actRow);

        expTd.appendChild(editorPanel);
        expTr.appendChild(expTd);
        tbody.appendChild(expTr);
      }
    });
    tbl.appendChild(tbody);
    wrap.appendChild(tbl);
    panel.appendChild(wrap);
  }

  function populateGovernFleetBody(panel) {
    const m = state.operationsMetrics;
    if (!m) return;

    const ob = m.origin_breakdown || {};
    const kpis = el("div", "kpi-grid-4");
    [
      [
        "Active Fleet Deployments",
        String(m.total_deployments),
        `${m.clean_first_pass_count} clean first-pass`,
      ],
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
        `${ob.google_gcp_standard || 0} Google Cloud | ${ob.custom_hybrid || 0} Custom`,
        `${ob.imported_manifest || 0} Imported Manifest`,
      ],
    ].forEach(([l, v, s], idx) => {
      const c = el("div", idx === 0 ? "surface-card hero-metric-card" : "surface-card");
      c.append(el("p", "kpi-label", l), el("p", "kpi-value", v), el("p", "kpi-sub", s));
      kpis.appendChild(c);
    });
    panel.appendChild(kpis);

    panel.appendChild(
      makeExclusiveSubExpanderList("govern-fleet-sub", "selectedGovernFleetSub", [
        [
          "adoption",
          "2.1 10-Capability Component Adoption",
          `${gcpShortName()} vs. ${customerShortName()}`,
          (subBody) => {
            const adoptKey = "gov-fleet-adoption";
            const adoptRows = m.component_adoption || [];
            const allDeps = m.deployments || [];
            const adoptCols = [
              {
                key: "functional_name",
                label: "Functional Capability",
                type: "string",
                filterType: "text",
                getValue: (r) => r.functional_name,
              },
              {
                key: "pillar",
                label: "Governance Pillar",
                type: "string",
                filterType: "select",
                getValue: (r) => r.pillar,
              },
              {
                key: "workstream",
                label: "Workstream",
                type: "string",
                filterType: "text",
                getValue: (r) => r.workstream,
              },
              {
                key: "cymbal_cnt",
                label: `${customerShortName()} Deployments`,
                type: "number",
                filterType: "text",
                getValue: (r) => Number(r.counts.cymbal_stack || 0),
                getFilterText: (r) => `${r.counts.cymbal_stack} ${r.provider_labels.cymbal_stack}`,
              },
              {
                key: "gcp_cnt",
                label: `${gcpShortName()} Deployments`,
                type: "number",
                filterType: "text",
                getValue: (r) => Number(r.counts.google_gcp || 0),
                getFilterText: (r) => `${r.counts.google_gcp} ${r.provider_labels.google_gcp}`,
              },
              {
                key: "google_gcp_pct",
                label: `${gcpShortName()} Share`,
                type: "number",
                filterType: "text",
                getValue: (r) => Number(r.google_gcp_pct || 0),
              },
            ];

            const processedAdopt = applyTableSortAndFilters(
              adoptRows,
              adoptCols,
              adoptKey,
              "google_gcp_pct",
              "desc"
            );

            const wrap = el("div", "table-wrap");
            const adoptBanner = buildActiveFiltersBanner(
              adoptKey,
              processedAdopt.length,
              adoptRows.length,
              null
            );
            if (adoptBanner) {
              wrap.appendChild(adoptBanner);
            }

            const tbl = el("table", "data-table");
            tbl.appendChild(
              el(
                "caption",
                "",
                `Select any functional capability row to inspect deployed agent component choices (${customerShortName()} vs. ${gcpShortName()}).`
              )
            );
            tbl.appendChild(
              buildInteractiveTableHead({
                tableKey: adoptKey,
                columns: adoptCols,
                allRows: adoptRows,
                defaultSortCol: "google_gcp_pct",
                defaultSortDir: "desc",
                paginationState: null,
              })
            );

            const tbody = el("tbody");
            processedAdopt.forEach((row) => {
              const isExp = state.expandedAdoptSlotId === row.slot_id;
              const tr = el(
                "tr",
                isExp ? "clickable-row is-active-agent-row is-expanded-parent" : "clickable-row"
              );

              const toggleAdopt = () => {
                state.activeGovernTab = "fleet";
                state.selectedGovernFleetSub = "adoption";
                state.expandedAdoptSlotId = isExp ? null : row.slot_id;
                renderStageBody();
              };

              const tdCap = el("td");
              const capBtn = el("button", "row-select-btn");
              capBtn.type = "button";
              capBtn.setAttribute("aria-expanded", isExp ? "true" : "false");
              capBtn.append(
                el("span", "row-chevron", isExp ? "\u25BE" : "\u25B8"),
                el("span", "", row.functional_name)
              );
              capBtn.addEventListener("click", (ev) => {
                ev.stopPropagation();
                toggleAdopt();
              });
              tdCap.appendChild(capBtn);

              tr.appendChild(tdCap);
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
              tr.addEventListener("click", toggleAdopt);
              tbody.appendChild(tr);

              if (isExp) {
                const expTr = el("tr", "expanded-editor-row");
                const expTd = el("td", "expanded-editor-cell");
                expTd.colSpan = 6;
                const subPanel = el("div", "expanded-instance-panel");

                const subKey = `gov-adopt-sub-${row.slot_id}`;
                const subSrc = allDeps.map((d) => {
                  const cEntry = (d.component_costs || []).find((c) => c.slot_id === row.slot_id);
                  const prov =
                    (d.component_choices && d.component_choices[row.slot_id]) ||
                    (cEntry && cEntry.provider) ||
                    "google_gcp";
                  return {
                    agent_name: d.agent_name,
                    deployed_at: d.deployed_at || "",
                    business_unit_label: d.business_unit_label,
                    provider: prov,
                    component_label:
                      (cEntry && cEntry.provider_label) ||
                      (row.provider_labels && row.provider_labels[prov]) ||
                      prov,
                    monthly_cost_usd: cEntry ? Number(cEntry.monthly_cost_usd || 0) : 0,
                  };
                });

                const subCols = [
                  {
                    key: "agent_name",
                    label: "Agent ID",
                    type: "string",
                    filterType: "text",
                    getValue: (x) => x.agent_name,
                  },
                  {
                    key: "deployed_at",
                    label: "Deployed At",
                    type: "date",
                    filterType: "text",
                    getValue: (x) => x.deployed_at,
                    getFilterText: (x) => (x.deployed_at ? x.deployed_at.slice(0, 10) : ""),
                  },
                  {
                    key: "business_unit_label",
                    label: "Business Unit",
                    type: "string",
                    filterType: "select",
                    getValue: (x) => x.business_unit_label,
                  },
                  {
                    key: "component_label",
                    label: "Selected Component",
                    type: "string",
                    filterType: "select",
                    getValue: (x) => x.component_label,
                  },
                  {
                    key: "provider",
                    label: "Provider Category",
                    type: "string",
                    filterType: "select",
                    options: [
                      ["google_gcp", gcpShortName()],
                      ["cymbal_stack", customerShortName()],
                    ],
                    getValue: (x) => x.provider,
                  },
                  {
                    key: "monthly_cost_usd",
                    label: "Component Run-Rate",
                    type: "number",
                    filterType: "text",
                    getValue: (x) => x.monthly_cost_usd,
                    getFilterText: (x) => formatUsd(x.monthly_cost_usd),
                  },
                ];

                const processedSub = applyTableSortAndFilters(
                  subSrc,
                  subCols,
                  subKey,
                  "deployed_at",
                  "desc"
                );
                const subWrap = el("div", "table-wrap");
                const subBan = buildActiveFiltersBanner(
                  subKey,
                  processedSub.length,
                  subSrc.length,
                  null
                );
                if (subBan) subWrap.appendChild(subBan);

                const subTbl = el("table", "data-table");
                subTbl.appendChild(
                  el("caption", "", `Deployed Agent Fleet Choices for ${row.functional_name}`)
                );
                subTbl.appendChild(
                  buildInteractiveTableHead({
                    tableKey: subKey,
                    columns: subCols,
                    allRows: subSrc,
                    defaultSortCol: "deployed_at",
                    defaultSortDir: "desc",
                    paginationState: null,
                  })
                );
                const stb = el("tbody");
                processedSub.forEach((x) => {
                  const r = el("tr");
                  r.appendChild(el("td", "", x.agent_name));
                  r.appendChild(el("td", "", x.deployed_at ? x.deployed_at.slice(0, 10) : "--"));
                  r.appendChild(el("td", "", x.business_unit_label));
                  r.appendChild(el("td", "", x.component_label));
                  const tdCat = el("td");
                  tdCat.appendChild(
                    el(
                      "span",
                      x.provider === "google_gcp"
                        ? "status-badge status-ok"
                        : "status-badge status-draft",
                      x.provider === "google_gcp" ? gcpShortName() : customerShortName()
                    )
                  );
                  r.appendChild(tdCat);
                  r.appendChild(el("td", "", formatUsd(x.monthly_cost_usd)));
                  stb.appendChild(r);
                });
                subTbl.appendChild(stb);
                subWrap.appendChild(subTbl);
                subPanel.appendChild(subWrap);
                expTd.appendChild(subPanel);
                expTr.appendChild(expTd);
                tbody.appendChild(expTr);
              }
            });
            tbl.appendChild(tbody);
            wrap.appendChild(tbl);
            subBody.appendChild(wrap);
          },
        ],
        [
          "auditlog",
          "2.2 Fleet Deployment Audit Log",
          `${m.total_deployments} Historical Deployments`,
          (subBody) => {
            subBody.appendChild(
              buildDeploymentsTable(
                m.deployments || [],
                "Fleet Deployment Audit Log - Sorted Newest-First (Select any row to expand component cost attribution)",
                state.governFleetPagination,
                "govern-fleet"
              )
            );
          },
        ],
        [
          "recertification",
          "2.3 Phase 7 Offboarding & ADR-004 90-Day Recertification",
          `${(state.recertificationRecords || []).length} Registered Agent(s)`,
          (subBody) => {
            const recs = state.recertificationRecords || [];
            const cntByState = { CURRENT: 0, DUE_SOON: 0, EXPIRED: 0, DECOMMISSIONED: 0 };
            let inactiveCnt = 0;
            recs.forEach((r) => {
              if (cntByState[r.lifecycle_state] !== undefined) {
                cntByState[r.lifecycle_state] += 1;
              }
              if (r.activity_status === "INACTIVE") {
                inactiveCnt += 1;
              }
            });

            const summaryStrip = el("div", "kpi-grid-4 recert-summary-strip");
            [
              ["Current (Active < 75d)", String(cntByState.CURRENT), "Identity enabled"],
              ["Due Soon (Day 75-89)", String(cntByState.DUE_SOON), "15d / 5d / 1d warnings"],
              ["Expired (Day 90+)", String(cntByState.EXPIRED), "Identity auto-disabled"],
              ["Inactive (>30d) / Decomm.", `${inactiveCnt} / ${cntByState.DECOMMISSIONED}`, "Offboarding candidates"],
            ].forEach(([l, v, s]) => {
              const c = el("div", "surface-card");
              c.append(el("p", "kpi-label", l), el("p", "kpi-value", v), el("p", "kpi-sub", s));
              summaryStrip.appendChild(c);
            });
            subBody.appendChild(summaryStrip);

            const wrap = el("div", "table-wrap");
            const tbl = el("table", "data-table");
            tbl.appendChild(
              el(
                "caption",
                "",
                "ADR-004 90-Day Recertification & AIGL Phase 7 Offboarding Queue (Select any row to recertify, advance timer, expire, or decommission)"
              )
            );
            const thead = el("thead");
            const hRow = el("tr");
            [
              "Agent ID",
              "Owner",
              "Activity",
              "Lifecycle State",
              "Alert Stage",
              "Identity",
              "Cycle / Remaining",
              "Next Review",
            ].forEach((lbl) => {
              const th = el("th", "", lbl);
              th.scope = "col";
              hRow.appendChild(th);
            });
            thead.appendChild(hRow);
            tbl.appendChild(thead);

            const tbody = el("tbody");
            recs.forEach((rec) => {
              const isExp = state.expandedRecertAgentId === rec.agent_id;
              const tr = el("tr", isExp ? "clickable-row is-expanded-parent" : "clickable-row");
              const toggleRec = () => {
                state.activeGovernTab = "fleet";
                state.selectedGovernFleetSub = "recertification";
                state.expandedRecertAgentId = isExp ? null : rec.agent_id;
                renderStageBody();
              };

              const tdId = el("td");
              const selBtn = el("button", "row-select-btn");
              selBtn.type = "button";
              selBtn.setAttribute("aria-expanded", isExp ? "true" : "false");
              selBtn.append(
                el("span", "row-chevron", isExp ? "\u25BE" : "\u25B8"),
                el("span", "", rec.agent_id)
              );
              selBtn.addEventListener("click", (e) => {
                e.stopPropagation();
                toggleRec();
              });
              tdId.appendChild(selBtn);

              const tdAct = el("td");
              tdAct.appendChild(
                el(
                  "span",
                  rec.activity_status === "ACTIVE" ? "status-badge status-ok" : "status-badge status-warn",
                  rec.activity_status
                )
              );

              const tdLife = el("td");
              const lifeCls =
                rec.lifecycle_state === "CURRENT"
                  ? "status-badge status-ok"
                  : rec.lifecycle_state === "DUE_SOON"
                  ? "status-badge status-warn"
                  : rec.lifecycle_state === "EXPIRED"
                  ? "status-badge status-err"
                  : "status-badge status-draft";
              tdLife.appendChild(el("span", lifeCls, rec.lifecycle_state));

              const tdIdent = el("td");
              tdIdent.appendChild(
                el(
                  "span",
                  rec.identity_enabled ? "status-badge status-ok" : "status-badge status-err",
                  rec.identity_enabled ? "ENABLED" : "DISABLED"
                )
              );

              tr.append(
                tdId,
                el("td", "", rec.owner_team || "--"),
                tdAct,
                tdLife,
                el("td", "", rec.alert_stage || "NONE"),
                tdIdent,
                el("td", "", `Day ${rec.cycle_day} (${rec.days_remaining}d left)`),
                el("td", "", rec.next_review_date || "--")
              );
              tr.addEventListener("click", toggleRec);
              tbody.appendChild(tr);

              if (isExp) {
                const expTr = el("tr", "expanded-editor-row");
                const expTd = el("td", "expanded-editor-cell");
                expTd.colSpan = 8;
                const expPanel = el("div", "expanded-instance-panel");
                expPanel.appendChild(
                  el(
                    "p",
                    "field-hint",
                    `${rec.description || ""} | Owner: ${rec.owner_email || ""} | Last LLM: ${rec.days_since_last_llm_call}d ago | Last A2A: ${rec.days_since_last_a2a_message}d ago`
                  )
                );

                const scopeSet = new Set(rec.current_scopes || []);
                const scopeRow = el("div", "toolbar-left");
                scopeRow.appendChild(el("strong", "", "Scopes:"));
                const scopeChecks = {};
                (rec.current_scopes || []).forEach((sc) => {
                  const lbl = el("label", "offline-toggle-label");
                  const chk = el("input");
                  chk.type = "checkbox";
                  chk.checked = true;
                  scopeChecks[sc] = chk;
                  lbl.append(chk, el("span", "", sc));
                  scopeRow.appendChild(lbl);
                });
                if (scopeSet.size === 0) {
                  scopeRow.appendChild(el("span", "field-hint", "No active scopes (revoked)"));
                }
                expPanel.appendChild(scopeRow);

                const btnRow = el("div", "toolbar-left");
                const recertBtn = el("button", "primary-btn sm-btn", "Recertify (Reset 90-Day Timer)");
                recertBtn.type = "button";
                recertBtn.addEventListener("click", async () => {
                  const confirmed = Object.keys(scopeChecks).filter((k) => scopeChecks[k].checked);
                  const removed = Object.keys(scopeChecks).filter((k) => !scopeChecks[k].checked);
                  try {
                    const res = await apiPost(
                      `/api/govern/recertification/${encodeURIComponent(rec.agent_id)}/recertify`,
                      {
                        scopes_confirmed: confirmed,
                        scopes_removed: removed,
                        certified_by: rec.owner_email || "platform-owner@cymbal.example",
                      }
                    );
                    state.recertificationRecords = res.records || [];
                    renderStageBody();
                    showNotice(`Recertified '${rec.agent_id}'; 90-day ADR-004 timer reset.`);
                  } catch (err) {
                    showError(err.message);
                  }
                });

                [
                  ["Sim Day 75", 75, null],
                  ["Sim Day 85", 85, null],
                  ["Sim Day 89", 89, null],
                  ["Sim Day 90 (Expire)", 90, null],
                  ["Sim Inactive (>30d)", Math.max(rec.cycle_day || 0, 45), 35],
                ].forEach(([lbl, cDay, inact]) => {
                  const simBtn = el("button", "secondary-btn sm-btn", lbl);
                  simBtn.type = "button";
                  simBtn.addEventListener("click", async () => {
                    try {
                      const res = await apiPost(
                        `/api/govern/recertification/${encodeURIComponent(rec.agent_id)}/advance-timer`,
                        { cycle_day: cDay, days_since_activity: inact }
                      );
                      state.recertificationRecords = res.records || [];
                      renderStageBody();
                    } catch (err) {
                      showError(err.message);
                    }
                  });
                  btnRow.appendChild(simBtn);
                });

                const expBtn = el("button", "secondary-btn sm-btn", "Expire Identity (Day 90)");
                expBtn.type = "button";
                expBtn.addEventListener("click", async () => {
                  try {
                    const res = await apiPost(
                      `/api/govern/recertification/${encodeURIComponent(rec.agent_id)}/expire`,
                      { reason: "Missed ADR-004 90-day recertification deadline" }
                    );
                    state.recertificationRecords = res.records || [];
                    renderStageBody();
                    showNotice(`Expired '${rec.agent_id}'; Agent Identity disabled.`);
                  } catch (err) {
                    showError(err.message);
                  }
                });

                const offBtn = el("button", "danger-btn sm-btn", "Offboard & Transfer Ownership");
                offBtn.type = "button";
                offBtn.addEventListener("click", async () => {
                  try {
                    const res = await apiPost(
                      `/api/govern/recertification/${encodeURIComponent(rec.agent_id)}/offboard`,
                      {
                        actor: rec.owner_email || "platform-owner@cymbal.example",
                        transfer_owner: "archived-platform-steward",
                      }
                    );
                    state.recertificationRecords = res.records || [];
                    if (res.operations_metrics) {
                      state.operationsMetrics = res.operations_metrics;
                    }
                    renderStageBody();
                    showNotice(`Offboarded '${rec.agent_id}' and transferred ownership to archived-platform-steward.`);
                  } catch (err) {
                    showError(err.message);
                  }
                });

                const actBar = el("div", "toolbar-row");
                const primaryActs = el("div", "toolbar-left");
                primaryActs.append(recertBtn, expBtn, offBtn);
                actBar.append(primaryActs, btnRow);
                expPanel.appendChild(actBar);

                if (rec.audit_log && rec.audit_log.length > 0) {
                  const logPre = el(
                    "pre",
                    "code-block",
                    rec.audit_log
                      .map((entry) => `[${entry.timestamp || ""}] ${entry.action}: ${entry.detail}`)
                      .join("\n")
                  );
                  expPanel.appendChild(logPre);
                }

                expTd.appendChild(expPanel);
                expTr.appendChild(expTd);
                tbody.appendChild(expTr);
              }
            });

            tbl.appendChild(tbody);
            wrap.appendChild(tbl);
            subBody.appendChild(wrap);
          },
        ],
      ])
    );
  }

  function populateGovernFinopsBody(panel) {
    const ec = state.executiveCosts;
    if (!ec) return;

    const kpis = el("div", "kpi-grid-4");
    [
      [
        "Historical Cumulative Spend",
        formatUsd(ec.total_historical_cumulative_usd),
        `${ec.deployment_count} deployments`,
      ],
      [
        "Current Monthly Run-Rate",
        formatUsd(ec.total_monthly_run_rate_usd),
        `Avg ${formatUsd(ec.avg_cost_per_deployment_monthly_usd)} / agent`,
      ],
      [
        "Projected Annual Run-Rate",
        formatUsd(ec.projected_annual_run_rate_usd),
        "12-month annualized",
      ],
      [
        "Annual Consolidation Savings",
        formatUsd(ec.projected_annual_consolidation_savings_usd),
        `vs. 100% ${customerShortName()} baseline`,
      ],
    ].forEach(([l, v, s], idx) => {
      const c = el("div", idx === 0 ? "surface-card hero-metric-card" : "surface-card");
      c.append(el("p", "kpi-label", l), el("p", "kpi-value", v), el("p", "kpi-sub", s));
      kpis.appendChild(c);
    });
    panel.appendChild(kpis);

    panel.appendChild(
      makeExclusiveSubExpanderList("govern-finops-sub", "selectedGovernFinopsSub", [
        [
          "attribution",
          "3.1 Pillar & 10-Component Spend Attribution",
          "4 Pillars | 10 Capabilities",
          (subBody) => {
            const pillarGrid = el("div", "kpi-grid-4");
            (ec.pillar_cost_rollup || []).forEach((p) => {
              const c = el("div", "surface-card");
              c.append(
                el("p", "kpi-label", `${p.pillar} Pillar Spend`),
                el("p", "kpi-value", formatUsd(p.historical_cumulative_usd)),
                el(
                  "p",
                  "kpi-sub",
                  `${formatUsd(p.monthly_run_rate_usd)}/mo (${p.share_of_total_pct}% share)`
                )
              );
              pillarGrid.appendChild(c);
            });
            subBody.appendChild(pillarGrid);

            const compKey = "gov-finops-comps";
            const compRows = ec.component_cost_rollup || [];
            const compCols = [
              {
                key: "functional_name",
                label: "Functional Component",
                type: "string",
                filterType: "text",
                getValue: (c) => c.functional_name,
              },
              {
                key: "pillar",
                label: "Pillar",
                type: "string",
                filterType: "select",
                getValue: (c) => c.pillar,
              },
              {
                key: "cymbal_spend",
                label: `${customerShortName()} Spend`,
                type: "number",
                filterType: "text",
                getValue: (c) => Number(c.spend_by_provider_usd.cymbal_stack || 0),
                getFilterText: (c) => formatUsd(c.spend_by_provider_usd.cymbal_stack),
              },
              {
                key: "gcp_spend",
                label: `${gcpShortName()} Spend`,
                type: "number",
                filterType: "text",
                getValue: (c) => Number(c.spend_by_provider_usd.google_gcp || 0),
                getFilterText: (c) => formatUsd(c.spend_by_provider_usd.google_gcp),
              },
              {
                key: "monthly_run_rate_usd",
                label: "Monthly Run-Rate",
                type: "number",
                filterType: "text",
                getValue: (c) => Number(c.monthly_run_rate_usd || 0),
                getFilterText: (c) => formatUsd(c.monthly_run_rate_usd),
              },
              {
                key: "historical_cumulative_usd",
                label: "Historical Total",
                type: "number",
                filterType: "text",
                getValue: (c) => Number(c.historical_cumulative_usd || 0),
                getFilterText: (c) => formatUsd(c.historical_cumulative_usd),
              },
              {
                key: "share_of_total_pct",
                label: "Share",
                type: "number",
                filterType: "text",
                getValue: (c) => Number(c.share_of_total_pct || 0),
              },
            ];

            const processedComps = applyTableSortAndFilters(
              compRows,
              compCols,
              compKey,
              "historical_cumulative_usd",
              "desc"
            );

            const compWrap = el("div", "table-wrap");
            const compBanner = buildActiveFiltersBanner(
              compKey,
              processedComps.length,
              compRows.length,
              null
            );
            if (compBanner) {
              compWrap.appendChild(compBanner);
            }

            const compTbl = el("table", "data-table");
            compTbl.appendChild(
              el(
                "caption",
                "",
                "Aggregate Historical Spend Across All 10 Functional Components (Select any row to expand top contributing agents)"
              )
            );
            compTbl.appendChild(
              buildInteractiveTableHead({
                tableKey: compKey,
                columns: compCols,
                allRows: compRows,
                defaultSortCol: "historical_cumulative_usd",
                defaultSortDir: "desc",
                paginationState: null,
              })
            );

            const cbody = el("tbody");
            processedComps.forEach((comp) => {
              const isExp = state.expandedFinopsSlotId === comp.slot_id;
              const tr = el("tr", isExp ? "clickable-row is-expanded-parent" : "clickable-row");

              const toggleComp = () => {
                state.activeGovernTab = "finops";
                state.selectedGovernFinopsSub = "attribution";
                state.expandedFinopsSlotId = isExp ? null : comp.slot_id;
                renderStageBody();
              };

              const tdName = el("td");
              const btn = el("button", "row-select-btn");
              btn.type = "button";
              btn.setAttribute("aria-expanded", isExp ? "true" : "false");
              btn.append(
                el("span", "row-chevron", isExp ? "\u25BE" : "\u25B8"),
                el("span", "", comp.functional_name)
              );
              btn.addEventListener("click", (e) => {
                e.stopPropagation();
                toggleComp();
              });
              tdName.appendChild(btn);

              tr.appendChild(tdName);
              tr.appendChild(el("td", "", comp.pillar));
              tr.appendChild(el("td", "", formatUsd(comp.spend_by_provider_usd.cymbal_stack)));
              tr.appendChild(el("td", "", formatUsd(comp.spend_by_provider_usd.google_gcp)));
              tr.appendChild(el("td", "", formatUsd(comp.monthly_run_rate_usd)));
              tr.appendChild(el("td", "", formatUsd(comp.historical_cumulative_usd)));
              tr.appendChild(el("td", "", `${comp.share_of_total_pct}%`));
              tr.addEventListener("click", toggleComp);
              cbody.appendChild(tr);

              if (isExp) {
                const expTr = el("tr", "expanded-editor-row");
                const expTd = el("td", "expanded-editor-cell");
                expTd.colSpan = 7;
                const subPanel = el("div", "expanded-instance-panel");
                subPanel.appendChild(
                  el("p", "field-hint", `${comp.workstream} | Consolidates: ${comp.consolidates}`)
                );

                const topSubKey = `finops-sub-${comp.slot_id}`;
                const topSrc = comp.top_deployments || [];
                const topCols = [
                  {
                    key: "agent_name",
                    label: "Agent ID",
                    type: "string",
                    filterType: "text",
                    getValue: (d) => d.agent_name,
                  },
                  {
                    key: "business_unit_label",
                    label: "Business Unit",
                    type: "string",
                    filterType: "select",
                    getValue: (d) => d.business_unit_label,
                  },
                  {
                    key: "provider_label",
                    label: "Selected Component",
                    type: "string",
                    filterType: "text",
                    getValue: (d) =>
                      (comp.provider_labels && comp.provider_labels[d.provider]) || d.provider,
                  },
                  {
                    key: "historical_cumulative_usd",
                    label: "Cumulative Spend",
                    type: "number",
                    filterType: "text",
                    getValue: (d) => Number(d.historical_cumulative_usd || 0),
                    getFilterText: (d) => formatUsd(d.historical_cumulative_usd),
                  },
                ];
                const processedTop = applyTableSortAndFilters(
                  topSrc,
                  topCols,
                  topSubKey,
                  "historical_cumulative_usd",
                  "desc"
                );

                const subWrap = el("div", "table-wrap");
                const subBanner = buildActiveFiltersBanner(
                  topSubKey,
                  processedTop.length,
                  topSrc.length,
                  null
                );
                if (subBanner) {
                  subWrap.appendChild(subBanner);
                }
                const subTbl = el("table", "data-table");
                subTbl.appendChild(
                  el("caption", "", `Top Contributing Agent Deployments for ${comp.functional_name}`)
                );
                subTbl.appendChild(
                  buildInteractiveTableHead({
                    tableKey: topSubKey,
                    columns: topCols,
                    allRows: topSrc,
                    defaultSortCol: "historical_cumulative_usd",
                    defaultSortDir: "desc",
                    paginationState: null,
                  })
                );

                const stb = el("tbody");
                processedTop.forEach((d) => {
                  const r = el("tr");
                  r.appendChild(el("td", "", d.agent_name));
                  r.appendChild(el("td", "", d.business_unit_label));
                  r.appendChild(
                    el(
                      "td",
                      "",
                      (comp.provider_labels && comp.provider_labels[d.provider]) || d.provider
                    )
                  );
                  r.appendChild(el("td", "", formatUsd(d.historical_cumulative_usd)));
                  stb.appendChild(r);
                });
                subTbl.appendChild(stb);
                subWrap.appendChild(subTbl);
                subPanel.appendChild(subWrap);
                expTd.appendChild(subPanel);
                expTr.appendChild(expTd);
                cbody.appendChild(expTr);
              }
            });
            compTbl.appendChild(cbody);
            compWrap.appendChild(compTbl);
            subBody.appendChild(compWrap);
          },
        ],
        [
          "ledger",
          "3.2 Per-Agent Deployment Cost Ledger",
          `${ec.deployment_count} Deployed Agents`,
          (subBody) => {
            subBody.appendChild(
              buildDeploymentsTable(
                ec.deployments || [],
                "Per-Agent Deployment Cost Ledger - Sorted Newest-First (Select any row to expand 10-component cost attribution)",
                state.governFinopsPagination,
                "govern-finops"
              )
            );
          },
        ],
        [
          "simulator",
          "3.3 Guardrail Scale Economics Simulator (1M - 50M Daily Turns)",
          "Model Armor Tier-0",
          (subBody) => {
            const tcoForm = el("form", "inline-single-action-row");
            const turnsGrp = el("div", "field-group");
            const turnsLbl = el("label", "", "Daily Fleet Turns");
            turnsLbl.setAttribute("for", "tco-daily-turns-select");
            const turnsSel = el("select");
            turnsSel.id = "tco-daily-turns-select";
            turnsSel.name = "daily_turns";
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

            const tcoAct = el("div", "form-actions-end");
            const calcBtn = el("button", "primary-btn", "Recalculate Scale Model");
            calcBtn.type = "submit";
            tcoAct.appendChild(calcBtn);
            tcoForm.append(turnsGrp, tcoAct);
            tcoForm.addEventListener("submit", async (e) => {
              e.preventDefault();
              calcBtn.disabled = true;
              try {
                state.tcoReport = await apiPost("/api/steward/tco", {
                  daily_turns: Number(turnsSel.value),
                  tokens_per_turn: 1000,
                });
                state.selectedGovernFinopsSub = "simulator";
                renderStageBody();
              } catch (err) {
                showError(err.message);
              } finally {
                calcBtn.disabled = false;
              }
            });
            subBody.appendChild(tcoForm);

            if (state.tcoReport) {
              const t = state.tcoReport;
              const tGrid = el("div", "kpi-grid-4");
              [
                [
                  "Google Model Armor Tier-0 Annual",
                  formatUsd(t.google_model_armor_annual_usd),
                  "$0.10 / 1M tokens",
                ],
                [
                  "Tier-0 + 20% Ensemble Hybrid",
                  formatUsd(t.ensemble_tier0_hybrid_annual_usd),
                  "100% Tier-0 pre-filter + 20% secondary escalation",
                ],
                [
                  "Legacy Guardrail List Baseline",
                  formatUsd(t.azure_content_safety_annual_usd),
                  "$1.00 / 1K text records benchmark",
                ],
                [
                  "Standalone Savings (Model Armor)",
                  formatUsd(t.annual_savings_vs_azure_usd),
                  `${t.pct_reduction_vs_azure}% reduction vs. baseline`,
                ],
              ].forEach(([l, v, s], idx) => {
                const c = el("div", idx === 3 ? "surface-card hero-metric-card" : "surface-card");
                c.append(el("p", "kpi-label", l), el("p", "kpi-value", v), el("p", "kpi-sub", s));
                tGrid.appendChild(c);
              });
              subBody.appendChild(tGrid);

              const savGrid = el("div", "split-2-col");
              const cStd = el("div", "surface-card");
              cStd.append(
                el("p", "kpi-label", "Standalone Model Armor Savings vs. Azure Content Safety"),
                el("p", "kpi-value", `${formatUsd(t.annual_savings_vs_azure_usd)} / yr`),
                el(
                  "p",
                  "kpi-sub",
                  `${t.pct_reduction_vs_azure}% reduction (${formatUsd(t.google_model_armor_annual_usd)} vs. ${formatUsd(t.azure_content_safety_annual_usd)})`
                )
              );
              const cEns = el("div", "surface-card hero-metric-card");
              cEns.append(
                el("p", "kpi-label", "Ensemble Tier-0 Hybrid Savings (100% Pre-Filter + 20% Escalation)"),
                el("p", "kpi-value", `${formatUsd(t.ensemble_annual_savings_vs_azure_usd)} / yr`),
                el(
                  "p",
                  "kpi-sub",
                  `${t.ensemble_pct_reduction_vs_azure}% reduction (${formatUsd(t.ensemble_tier0_hybrid_annual_usd)} vs. ${formatUsd(t.azure_content_safety_annual_usd)})`
                )
              );
              savGrid.append(cStd, cEns);
              subBody.appendChild(savGrid);
            }
          },
        ],
      ])
    );
  }

  function populateGovernControlsBody(panel) {
    const curStatus = (state.agentState && state.agentState.status) || "ACTIVE";
    const spentUsd = ((state.walletState && state.walletState.spent_nano_usd) || 0) / 1e9;
    const capUsd =
      ((state.walletState && state.walletState.monthly_cap_nano_usd) || 15000000000) / 1e9;
    const passedProofsCnt = state.proofResults.filter((p) => p.passed).length;

    panel.appendChild(
      makeExclusiveSubExpanderList("govern-controls-sub", "selectedGovernControlsSub", [
        [
          "killswitch",
          "4.1 Global Containment, Atomic Budget & ADR-011 OBO",
          `State: ${curStatus} | Ceiling: $${capUsd.toFixed(2)}`,
          (subBody) => {
            const topBar = el("div", "instance-toolbar");
            const leftStatus = el("div", "toolbar-left");
            leftStatus.appendChild(
              el(
                "span",
                curStatus === "ACTIVE" ? "status-badge status-ok" : "status-badge status-err",
                `Fleet Runtime State: ${curStatus}`
              )
            );
            leftStatus.appendChild(
              el("span", "field-hint", "Enforced pre-inference across all ADK 2.0 runtime endpoints")
            );

            const killRadios = buildSegmentedPillRadios(
              "Kill Switch",
              "global-kill-switch-state",
              curStatus,
              [
                ["ACTIVE", "ACTIVE"],
                ["PAUSED", "PAUSED"],
                ["DISABLED", "DISABLED"],
              ],
              async (nextSt) => {
                try {
                  const res = await apiPost("/api/steward/kill-switch", { status: nextSt });
                  state.agentState = res.agent_state;
                  state.activeGovernTab = "controls";
                  state.selectedGovernControlsSub = "killswitch";
                  renderStageBody();
                } catch (err) {
                  showError(err.message);
                }
              }
            );
            topBar.append(leftStatus, killRadios);
            subBody.appendChild(topBar);

            const capForm = el("form", "inline-single-action-row");
            const capGrp = el("div", "field-group");
            const capLbl = el(
              "label",
              "",
              `Atomic Budget Ceiling USD (Current Spend: $${spentUsd.toFixed(6)})`
            );
            capLbl.setAttribute("for", "wallet-cap-usd-input");
            const capInp = el("input");
            capInp.type = "number";
            capInp.id = "wallet-cap-usd-input";
            capInp.name = "monthly_cap_usd";
            capInp.step = "0.01";
            capInp.min = "0";
            capInp.value = String(capUsd);
            capGrp.append(capLbl, capInp);

            const capBtns = el("div", "form-actions-end");
            const oboBtn = el("button", "secondary-btn", "Verify OBO Token Pair (ADR-011)");
            oboBtn.type = "button";
            oboBtn.addEventListener("click", async () => {
              try {
                state.lastOboResult = await apiPost("/api/steward/obo-verify", {});
                state.activeGovernTab = "controls";
                state.selectedGovernControlsSub = "killswitch";
                renderStageBody();
              } catch (err) {
                showError(err.message);
              }
            });

            const updCapBtn = el("button", "primary-btn", "Update Ceiling");
            updCapBtn.type = "submit";
            capBtns.append(oboBtn, updCapBtn);
            capForm.append(capGrp, capBtns);

            capForm.addEventListener("submit", async (e) => {
              e.preventDefault();
              updCapBtn.disabled = true;
              try {
                const nano = Math.round(Number(capInp.value || 0) * 1e9);
                const r = await apiPost("/api/steward/wallet-cap", {
                  monthly_cap_nano_usd: nano,
                  reset_spend: false,
                });
                state.walletState = r.wallet_state;
                state.activeGovernTab = "controls";
                state.selectedGovernControlsSub = "killswitch";
                renderStageBody();
              } catch (err) {
                showError(err.message);
              } finally {
                updCapBtn.disabled = false;
              }
            });
            subBody.appendChild(capForm);

            if (state.lastOboResult) {
              subBody.appendChild(
                el(
                  "pre",
                  "code-block",
                  JSON.stringify(state.lastOboResult.adr011_valid_pair, null, 2)
                )
              );
            }
          },
        ],
        [
          "guardrail",
          "4.2 Dynamic Guardrail & Inline PII Policy Tester",
          "Google Model Armor + Cloud SDP",
          (subBody) => {
            const guardForm = el("form", "form-stack");
            const gTxtGrp = el("div", "field-group");
            const gLbl = el("label", "", "Inspection Input Payload");
            gLbl.setAttribute("for", "guardrail-test-input");
            const gTxt = el("textarea");
            gTxt.id = "guardrail-test-input";
            gTxt.name = "sample_text";
            gTxt.rows = 3;
            gTxt.value = "Subscriber log check: SSN 123-45-6789 on gateway MAC aa:bb:cc:dd:ee:ff";
            gTxtGrp.append(gLbl, gTxt);

            const modeRow = el("div", "inline-single-action-row");
            const gModeGrp = el("div", "field-group");
            const gModeLbl = el("label", "", "PII Enforcement Mode");
            gModeLbl.setAttribute("for", "guardrail-sdp-select");
            const gModeSel = el("select");
            gModeSel.id = "guardrail-sdp-select";
            gModeSel.name = "sdp_pii_mode";
            [
              ["DEIDENTIFY_INLINE", "DEIDENTIFY_INLINE (Mask PII & Continue)"],
              ["BLOCK_ON_MATCH", "BLOCK_ON_MATCH (Strict Regional Block)"],
            ].forEach(([val, txt]) => {
              const o = el("option", "", txt);
              o.value = val;
              gModeSel.appendChild(o);
            });
            gModeGrp.append(gModeLbl, gModeSel);

            const gAct = el("div", "form-actions-end");
            const gRunBtn = el("button", "primary-btn", "Inspect Payload");
            gRunBtn.type = "submit";
            gAct.appendChild(gRunBtn);
            modeRow.append(gModeGrp, gAct);
            guardForm.append(gTxtGrp, modeRow);

            guardForm.addEventListener("submit", async (e) => {
              e.preventDefault();
              gRunBtn.disabled = true;
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
                state.activeGovernTab = "controls";
                state.selectedGovernControlsSub = "guardrail";
                renderStageBody();
              } catch (err) {
                showError(err.message);
              } finally {
                gRunBtn.disabled = false;
              }
            });
            subBody.appendChild(guardForm);

            if (state.lastGuardrailVerdict) {
              const gv = state.lastGuardrailVerdict;
              subBody.appendChild(
                el(
                  "span",
                  gv.allowed ? "status-badge status-ok" : "status-badge status-err",
                  `${gv.action_taken} (${gv.latency_ms}ms)`
                )
              );
              subBody.appendChild(el("pre", "code-block", gv.sanitized_text));
            }
          },
        ],
        [
          "proofs",
          "4.3 Live Control Plane Verification Checks (8)",
          state.proofResults.length > 0
            ? `${passedProofsCnt}/${state.proofResults.length} Passed`
            : "8 Runtime Checks",
          (subBody) => {
            const pHead = el("div", "toolbar-row");
            pHead.appendChild(
              el(
                "span",
                "field-hint",
                "Execute live assertions across SPIFFE, UAP CEL, Atomic Wallet, Model Armor SDP, gVisor, Memory Bank, and Eval gates."
              )
            );
            const streamBox = el("div", "stream-progress-panel");
            streamBox.id = "proofs-stream-progress";
            streamBox.setAttribute("aria-live", "polite");
            streamBox.hidden = true;

            const runAllBtn = el("button", "primary-btn sm-btn", "Run All 8 Verification Checks");
            runAllBtn.type = "button";
            runAllBtn.addEventListener("click", async () => {
              runAllBtn.disabled = true;
              try {
                const res = await runWithLiveStepper(streamBox, {
                  title: "Running 8 Modular Coexistence Verification Checks",
                  totalSteps: 8,
                  runnerFn: (onStep) => apiPostStream("/api/steward/proofs-all", {}, onStep),
                });
                state.proofResults = res.proofs || [];
                state.activeGovernTab = "controls";
                state.selectedGovernControlsSub = "proofs";
                renderStageBody();
              } catch (err) {
                showError(err.message);
              } finally {
                runAllBtn.disabled = false;
              }
            });
            pHead.appendChild(runAllBtn);
            subBody.append(pHead, streamBox);

            if (state.proofResults.length > 0) {
              const proofKey = "gov-proofs";
              const proofCols = [
                {
                  key: "proof_id",
                  label: "#",
                  type: "number",
                  filterType: "text",
                  getValue: (p) => Number(p.proof_id || 0),
                },
                {
                  key: "title",
                  label: "Capability Check",
                  type: "string",
                  filterType: "text",
                  getValue: (p) => p.title,
                },
                {
                  key: "control_availability",
                  label: "Availability",
                  type: "string",
                  filterType: "select",
                  options: [
                    ["GA", "GA"],
                    ["Preview", "Preview"],
                  ],
                  getValue: (p) => p.control_availability || "GA",
                  getFilterValue: (p) =>
                    /preview/i.test(String(p.control_availability || "")) ? "Preview" : "GA",
                },
                {
                  key: "passed",
                  label: "Status",
                  type: "string",
                  filterType: "select",
                  options: [
                    ["PASS", "PASS"],
                    ["FAIL", "FAIL"],
                  ],
                  getValue: (p) => (p.passed ? "PASS" : "FAIL"),
                },
                {
                  key: "latency_ms",
                  label: "Latency",
                  type: "number",
                  filterType: "text",
                  getValue: (p) => Number(p.latency_ms || 0),
                },
                {
                  key: "measured_evidence",
                  label: "Measured Evidence",
                  type: "string",
                  filterType: "text",
                  getValue: (p) => p.measured_evidence,
                },
              ];
              const processedProofs = applyTableSortAndFilters(
                state.proofResults,
                proofCols,
                proofKey,
                "proof_id",
                "asc"
              );

              const pWrap = el("div", "table-wrap");
              const pBanner = buildActiveFiltersBanner(
                proofKey,
                processedProofs.length,
                state.proofResults.length,
                null
              );
              if (pBanner) {
                pWrap.appendChild(pBanner);
              }

              const pTbl = el("table", "data-table");
              pTbl.appendChild(el("caption", "", "Measured Control Plane Verification Results"));
              pTbl.appendChild(
                buildInteractiveTableHead({
                  tableKey: proofKey,
                  columns: proofCols,
                  allRows: state.proofResults,
                  defaultSortCol: "proof_id",
                  defaultSortDir: "asc",
                  paginationState: null,
                })
              );

              const pb = el("tbody");
              processedProofs.forEach((pr) => {
                const tr = el("tr");
                tr.appendChild(el("td", "", String(pr.proof_id)));
                tr.appendChild(el("td", "", pr.title));
                const avail = pr.control_availability || "GA";
                const tdAvail = el("td");
                tdAvail.appendChild(
                  el(
                    "span",
                    /preview/i.test(avail) ? "status-badge preview-badge" : "status-badge ga-badge",
                    avail
                  )
                );
                tr.appendChild(tdAvail);
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
              subBody.appendChild(pWrap);
            }
          },
        ],
        [
          "topology",
          "4.4 Control Plane Service Topology (9 Runtime Services)",
          "9 Active Services",
          (subBody) => {
            const previewIds = new Set(["agent_registry", "agent_gateway", "memory_bank"]);
            if (state.platformServices && state.platformServices.services) {
              subBody.appendChild(
                el("p", "field-hint", state.platformServices.last_event || "Control plane ready.")
              );
              const pList = el("ol", "pipeline-grid");
              state.platformServices.services.forEach((svc) => {
                const li = el("li", "pipeline-item");
                const top = el("div", "pipeline-item-top");
                top.appendChild(el("strong", "", `${svc.step}. ${svc.name}`));
                const availTxt = previewIds.has(svc.id) ? "Preview" : "GA";
                const badgeWrap = el("span", "toolbar-left");
                badgeWrap.appendChild(
                  el(
                    "span",
                    availTxt === "Preview" ? "status-badge preview-badge" : "status-badge ga-badge",
                    availTxt
                  )
                );
                const ok =
                  svc.status === "READY" || svc.status === "VERIFIED" || svc.status === "ACTIVE";
                badgeWrap.appendChild(
                  el(
                    "span",
                    ok ? "status-badge status-ok" : "status-badge status-warn",
                    svc.badge_label || svc.status
                  )
                );
                top.appendChild(badgeWrap);
                li.append(top, el("span", "field-hint", svc.subtitle));
                if (svc.summary) {
                  li.appendChild(el("span", "field-hint", svc.summary));
                }
                if (svc.id === "agent_runtime" && svc.metrics && svc.metrics.sandbox) {
                  li.appendChild(el("span", "field-hint", `Sandbox: ${svc.metrics.sandbox}`));
                } else if (svc.id === "model_armor" && svc.metrics && svc.metrics.base_pool) {
                  li.appendChild(el("span", "field-hint", `Base Pool: ${svc.metrics.base_pool}`));
                }
                pList.appendChild(li);
              });
              subBody.appendChild(pList);
            }
          },
        ],
      ])
    );
  }

  /* Center Modals for + New Agent & Import Manifest */
  function openNewAgentModal() {
    const dlg = document.getElementById("agent-modal-dialog");
    const hd = document.getElementById("agent-modal-heading");
    const body = document.getElementById("agent-modal-body");
    if (!dlg || !body) return;
    if (hd) hd.textContent = "Register New Agent";
    body.replaceChildren();

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
    const cmdbSeed = tenantDefault("cmdb_app_id", "svc-ops-992");
    const cmdbPrefix = cmdbSeed.replace(/\d+$/, "");
    const intakeSeed = tenantDefault("intake_record_id", "intake-2026-0841");
    const intakePrefix = intakeSeed.replace(/\d+$/, "");

    const fName = addInput("new-agent-id", "Agent ID", `customer-care-agent-${nextNum}`);
    const fApp = addInput(
      "new-app-id",
      tenantTerm("cmdb_col_label", "CMDB App ID"),
      `${cmdbPrefix}${990 + nextNum}`
    );
    const fIntake = addInput(
      "new-intake-id",
      tenantTerm("intake_col_label", "Intake ID"),
      `${intakePrefix}${840 + nextNum}`
    );

    const profGrp = el("div", "field-group");
    const profLbl = el("label", "", "Initial Template");
    profLbl.setAttribute("for", "new-agent-profile");
    const profSel = el("select");
    profSel.id = "new-agent-profile";
    [
      ["google_gcp", `${gcpShortName()} (All 10 Google Cloud components)`],
      ["custom", `Custom (${customerShortName()} baseline / per-component choices)`],
    ].forEach(([val, txt]) => {
      const o = el("option", "", txt);
      o.value = val;
      profSel.appendChild(o);
    });
    profGrp.append(profLbl, profSel);

    const riskGrp = el("div", "field-group");
    const riskLbl = el(
      "label",
      "",
      tenantTerm("agency_tier_label", tenantTerm("risk_col_label", "Agency Tier"))
    );
    riskLbl.setAttribute("for", "new-agent-risk-tier");
    const riskSel = el("select");
    riskSel.id = "new-agent-risk-tier";
    [
      ["AG1", "AG1 (Low Risk / Read-Only)"],
      ["AG2", "AG2 (Standard Governed)"],
      ["AG3", "AG3 (High-Risk HITL Gate)"],
      ["AG4", "AG4 (Critical Multi-BU)"],
      ["AG5", "AG5 (Prohibited - Fully Autonomous)"],
    ].forEach(([val, txt]) => {
      const o = el("option", "", txt);
      o.value = val;
      if (val === "AG2") o.selected = true;
      riskSel.appendChild(o);
    });
    riskGrp.append(riskLbl, riskSel);

    const createBtn = el("button", "primary-btn", "Create & Open Agent");
    createBtn.type = "submit";
    form.append(fName.group, fApp.group, fIntake.group, profGrp, riskGrp, createBtn);

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const slug = fName.input.value.trim().toLowerCase().replace(/[^a-z0-9_-]+/g, "-");
      const useGcp = profSel.value === "google_gcp";
      const targetProv = useGcp ? "google_gcp" : "cymbal_stack";
      const comps = {};
      state.slotCatalog.forEach((s) => {
        comps[s.slot_id] = {
          slot_id: s.slot_id,
          provider: targetProv,
          enabled: true,
          enterprise_sync_enabled: true,
          parameters: {},
        };
      });
      const payload = {
        template_id: slug,
        name: slug,
        description: `Registered via ${tenantTerm("platform_name", "Agent Governance Platform")}.`,
        template_mode: useGcp ? "google_gcp" : "custom",
        origin: useGcp ? "google_gcp_standard" : "custom_hybrid",
        agent_name: slug,
        app_id: fApp.input.value.trim(),
        intake_id: fIntake.input.value.trim(),
        business_unit: "core_cable",
        risk_tier: riskSel.value || "AG2",
        onboarding_path: useGcp ? "Path C: Greenfield" : "Path B: SDK Integration",
        runtime_cloud: useGcp ? "gcp" : "hybrid_multicloud",
        estimated_monthly_turns_millions: 3.5,
        uap_cel_per_tool_enforced: true,
        sdp_pii_mode: "DEIDENTIFY_INLINE",
        prompt_version: "v2",
        behavior_score: useGcp ? 96.4 : 88.5,
        components: comps,
      };
      try {
        const res = await apiPost("/api/agents/save", payload);
        state.templates = res.templates;
        state.workingTemplate = res.template;
        state.currentEvaluation = res.evaluation;
        clearTableFilters("build-agents", state.buildPagination);
        state.buildPagination.page = 1;
        state.expandedAgentId = slug;
        dlg.close();
        renderHeaderAndBrand();
        renderStageBody();
      } catch (err) {
        showError(err.message);
      }
    });

    body.appendChild(form);

    const starterSection = el("div", "surface-card form-stack modal-starter-section");
    starterSection.appendChild(
      el("h3", "section-heading", "Import Saved Template or Load Starter YAML")
    );

    if (state.starterTemplates && state.starterTemplates.length > 0) {
      const starterList = el("div", "form-stack");
      state.starterTemplates.forEach((st) => {
        const stBtn = el(
          "button",
          "secondary-btn starter-preset-btn",
          `Load Starter: ${st.name} (${st.cymbal_stack_slots} ${customerShortName()} / ${st.google_gcp_slots} ${gcpShortName()} | ${Number(st.overall_score || 0).toFixed(1)}/100)`
        );
        stBtn.type = "button";
        stBtn.addEventListener("click", async () => {
          stBtn.disabled = true;
          try {
            const customName = fName.input.value.trim().toLowerCase().replace(/[^a-z0-9_-]+/g, "-");
            const res = await apiPost(
              `/api/templates/starters/${encodeURIComponent(st.starter_id)}/load`,
              { save: true, agent_name: customName || null }
            );
            state.templates = res.templates || state.templates;
            state.workingTemplate = res.template;
            state.currentEvaluation = res.evaluation;
            state.initialScoreBaseline = res.evaluation.overall_score;
            clearTableFilters("build-agents", state.buildPagination);
            state.buildPagination.page = 1;
            state.expandedAgentId = res.template.template_id;
            dlg.close();
            renderHeaderAndBrand();
            renderStageBody();
            showNotice(`Loaded starter template '${res.template.agent_name}'.`);
          } catch (err) {
            showError(err.message);
          } finally {
            stBtn.disabled = false;
          }
        });
        starterList.appendChild(stBtn);
      });
      starterSection.appendChild(starterList);
    }

    const importRow = el("div", "toolbar-left");
    const hiddenFile = el("input", "visually-hidden");
    hiddenFile.type = "file";
    hiddenFile.id = "new-agent-yaml-file";
    hiddenFile.accept = ".yaml,.yml,.json";
    hiddenFile.addEventListener("change", async () => {
      const file = hiddenFile.files && hiddenFile.files[0];
      if (!file) return;
      try {
        const content = await file.text();
        const up = await apiPost("/api/templates/upload", {
          filename: file.name,
          content,
        });
        const saved = await apiPost("/api/agents/save", up.template);
        state.templates = saved.templates;
        state.workingTemplate = saved.template;
        state.currentEvaluation = saved.evaluation;
        state.initialScoreBaseline = saved.evaluation.overall_score;
        clearTableFilters("build-agents", state.buildPagination);
        state.buildPagination.page = 1;
        state.expandedAgentId = saved.template.template_id;
        dlg.close();
        renderHeaderAndBrand();
        renderStageBody();
        showNotice(`Imported template '${saved.template.agent_name}' from '${file.name}'.`);
      } catch (err) {
        showError(err.message);
      }
    });

    const yamlFileBtn = el("button", "secondary-btn sm-btn", "Import Saved Template (.yaml)");
    yamlFileBtn.type = "button";
    yamlFileBtn.addEventListener("click", () => hiddenFile.click());

    const pasteYamlBtn = el("button", "secondary-btn sm-btn", "Paste / Edit YAML...");
    pasteYamlBtn.type = "button";
    pasteYamlBtn.addEventListener("click", () => openImportManifestModal(false));

    importRow.append(hiddenFile, yamlFileBtn, pasteYamlBtn);
    starterSection.appendChild(importRow);
    body.appendChild(starterSection);

    dlg.showModal();
  }

  function openImportManifestModal(applyToSelectedAgent = false) {
    const dlg = document.getElementById("agent-modal-dialog");
    const hd = document.getElementById("agent-modal-heading");
    const body = document.getElementById("agent-modal-body");
    if (!dlg || !body) return;
    const targetName =
      applyToSelectedAgent && state.workingTemplate
        ? state.workingTemplate.agent_name
        : "Agent Instance";
    if (hd) hd.textContent = `Import Manifest (${targetName})`;
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
    const defaultId =
      applyToSelectedAgent && state.workingTemplate
        ? state.workingTemplate.agent_name
        : "order-fulfillment-specialist";
    const cmdbSeed = tenantDefault("cmdb_app_id", "svc-ops-740").replace(/\d+$/, "");
    txtArea.value = [
      `template_id: ${defaultId}`,
      `agent_name: ${defaultId}`,
      `app_id: ${cmdbSeed}740`,
      "intake_id: ''",
      "business_unit: media_studio",
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

    let chosenFilename = `${defaultId}.yaml`;
    fileInp.addEventListener("change", async () => {
      const file = fileInp.files && fileInp.files[0];
      if (!file) return;
      chosenFilename = file.name;
      txtArea.value = await file.text();
    });

    const subBtn = el("button", "primary-btn", "Import into Instance");
    subBtn.type = "submit";
    form.append(fileGrp, txtGrp, subBtn);

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        const res = await apiPost("/api/templates/upload", {
          filename: chosenFilename,
          content: txtArea.value,
        });
        if (applyToSelectedAgent && state.workingTemplate) {
          res.template.template_id = state.workingTemplate.template_id;
          res.template.agent_name = state.workingTemplate.agent_name;
          res.template.name = state.workingTemplate.agent_name;
        }
        const saved = await apiPost("/api/agents/save", res.template);
        state.templates = saved.templates;
        state.workingTemplate = saved.template;
        state.currentEvaluation = saved.evaluation;
        state.initialScoreBaseline = saved.evaluation.overall_score;
        clearTableFilters("build-agents", state.buildPagination);
        state.buildPagination.page = 1;
        state.expandedAgentId = state.workingTemplate.template_id;
        dlg.close();
        renderHeaderAndBrand();
        renderStageBody();
      } catch (err) {
        showError(err.message);
      }
    });

    body.appendChild(form);
    dlg.showModal();
  }

  function wireStaticControls() {
    document.querySelectorAll(".lifecycle-nav-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.expandedAgentId = null;
        state.expandedEvalAgentId = null;
        state.expandedDeployAgentId = null;
        setStage(btn.dataset.stage);
      });
    });

    const offlineChk = document.getElementById("offline-demo-toggle");
    if (offlineChk) {
      offlineChk.addEventListener("change", async () => {
        const desiredOffline = Boolean(offlineChk.checked);
        offlineChk.disabled = true;
        try {
          const res = await apiPost("/api/config/mode", { offline_mode: desiredOffline });
          state.offlineMode = Boolean(res.offline_mode);
          state.liveCloudAvailable = Boolean(res.live_cloud_available);
          state.architectureMode = res.architecture_mode || state.architectureMode;
          renderHeaderAndBrand();
          showNotice(
            state.offlineMode
              ? "Offline Demo Fallback enabled for this browser session."
              : "Live Vertex AI (gemini-3.8-flash) execution enabled for this browser session."
          );
        } catch (err) {
          offlineChk.checked = state.offlineMode;
          showError(err.message);
        } finally {
          syncOfflineModeControl();
        }
      });
    }

    window.addEventListener("popstate", () => {
      setStage(resolveInitialStageFromPath(), false);
    });

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
  }

  async function initConsole() {
    wireStaticControls();
    try {
      const boot = await apiGet("/api/bootstrap");
      state.csrfToken = boot.csrf_token;
      state.offlineMode = Boolean(boot.offline_mode);
      state.liveCloudAvailable = Boolean(boot.live_cloud_available);
      state.architectureMode = boot.architecture_mode || "enterprise_hybrid";
      state.tenant = boot.tenant;
      state.candidates = boot.candidates || [];
      state.slotCatalog = boot.slot_catalog || [];
      state.slotById = {};
      state.slotCatalog.forEach((s) => {
        state.slotById[s.slot_id] = s;
      });
      state.templates = boot.templates || [];
      state.starterTemplates = boot.starter_templates || [];
      state.aiglPhaseSpecs = boot.aigl_phase_specs || [];
      state.caasRiskDomains = boot.caas_risk_domains || [];
      state.caas49Factors = boot.caas_49_factors || [];
      state.phase5ReviewerRoles = boot.phase5_reviewer_roles || [];
      state.recertificationRecords = boot.recertification_records || [];
      state.rubric = boot.rubric;
      state.operationsMetrics = boot.operations_metrics;
      state.executiveCosts = boot.executive_costs;
      state.platformServices = boot.platform_services;
      state.agentState = boot.agent_state;
      state.walletState = boot.wallet_state;
      state.tcoReport = boot.tco_default;

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
