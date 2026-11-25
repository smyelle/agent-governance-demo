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
    slotCatalog: [],
    slotById: {},
    templates: [],
    sampleUploads: [],
    rubric: null,
    opsMetrics: null,
    execCosts: null,
    tcoDefault: null,
    agentState: null,
    walletState: null,
    identityPosture: null,
    promptRegistry: null,
    candidates: [],
    recentMemories: [],
    platformSnapshot: null,

    // Navigation & 4-Zone UI state
    activePersona: "end-user",
    activeNode: "uj1-mock",
    collapsedFolders: new Set(["ops-folder-day2"]),
    rightTrayOpen: true,
    rightTrayTab: "inspector",

    // Persona 1 working template & evaluation state
    workingTemplate: null,
    initialEvalScore: 88.5,
    currentEvaluation: null,
    lastDeploymentReceipt: null,
    adkAuditResult: null,

    // Persona 2 & 3 selection state
    opsSelectedTemplate: null,
    opsSearchQuery: "",
    execBuFilter: "all",
    execOriginFilter: "all",

    // Contextual Right-Tray Inspector focus
    inspectorContext: {
      kind: "slot",
      id: "safety_guardrails",
      data: null,
    },

    // Live 9-service pipeline animation state
    expandedServiceIds: new Set(["eval_flywheel"]),
    expandAll: false,
    steppingServiceId: "",
    replayTimerIds: [],
  };

  const PROOF_DEFINITIONS = [
    {
      id: 1,
      title: "1. Un-Bypassable Tenant Network (ACT + PSC-I) & Unified Kill Switch",
      vendors: "Agentgateway, Hush, Geordie, Harmonic",
    },
    {
      id: 2,
      title: "2. Inline Per-Tool & Semantic Payload Authz (UAP Policy V2 CEL)",
      vendors: "Runlayer, Keycard, Arcade",
    },
    {
      id: 3,
      title: "3. Zero-Secret Container (SPIFFE AGENT_IDENTITY) & ADR-011 azp OBO",
      vendors: "Keycard, Custom Sidecars, Vault",
    },
    {
      id: 4,
      title: "4. Dynamic Per-Request Model Armor Router + Inline SDP + 40-URL Floor",
      vendors: "Straiker.ai, Static Template Glue",
    },
    {
      id: 5,
      title: "5. Durable Reviewer RequestInput HITL & Native gVisor Sandbox",
      vendors: "E2B MicroVMs, Custom Checkpoint Glue",
    },
    {
      id: 6,
      title: "6. Longitudinal Governance Memory Bank (Strict JWT Isolation)",
      vendors: "Mem0, Memori, Custom ABAC Stores",
    },
    {
      id: 7,
      title: "7. Unified W3C + OTLP Trace Join & Atomic Cost-per-Outcome Wallet",
      vendors: "Revenium, Ascerta, Faros",
    },
    {
      id: 8,
      title: "8. A-La-Carte 6-Stage Cross-Cloud Trace -> Eval -> Optimizer -> Gate",
      vendors: "Veris Simulator, LangSmith",
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

  function deepClone(obj) {
    return JSON.parse(JSON.stringify(obj));
  }

  function fmtUsd(val) {
    const num = Number(val || 0);
    return "$" + num.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  }

  function fmtIntUsd(val) {
    const num = Math.round(Number(val || 0));
    return "$" + num.toLocaleString();
  }

  function announcePolite(msg) {
    const reg = document.getElementById("live-status-region");
    if (reg) {
      reg.textContent = msg;
    }
  }

  function showGlobalAlert(msg, isError) {
    const banner = document.getElementById("global-alert-banner");
    if (!banner) {
      return;
    }
    if (!msg) {
      banner.classList.add("hidden");
      banner.textContent = "";
      return;
    }
    banner.className = isError ? "alert-banner" : "info-banner";
    banner.textContent = msg;
  }

  async function apiGet(path) {
    const resp = await fetch(path, { credentials: "same-origin" });
    const data = await resp.json().catch(() => ({ detail: resp.statusText }));
    if (!resp.ok) {
      throw new Error(data.detail || resp.statusText);
    }
    return data;
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

  function terms() {
    return (state.tenant && state.tenant.terminology) || {};
  }

  function platformLabel() {
    return terms().platform_name || "Enterprise Platform";
  }

  function mockStackShortLabel() {
    return terms().mock_stack_short || "Mocked Enterprise Stack";
  }

  function originLabel(origin) {
    if (origin === "standard_enterprise_mock") {
      return "Standard (" + mockStackShortLabel() + ")";
    }
    if (origin === "standard_gcp_native") {
      return "Standard (GCP Agent Platform)";
    }
    if (origin === "uploaded_manifest") {
      return "Uploaded Template Manifest";
    }
    return "Custom Composed Template";
  }

  function providerShortLabel(prov) {
    if (prov === "enterprise_mock") {
      return mockStackShortLabel();
    }
    if (prov === "gcp_native") {
      return "GCP Agent Platform";
    }
    if (prov === "coexistence_bridge") {
      return "4-Tier Coexistence Bridge";
    }
    return "Missing / Unconfigured";
  }

  function providerChipClass(prov) {
    if (prov === "unconfigured") {
      return "status-chip chip-danger";
    }
    if (prov === "enterprise_mock") {
      return "subtle-tag";
    }
    if (prov === "gcp_native") {
      return "status-chip chip-ready";
    }
    return "status-chip";
  }

  function downloadTextFile(filename, content, mimeType) {
    const blob = new Blob([content], { type: mimeType || "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function templateToYaml(tpl) {
    const lines = [
      "# Fully Qualified Agent Deployment Template",
      "template_id: " + JSON.stringify(tpl.template_id),
      "name: " + JSON.stringify(tpl.name),
      "agent_name: " + JSON.stringify(tpl.agent_name),
      "app_id: " + JSON.stringify(tpl.app_id),
      "intake_id: " + JSON.stringify(tpl.intake_id || ""),
      "business_unit: " + JSON.stringify(tpl.business_unit),
      "risk_tier: " + JSON.stringify(tpl.risk_tier),
      "onboarding_path: " + JSON.stringify(tpl.onboarding_path),
      "runtime_cloud: " + JSON.stringify(tpl.runtime_cloud),
      "estimated_monthly_turns_millions: " + String(tpl.estimated_monthly_turns_millions),
      "destructive_mcp_tools_exposed: " + String(Boolean(tpl.destructive_mcp_tools_exposed)),
      "uap_cel_per_tool_enforced: " + String(Boolean(tpl.uap_cel_per_tool_enforced)),
      "sdp_pii_mode: " + JSON.stringify(tpl.sdp_pii_mode),
      "prompt_version: " + JSON.stringify(tpl.prompt_version),
      "behavior_score: " + String(tpl.behavior_score),
      "static_secrets_in_env: " + JSON.stringify(tpl.static_secrets_in_env || []),
      "system_instruction: " + JSON.stringify(tpl.system_instruction || ""),
      "components:",
    ];
    state.slotCatalog.forEach((spec) => {
      const sid = spec.slot_id;
      const comp = (tpl.components && tpl.components[sid]) || {
        provider: "unconfigured",
        enabled: false,
      };
      lines.push("  " + sid + ":");
      lines.push("    provider: " + JSON.stringify(comp.provider));
      lines.push("    enabled: " + String(Boolean(comp.enabled)));
    });
    return lines.join("\n") + "\n";
  }

  /* ================= MENU TREE DEFINITIONS PER PERSONA ================= */
  function getMenuTreeForPersona(persona) {
    const recCount = state.currentEvaluation
      ? state.currentEvaluation.recommendations_count || 0
      : 0;
    const depCount = state.opsMetrics ? state.opsMetrics.total_deployments || 0 : 0;
    const ruleCount = state.rubric && state.rubric.rules ? state.rubric.rules.length : 10;

    if (persona === "governance-ops") {
      return {
        kicker: "Persona 2",
        heading: "Governance Operations",
        folders: [
          {
            id: "ops-folder-rubric",
            label: "1. Template Rubric Studio",
            items: [
              {
                id: "ops-rubric",
                label: "Define Best-Practices Rubric",
                badge: ruleCount + " Rules",
                badgeKind: "ok",
              },
            ],
          },
          {
            id: "ops-folder-templates",
            label: "2. Standard Template Studio",
            items: [
              {
                id: "ops-templates",
                label: "Manage Templates & Components",
                badge: state.templates.length + " Std",
              },
            ],
          },
          {
            id: "ops-folder-metrics",
            label: "3. Operational Fleet Metrics",
            items: [
              {
                id: "ops-metrics-overview",
                label: "Component & Score Analytics",
                badge: depCount + " Deps",
                badgeKind: "ok",
              },
              {
                id: "ops-metrics-ledger",
                label: "Deployment Audit Log",
              },
            ],
          },
          {
            id: "ops-folder-day2",
            label: "4. Day-2 Live Controls",
            items: [
              { id: "ops-day2-steward", label: "Kill Switch, Wallet & OBO" },
              { id: "ops-day2-armor", label: "Dynamic Model Armor Lab" },
              { id: "ops-day2-flywheel", label: "6-Stage Closed-Loop Eval" },
              { id: "ops-day2-proofs", label: "8 Live Coexistence Proofs" },
            ],
          },
        ],
      };
    }

    if (persona === "executive") {
      return {
        kicker: "Persona 3",
        heading: "Executive FinOps",
        folders: [
          {
            id: "exec-folder-deployments",
            label: "1. Agent Deployment Costs",
            items: [
              {
                id: "exec-deployments",
                label: "Per-Deployment Cost Ledger",
                badge: depCount + " Agents",
              },
            ],
          },
          {
            id: "exec-folder-components",
            label: "2. Governance Component Rollup",
            items: [
              {
                id: "exec-components",
                label: "Aggregate 9-Component Spend",
                badge: "9 Slots",
                badgeKind: "ok",
              },
            ],
          },
          {
            id: "exec-folder-tco",
            label: "3. Strategic Scale Modeling",
            items: [
              {
                id: "exec-tco",
                label: "Enterprise TCO Simulator",
              },
            ],
          },
        ],
      };
    }

    return {
      kicker: "Persona 1",
      heading: "End User Journeys",
      folders: [
        {
          id: "eu-folder-uj1",
          label: "UJ1: Select or Compose Template",
          items: [
            { id: "uj1-mock", label: "Template 1: " + mockStackShortLabel() },
            { id: "uj1-gcp", label: "Template 2: GCP Agent Platform" },
            { id: "uj1-custom", label: "Option 3: Custom Composer" },
          ],
        },
        {
          id: "eu-folder-uj2",
          label: "UJ2: Upload & Inspect Template",
          items: [{ id: "uj2-upload", label: "Upload Manifest (.json/.yaml)" }],
        },
        {
          id: "eu-folder-uj3",
          label: "UJ3: Evaluate Best Practices",
          items: [
            {
              id: "uj3-evaluate",
              label: "Run Rubric Evaluation",
              badge: state.currentEvaluation
                ? state.currentEvaluation.overall_score + "/100"
                : "",
              badgeKind:
                state.currentEvaluation && state.currentEvaluation.gate_passed ? "ok" : "warn",
            },
          ],
        },
        {
          id: "eu-folder-uj45",
          label: "UJ4 & UJ5: Remediate & Deploy",
          items: [
            {
              id: "uj4-recommendations",
              label: "UJ4: Remediation Recommendations",
              badge: recCount > 0 ? recCount + " Open" : "0 Open",
              badgeKind: recCount > 0 ? "warn" : "ok",
            },
            {
              id: "uj5-remediate-deploy",
              label: "UJ5: Accept, Edit & Deploy",
            },
          ],
        },
      ],
    };
  }

  /* ================= WORKING TEMPLATE SELECTION & EVALUATION ================= */
  async function loadTemplateIntoWorkspace(tplObj, preserveOrigin) {
    const cloned = deepClone(tplObj);
    if (!preserveOrigin && state.activeNode === "uj1-custom") {
      cloned.origin = "custom_composed";
    }
    state.workingTemplate = cloned;
    state.lastDeploymentReceipt = null;
    try {
      const res = await apiPost("/api/templates/evaluate", { template: cloned });
      state.workingTemplate = res.template;
      state.currentEvaluation = res.evaluation;
      state.initialEvalScore = res.evaluation.overall_score;
      if (res.platform_services) {
        updatePlatformServices(res.platform_services, false);
      }
    } catch (err) {
      showGlobalAlert("Evaluation error: " + err.message, true);
    }
    renderAll();
  }

  async function refreshWorkingEvaluation(animatePipeline) {
    if (!state.workingTemplate) {
      return;
    }
    const res = await apiPost("/api/templates/evaluate", {
      template: state.workingTemplate,
    });
    state.workingTemplate = res.template;
    state.currentEvaluation = res.evaluation;
    if (res.platform_services) {
      updatePlatformServices(res.platform_services, Boolean(animatePipeline));
    }
  }

  /* ================= NAVIGATION & ACCESSIBLE KEYBOARD WIRING ================= */
  function setActivePersona(persona, targetNode, pushUrl) {
    state.activePersona = persona;
    showGlobalAlert("", false);

    if (targetNode) {
      state.activeNode = targetNode;
    } else if (persona === "end-user") {
      state.activeNode = "uj1-mock";
    } else if (persona === "governance-ops") {
      state.activeNode = "ops-rubric";
    } else {
      state.activeNode = "exec-deployments";
    }

    // Update default Right-Tray inspector context cleanly per persona
    if (persona === "end-user") {
      state.inspectorContext = { kind: "slot", id: "safety_guardrails", data: null };
    } else if (persona === "governance-ops") {
      const firstRule =
        state.rubric && state.rubric.rules && state.rubric.rules[0]
          ? state.rubric.rules[0]
          : null;
      state.inspectorContext = {
        kind: state.activeNode.startsWith("ops-metrics") ? "deployment" : "rubric_rule",
        id: firstRule ? firstRule.rule_id : "RUB-01",
        data:
          state.opsMetrics && state.opsMetrics.deployments && state.opsMetrics.deployments[0]
            ? state.opsMetrics.deployments[0]
            : firstRule,
      };
    } else {
      const firstDep =
        state.execCosts && state.execCosts.deployments && state.execCosts.deployments[0]
          ? state.execCosts.deployments[0]
          : null;
      state.inspectorContext = {
        kind: "exec_deployment",
        id: firstDep ? firstDep.deployment_id : "",
        data: firstDep,
      };
    }

    const titleMap = {
      "end-user": "End User - Agent Builder",
      "governance-ops": "Agent Governance Operations",
      executive: "Executive Management - FinOps",
    };
    document.title =
      (titleMap[persona] || "Workbench") +
      " | " +
      ((state.tenant && state.tenant.agent_title) || "Agent Governance Workbench");

    if (pushUrl) {
      const routeMap = {
        "end-user": "/end-user",
        "governance-ops": "/governance-ops",
        executive: "/executive",
      };
      const targetPath = routeMap[persona] || "/end-user";
      if (window.location.pathname !== targetPath) {
        window.history.pushState({ persona: persona }, "", targetPath);
      }
    }

    document.querySelectorAll(".persona-tab").forEach((btn) => {
      const isMatch = btn.getAttribute("data-persona") === persona;
      btn.classList.toggle("active", isMatch);
      btn.setAttribute("aria-selected", String(isMatch));
      btn.setAttribute("tabindex", isMatch ? "0" : "-1");
    });

    announcePolite("Switched to " + (titleMap[persona] || persona));
    renderAll();
  }

  async function selectTreeNode(nodeId) {
    state.activeNode = nodeId;
    showGlobalAlert("", false);

    if (nodeId === "uj1-mock") {
      const mockTpl = state.templates.find((t) => t.template_id === "tpl-enterprise-mock");
      if (mockTpl) {
        await loadTemplateIntoWorkspace(mockTpl, true);
        return;
      }
    } else if (nodeId === "uj1-gcp") {
      const gcpTpl = state.templates.find((t) => t.template_id === "tpl-gcp-native");
      if (gcpTpl) {
        await loadTemplateIntoWorkspace(gcpTpl, true);
        return;
      }
    } else if (nodeId === "uj1-custom" && state.workingTemplate) {
      state.workingTemplate.origin = "custom_composed";
    } else if (nodeId === "ops-templates" && !state.opsSelectedTemplate && state.templates[0]) {
      state.opsSelectedTemplate = deepClone(state.templates[0]);
    } else if (
      (nodeId === "ops-metrics-overview" || nodeId === "ops-metrics-ledger") &&
      state.opsMetrics &&
      state.opsMetrics.deployments &&
      state.opsMetrics.deployments[0]
    ) {
      state.inspectorContext = {
        kind: "deployment",
        id: state.opsMetrics.deployments[0].deployment_id,
        data: state.opsMetrics.deployments[0],
      };
    } else if (
      nodeId === "exec-components" &&
      state.execCosts &&
      state.execCosts.component_cost_rollup &&
      state.execCosts.component_cost_rollup[0]
    ) {
      const firstComp = state.execCosts.component_cost_rollup[0];
      state.inspectorContext = {
        kind: "exec_component",
        id: firstComp.slot_id,
        data: firstComp,
      };
    }
    renderAll();
  }

  /* ================= ZONE 2 RENDERER: LEFT MENU TREE ================= */
  function renderLeftMenuTree() {
    const spec = getMenuTreeForPersona(state.activePersona);
    document.getElementById("tree-persona-kicker").textContent = spec.kicker;
    document.getElementById("tree-persona-heading").textContent = spec.heading;

    const treeRoot = document.getElementById("left-menu-tree");
    treeRoot.replaceChildren();

    spec.folders.forEach((folder) => {
      const isExpanded = !state.collapsedFolders.has(folder.id);
      const wrap = el("div", "tree-group-wrap");

      const folderBtn = el("button", "tree-folder-btn");
      folderBtn.type = "button";
      folderBtn.setAttribute("role", "treeitem");
      folderBtn.setAttribute("aria-expanded", String(isExpanded));
      folderBtn.appendChild(el("span", "", folder.label));
      folderBtn.appendChild(el("span", "tree-folder-chevron", isExpanded ? "[-]" : "[+]"));

      const toggleFolder = () => {
        if (state.collapsedFolders.has(folder.id)) {
          state.collapsedFolders.delete(folder.id);
        } else {
          state.collapsedFolders.add(folder.id);
        }
        renderLeftMenuTree();
      };
      folderBtn.addEventListener("click", toggleFolder);
      wrap.appendChild(folderBtn);

      if (isExpanded) {
        const groupBox = el("div", "tree-children-group");
        groupBox.setAttribute("role", "group");

        folder.items.forEach((item) => {
          const isSelected = state.activeNode === item.id;
          const leafBtn = el("button", "tree-leaf-btn" + (isSelected ? " selected" : ""));
          leafBtn.type = "button";
          leafBtn.setAttribute("role", "treeitem");
          leafBtn.setAttribute("aria-selected", String(isSelected));
          leafBtn.appendChild(el("span", "", item.label));

          if (item.badge) {
            const bCls =
              item.badgeKind === "warn"
                ? "tree-badge badge-warn"
                : item.badgeKind === "ok"
                ? "tree-badge badge-ok"
                : "tree-badge";
            leafBtn.appendChild(el("span", bCls, item.badge));
          }

          leafBtn.addEventListener("click", () => {
            selectTreeNode(item.id);
          });
          groupBox.appendChild(leafBtn);
        });
        wrap.appendChild(groupBox);
      }

      treeRoot.appendChild(wrap);
    });
  }

  /* ================= SHARED 4-TIER 9-SLOT VISUAL TOPOLOGY CANVAS ================= */
  function renderNineSlotVisualCanvas(tpl, editableInline, onSlotChanged) {
    const card = el("div", "card");
    const hdr = el("div", "card-header");
    const titleBox = el("div", "");
    titleBox.appendChild(
      el("h3", "", "4-Tier " + platformLabel() + " Component Architecture (9 Slots)")
    );
    titleBox.appendChild(
      el(
        "p",
        "muted-note",
        "Click any component card to inspect API surfaces, policy parameters, and cost drivers in the Right Dynamic Tray."
      )
    );
    hdr.appendChild(titleBox);

    const legend = el("div", "btn-row");
    legend.appendChild(el("span", "subtle-tag", mockStackShortLabel()));
    legend.appendChild(el("span", "status-chip chip-ready", "GCP Agent Platform"));
    legend.appendChild(el("span", "status-chip", "4-Tier Coexistence"));
    hdr.appendChild(legend);
    card.appendChild(hdr);

    const tiers = ["Tier 1", "Tier 2", "Tier 3 & 4"];
    const tierTitles = {
      "Tier 1": "Tier 1: Mandatory Foundation (" + platformLabel() + ")",
      "Tier 2": "Tier 2: Enterprise Control, Guardrails & Runtime",
      "Tier 3 & 4": "Tier 3 & 4: Closed-Loop Quality, Evaluation & Frontier Models",
    };

    const failedSlotIds = new Set(
      ((state.currentEvaluation && state.currentEvaluation.rule_results) || [])
        .filter((r) => r.status === "FAILED")
        .map((r) => r.slot_id)
    );

    tiers.forEach((tierKey) => {
      const tierSpecs = state.slotCatalog.filter((s) => s.tier === tierKey);
      if (!tierSpecs.length) {
        return;
      }
      const tBlock = el("div", "tier-block");
      tBlock.appendChild(el("h4", "tier-block-title", tierTitles[tierKey] || tierKey));
      const grid = el("div", "slot-cards-grid");

      tierSpecs.forEach((spec) => {
        const sid = spec.slot_id;
        const comp = (tpl.components && tpl.components[sid]) || {
          slot_id: sid,
          provider: "unconfigured",
          enabled: false,
          parameters: {},
        };
        const prov = comp.enabled === false ? "unconfigured" : comp.provider;
        const isSelected =
          state.inspectorContext.kind === "slot" && state.inspectorContext.id === sid;

        const node = el(
          "div",
          "slot-node-card prov-" + prov + (isSelected ? " selected-slot" : "")
        );
        const top = el("div", "slot-card-top");
        top.appendChild(el("span", "", "Slot " + spec.step));
        if (prov === "unconfigured") {
          top.appendChild(el("span", "status-chip chip-danger", "Missing"));
        } else if (failedSlotIds.has(sid) && state.activePersona === "end-user") {
          top.appendChild(el("span", "status-chip chip-warn", "Needs Fix"));
        } else {
          top.appendChild(el("span", providerChipClass(prov), providerShortLabel(prov)));
        }
        node.appendChild(top);
        node.appendChild(el("div", "slot-card-title", spec.capability_name));
        node.appendChild(
          el("div", "slot-card-provider", spec.provider_labels[prov] || prov)
        );

        if (editableInline) {
          const selId = "slot-select-" + sid;
          const lbl = el("label", "visually-hidden", "Provider for " + spec.capability_name);
          lbl.setAttribute("for", selId);
          const sel = el("select", "ctrl-select");
          sel.id = selId;
          [
            ["coexistence_bridge", "Coexistence: " + spec.coexistence_name],
            ["enterprise_mock", "Mocked: " + spec.mock_name],
            ["gcp_native", "GCP Native: " + spec.gcp_name],
            ["unconfigured", "Unconfigured / Omit Slot"],
          ].forEach(([val, txt]) => {
            const opt = el("option", "", txt);
            opt.value = val;
            if (val === prov) {
              opt.selected = true;
            }
            sel.appendChild(opt);
          });
          sel.addEventListener("click", (ev) => ev.stopPropagation());
          sel.addEventListener("change", (ev) => {
            ev.stopPropagation();
            const nextProv = ev.target.value;
            tpl.components[sid] = {
              slot_id: sid,
              provider: nextProv,
              enabled: nextProv !== "unconfigured",
              parameters: (tpl.components[sid] && tpl.components[sid].parameters) || {},
            };
            if (onSlotChanged) {
              onSlotChanged(sid, nextProv);
            }
          });
          node.appendChild(lbl);
          node.appendChild(sel);
        }

        node.addEventListener("click", () => {
          state.inspectorContext = { kind: "slot", id: sid, data: tpl };
          activateRightTrayTab("inspector");
          renderAll();
        });

        grid.appendChild(node);
      });

      tBlock.appendChild(grid);
      card.appendChild(tBlock);
    });

    return card;
  }

  /* ================= PERSONA 1 CENTER VIEWS (END USER JOURNEYS 1-5) ================= */
  function renderPersona1Header(headerBox) {
    const tpl = state.workingTemplate;
    const ev = state.currentEvaluation;
    const top = el("div", "center-header-top");

    const left = el("div", "");
    left.appendChild(
      el("div", "breadcrumb-line", "Persona 1: End User (Agent Builder) / " + originLabel(tpl ? tpl.origin : ""))
    );
    left.appendChild(
      el("h2", "", tpl ? tpl.name + " (" + tpl.agent_name + ")" : "Agent Deployment Builder")
    );
    if (tpl) {
      left.appendChild(el("p", "muted-note", tpl.description || ""));
    }
    top.appendChild(left);

    const right = el("div", "btn-row");
    if (ev) {
      const scoreCls = ev.gate_passed ? "status-chip" : "status-chip chip-warn";
      right.appendChild(
        el(
          "span",
          scoreCls,
          "Rubric Score: " + ev.overall_score + "/100 (" + (ev.gate_passed ? "Ready" : "Needs Fixes") + ")"
        )
      );
      if (ev.cost_estimate) {
        right.appendChild(
          el("span", "mono-pill", fmtUsd(ev.cost_estimate.monthly_run_rate_usd) + " / mo")
        );
      }
    }
    if (tpl) {
      const dlYamlBtn = el("button", "small-btn", "Download .yaml");
      dlYamlBtn.type = "button";
      dlYamlBtn.addEventListener("click", () => {
        downloadTextFile(tpl.agent_name + "-template.yaml", templateToYaml(tpl), "text/yaml");
      });
      const dlJsonBtn = el("button", "small-btn", "Download .json");
      dlJsonBtn.type = "button";
      dlJsonBtn.addEventListener("click", () => {
        downloadTextFile(
          tpl.agent_name + "-template.json",
          JSON.stringify(tpl, null, 2),
          "application/json"
        );
      });
      right.appendChild(dlYamlBtn);
      right.appendChild(dlJsonBtn);
    }
    headerBox.appendChild(top);

    // 5-User-Journey Horizontal Stepper
    const stepper = el("div", "journey-stepper");
    const steps = [
      { id: "uj1-custom", match: ["uj1-mock", "uj1-gcp", "uj1-custom"], label: "UJ1: Select / Compose" },
      { id: "uj2-upload", match: ["uj2-upload"], label: "UJ2: Upload & Inspect" },
      { id: "uj3-evaluate", match: ["uj3-evaluate"], label: "UJ3: Evaluate Rubric" },
      { id: "uj4-recommendations", match: ["uj4-recommendations"], label: "UJ4: Recommendations" },
      { id: "uj5-remediate-deploy", match: ["uj5-remediate-deploy"], label: "UJ5: Remediate & Deploy" },
    ];
    steps.forEach((st) => {
      const isAct = st.match.includes(state.activeNode);
      const btn = el("button", "step-pill-btn" + (isAct ? " active" : ""), st.label);
      btn.type = "button";
      btn.addEventListener("click", () => selectTreeNode(st.id));
      stepper.appendChild(btn);
    });
    headerBox.appendChild(stepper);
  }

  function renderEndUserJourney1(stage) {
    const tpl = state.workingTemplate;
    if (!tpl) {
      return;
    }

    // Standard Template Picker Row
    const pickerCard = el("div", "card");
    const pHdr = el("div", "card-header");
    const pTitle = el("div", "");
    pTitle.appendChild(el("h3", "", "User Journey 1: Select a Standard Template or Compose Custom"));
    pTitle.appendChild(
      el(
        "p",
        "muted-note",
        "Choose between all mocked " +
          platformLabel() +
          " components, all GCP Agent Platform services, or compose a custom 9-slot mix."
      )
    );
    pHdr.appendChild(pTitle);
    const evalJumpBtn = el("button", "primary-btn", "Evaluate Against Best Practices (UJ3) ->");
    evalJumpBtn.type = "button";
    evalJumpBtn.addEventListener("click", () => selectTreeNode("uj3-evaluate"));
    pHdr.appendChild(evalJumpBtn);
    pickerCard.appendChild(pHdr);

    const grid = el("div", "template-card-grid");
    const mockTpl = state.templates.find((t) => t.template_id === "tpl-enterprise-mock");
    const gcpTpl = state.templates.find((t) => t.template_id === "tpl-gcp-native");
    const coexTpl = state.templates.find((t) => t.template_id === "tpl-coexistence-blueprint");

    const cards = [
      {
        nodeId: "uj1-mock",
        title: "Option 1: " + mockStackShortLabel(),
        desc: "Uses mocked versions of all 9 " + platformLabel() + " components across Tiers 1-4.",
        tpl: mockTpl,
        selected: state.activeNode === "uj1-mock",
      },
      {
        nodeId: "uj1-gcp",
        title: "Option 2: All GCP Agent Platform Services",
        desc: "Uses 100% Google Cloud Agent Platform services (ADK 2.0, Model Armor, Agent Gateway, Eval Optimizer).",
        tpl: gcpTpl,
        selected: state.activeNode === "uj1-gcp",
      },
      {
        nodeId: "uj1-custom",
        title: "Option 3: Custom Component Composer",
        desc: "Mix and match any " + platformLabel() + ", GCP Native, or 4-Tier Coexistence component per slot.",
        tpl: coexTpl,
        selected: state.activeNode === "uj1-custom",
      },
    ];

    cards.forEach((c) => {
      const box = el("div", "template-choice-card" + (c.selected ? " selected" : ""));
      const top = el("div", "");
      top.appendChild(el("h4", "slot-card-title", c.title));
      top.appendChild(el("p", "muted-note", c.desc));
      box.appendChild(top);

      const foot = el("div", "btn-row");
      const btn = el(
        "button",
        c.selected ? "primary-btn" : "small-btn",
        c.selected ? "Selected Active Mode" : "Select Mode"
      );
      btn.type = "button";
      btn.addEventListener("click", () => selectTreeNode(c.nodeId));
      foot.appendChild(btn);

      if (c.nodeId === "uj1-custom" && coexTpl) {
        const presetBtn = el("button", "small-btn", "Load Coexistence Preset");
        presetBtn.type = "button";
        presetBtn.addEventListener("click", async () => {
          state.activeNode = "uj1-custom";
          await loadTemplateIntoWorkspace(coexTpl, false);
        });
        foot.appendChild(presetBtn);
      }
      box.appendChild(foot);
      grid.appendChild(box);
    });
    pickerCard.appendChild(grid);
    stage.appendChild(pickerCard);

    // Custom Metadata Form when in Custom Composer mode (or editable anytime)
    const metaCard = el("div", "card");
    metaCard.appendChild(
      el(
        "h3",
        "",
        state.activeNode === "uj1-custom"
          ? "Custom Agent Metadata & Risk Posture"
          : "Template Workload Configuration"
      )
    );
    const fGrid = el("div", "form-grid");

    const addInput = (id, labelTxt, val, onChange) => {
      const fg = el("div", "field-group");
      const lbl = el("label", "", labelTxt);
      lbl.setAttribute("for", id);
      const inp = el("input", "ctrl-input");
      inp.id = id;
      inp.type = "text";
      inp.value = val || "";
      inp.addEventListener("change", () => onChange(inp.value));
      fg.appendChild(lbl);
      fg.appendChild(inp);
      fGrid.appendChild(fg);
    };

    addInput("eu-agent-name", "Agent Workload Name", tpl.agent_name, async (v) => {
      tpl.agent_name = v.trim() || tpl.agent_name;
      await refreshWorkingEvaluation(false);
      renderAll();
    });
    addInput("eu-app-id", (terms().cmdb_name || "CMDB") + " App ID", tpl.app_id, async (v) => {
      tpl.app_id = v.trim() || tpl.app_id;
      await refreshWorkingEvaluation(false);
      renderAll();
    });
    addInput("eu-intake-id", (terms().intake_name || "AI Intake") + " ID", tpl.intake_id, async (v) => {
      tpl.intake_id = v.trim();
      await refreshWorkingEvaluation(false);
      renderAll();
    });

    // Business Unit select
    const buGroup = el("div", "field-group");
    const buLbl = el("label", "", "Business Unit");
    buLbl.setAttribute("for", "eu-bu-select");
    const buSel = el("select", "ctrl-select");
    buSel.id = "eu-bu-select";
    const buMap = terms().business_units || {
      core_cable: "Core Connectivity",
      media_studio: "Media Studio",
      intl_sky: "International Strict",
      enterprise_shared: "Enterprise Shared",
    };
    Object.keys(buMap).forEach((k) => {
      const o = el("option", "", buMap[k]);
      o.value = k;
      if (tpl.business_unit === k) {
        o.selected = true;
      }
      buSel.appendChild(o);
    });
    buSel.addEventListener("change", async () => {
      tpl.business_unit = buSel.value;
      await refreshWorkingEvaluation(false);
      renderAll();
    });
    buGroup.appendChild(buLbl);
    buGroup.appendChild(buSel);
    fGrid.appendChild(buGroup);

    // Risk Tier select
    const riskGroup = el("div", "field-group");
    const riskLbl = el("label", "", (terms().risk_framework || "Risk") + " Agency Tier");
    riskLbl.setAttribute("for", "eu-risk-select");
    const riskSel = el("select", "ctrl-select");
    riskSel.id = "eu-risk-select";
    ["AG1", "AG2", "AG3", "AG4"].forEach((rt) => {
      const o = el("option", "", rt);
      o.value = rt;
      if (tpl.risk_tier === rt) {
        o.selected = true;
      }
      riskSel.appendChild(o);
    });
    riskSel.addEventListener("change", async () => {
      tpl.risk_tier = riskSel.value;
      await refreshWorkingEvaluation(false);
      renderAll();
    });
    riskGroup.appendChild(riskLbl);
    riskGroup.appendChild(riskSel);
    fGrid.appendChild(riskGroup);

    // Monthly Turns input
    const turnsGroup = el("div", "field-group");
    const turnsLbl = el("label", "", "Est. Monthly Volume (Million Turns)");
    turnsLbl.setAttribute("for", "eu-turns-input");
    const turnsInp = el("input", "ctrl-input");
    turnsInp.id = "eu-turns-input";
    turnsInp.type = "number";
    turnsInp.step = "0.5";
    turnsInp.min = "0.1";
    turnsInp.max = "100";
    turnsInp.value = String(tpl.estimated_monthly_turns_millions || 3.0);
    turnsInp.addEventListener("change", async () => {
      tpl.estimated_monthly_turns_millions = Math.max(0.1, parseFloat(turnsInp.value) || 3.0);
      await refreshWorkingEvaluation(false);
      renderAll();
    });
    turnsGroup.appendChild(turnsLbl);
    turnsGroup.appendChild(turnsInp);
    fGrid.appendChild(turnsGroup);

    metaCard.appendChild(fGrid);
    stage.appendChild(metaCard);

    // 9-Slot Interactive Visual Canvas (editable inline in Custom mode, inspectable in all modes)
    stage.appendChild(
      renderNineSlotVisualCanvas(tpl, state.activeNode === "uj1-custom", async () => {
        tpl.origin = "custom_composed";
        await refreshWorkingEvaluation(true);
        renderAll();
      })
    );
  }

  function renderEndUserJourney2Upload(stage) {
    const upCard = el("div", "card");
    const hdr = el("div", "card-header");
    const tBox = el("div", "");
    tBox.appendChild(
      el("h3", "", "User Journey 2: Upload & Inspect a Fully Qualified Agent Deployment Template")
    );
    tBox.appendChild(
      el(
        "p",
        "muted-note",
        "Upload an existing .json or .yaml deployment manifest (or load one of the 3 built-in candidate manifests) to inspect its active " +
          platformLabel() +
          " components."
      )
    );
    hdr.appendChild(tBox);
    const nextBtn = el("button", "primary-btn", "Evaluate Uploaded Template (UJ3) ->");
    nextBtn.type = "button";
    nextBtn.addEventListener("click", () => selectTreeNode("uj3-evaluate"));
    hdr.appendChild(nextBtn);
    upCard.appendChild(hdr);

    const dropzone = el("div", "upload-dropzone");
    dropzone.appendChild(
      el("p", "slot-card-title", "Drag & Drop a .yaml or .json Agent Deployment Template here")
    );
    dropzone.appendChild(
      el("p", "muted-note", "Strict server-side validation: <= 512 KB, safe JSON/YAML schema check.")
    );

    const fileInput = el("input", "visually-hidden");
    fileInput.type = "file";
    fileInput.id = "template-file-input";
    fileInput.accept = ".json,.yaml,.yml";

    const browseLbl = el("label", "primary-btn", "Choose Manifest File (.yaml / .json)");
    browseLbl.setAttribute("for", "template-file-input");
    dropzone.appendChild(fileInput);
    dropzone.appendChild(browseLbl);

    const handleUploadedFile = async (file) => {
      if (!file) {
        return;
      }
      if (file.size > 524288) {
        showGlobalAlert("File exceeds 512 KB maximum size limit.", true);
        return;
      }
      const text = await file.text();
      try {
        const res = await apiPost("/api/templates/upload", {
          filename: file.name,
          content: text,
        });
        state.workingTemplate = res.template;
        state.currentEvaluation = res.evaluation;
        state.initialEvalScore = res.evaluation.overall_score;
        if (res.platform_services) {
          updatePlatformServices(res.platform_services, true);
        }
        showGlobalAlert(
          "Loaded '" +
            res.template.agent_name +
            "' (" +
            file.name +
            ") - Initial Score: " +
            res.evaluation.overall_score +
            "/100.",
          false
        );
        renderAll();
      } catch (err) {
        showGlobalAlert("Manifest upload rejected: " + err.message, true);
      }
    };

    fileInput.addEventListener("change", () => {
      if (fileInput.files && fileInput.files[0]) {
        handleUploadedFile(fileInput.files[0]);
      }
    });
    dropzone.addEventListener("dragover", (ev) => {
      ev.preventDefault();
      dropzone.classList.add("drag-active");
    });
    dropzone.addEventListener("dragleave", () => dropzone.classList.remove("drag-active"));
    dropzone.addEventListener("drop", (ev) => {
      ev.preventDefault();
      dropzone.classList.remove("drag-active");
      if (ev.dataTransfer && ev.dataTransfer.files && ev.dataTransfer.files[0]) {
        handleUploadedFile(ev.dataTransfer.files[0]);
      }
    });
    upCard.appendChild(dropzone);

    // Built-in Sample Uploadable Templates
    const sampleHeading = el(
      "h4",
      "tier-block-title",
      "Sample Previously-Built Candidate Templates (Load Directly or Download to Disk)"
    );
    sampleHeading.style.marginBlockStart = "1rem";
    upCard.appendChild(sampleHeading);

    const sampleGrid = el("div", "template-card-grid");
    state.sampleUploads.forEach((samp) => {
      const sCard = el(
        "div",
        "template-choice-card" +
          (state.workingTemplate && state.workingTemplate.template_id === samp.template_id
            ? " selected"
            : "")
      );
      const top = el("div", "");
      top.appendChild(el("div", "slot-card-title", samp.name));
      top.appendChild(el("p", "muted-note", samp.description));
      sCard.appendChild(top);

      const act = el("div", "btn-row");
      const loadBtn = el("button", "primary-btn", "Load & Inspect");
      loadBtn.type = "button";
      loadBtn.addEventListener("click", async () => {
        await loadTemplateIntoWorkspace(samp, true);
        showGlobalAlert(
          "Inspected '" + samp.agent_name + "': highlighted configured vs. missing components below.",
          false
        );
      });
      const dlBtn = el("button", "small-btn", "Save Sample .yaml");
      dlBtn.type = "button";
      dlBtn.addEventListener("click", () => {
        downloadTextFile(
          samp.template_id + ".yaml",
          samp.yaml_export || templateToYaml(samp),
          "text/yaml"
        );
      });
      act.appendChild(loadBtn);
      act.appendChild(dlBtn);
      sCard.appendChild(act);
      sampleGrid.appendChild(sCard);
    });
    upCard.appendChild(sampleGrid);
    stage.appendChild(upCard);

    if (state.workingTemplate) {
      stage.appendChild(renderNineSlotVisualCanvas(state.workingTemplate, false, null));
    }
  }

  function renderEndUserJourney3Evaluate(stage) {
    const tpl = state.workingTemplate;
    const ev = state.currentEvaluation;
    if (!tpl || !ev) {
      return;
    }

    const kpiRow = el("div", "kpi-grid");
    const c1 = el("div", "kpi-card " + (ev.gate_passed ? "kpi-success" : "kpi-warn"));
    c1.appendChild(el("div", "kpi-label", "Overall Rubric Score"));
    c1.appendChild(el("div", "kpi-value", ev.overall_score + " / 100"));
    c1.appendChild(
      el("div", "kpi-sub", "Passing Gate Threshold: " + ev.passing_threshold + " / 100")
    );
    kpiRow.appendChild(c1);

    ["Tier 1", "Tier 2", "Tier 3 & 4"].forEach((tName) => {
      const ts = (ev.tier_scores && ev.tier_scores[tName]) || {
        earned_pts: 0,
        possible_pts: 0,
        pct: 100,
      };
      const tk = el("div", "kpi-card " + (ts.pct >= 85 ? "kpi-success" : "kpi-warn"));
      tk.appendChild(el("div", "kpi-label", tName + " Sub-Score"));
      tk.appendChild(el("div", "kpi-value", ts.pct + "%"));
      tk.appendChild(
        el("div", "kpi-sub", ts.earned_pts + " / " + ts.possible_pts + " weighted pts")
      );
      kpiRow.appendChild(tk);
    });
    stage.appendChild(kpiRow);

    // Action Bar: Re-Run Evaluation + Run ADK 2.0 Deep Workflow Audit + Proceed to Recommendations
    const ctrlCard = el("div", "card");
    const cHdr = el("div", "card-header");
    const cLeft = el("div", "");
    cLeft.appendChild(el("h3", "", "User Journey 3: Evaluate Against " + ev.rubric_name));
    cLeft.appendChild(
      el(
        "p",
        "muted-note",
        "Evaluates all 9 component slots, zero-secret posture, per-tool UAP CEL authz, PII protection, and behavioral trace score."
      )
    );
    cHdr.appendChild(cLeft);

    const btnRow = el("div", "btn-row");
    const reEvalBtn = el("button", "secondary-btn", "Re-Evaluate Template");
    reEvalBtn.type = "button";
    reEvalBtn.addEventListener("click", async () => {
      reEvalBtn.disabled = true;
      try {
        await refreshWorkingEvaluation(true);
        renderAll();
      } finally {
        reEvalBtn.disabled = false;
      }
    });

    const adkBtn = el("button", "small-btn", "Run Deep ADK 2.0 Workflow Audit");
    adkBtn.type = "button";
    adkBtn.addEventListener("click", async () => {
      adkBtn.disabled = true;
      adkBtn.textContent = "Running ADK 2.0 Audit...";
      try {
        const res = await apiPost("/api/agent/audit", {
          candidate_id: "CAND-101",
          agent_name: tpl.agent_name,
          app_id: tpl.app_id,
          operator_prompt:
            "Audit " + tpl.agent_name + " (" + tpl.app_id + ") and synthesize Paved-Path artifacts.",
          architecture_mode: state.architectureMode,
        });
        state.adkAuditResult = res;
        if (res.platform_services) {
          updatePlatformServices(res.platform_services, true);
        }
        activateRightTrayTab("pipeline");
        renderAll();
      } catch (err) {
        showGlobalAlert("ADK Audit halted: " + err.message, true);
      } finally {
        adkBtn.disabled = false;
        adkBtn.textContent = "Run Deep ADK 2.0 Workflow Audit";
      }
    });

    const viewRecBtn = el(
      "button",
      "primary-btn",
      "View " + ev.recommendations_count + " Remediation Recommendation(s) (UJ4) ->"
    );
    viewRecBtn.type = "button";
    viewRecBtn.addEventListener("click", () => selectTreeNode("uj4-recommendations"));

    btnRow.appendChild(reEvalBtn);
    btnRow.appendChild(adkBtn);
    btnRow.appendChild(viewRecBtn);
    cHdr.appendChild(btnRow);
    ctrlCard.appendChild(cHdr);

    // Semantic Rule-by-Rule Evaluation Table
    const tWrap = el("div", "table-scroll-wrap");
    const tbl = el("table", "data-table");
    tbl.appendChild(
      el("caption", "", "Detailed Best-Practices Evaluation Results (" + tpl.agent_name + ")")
    );
    const thead = el("thead");
    const htr = el("tr");
    ["Rule", "Tier", "Component Slot", "Active Provider", "Weight", "Status", "Finding"].forEach(
      (h) => {
        const th = el("th", "", h);
        th.setAttribute("scope", "col");
        htr.appendChild(th);
      }
    );
    thead.appendChild(htr);
    tbl.appendChild(thead);

    const tbody = el("tbody");
    (ev.rule_results || []).forEach((r) => {
      const tr = el("tr", "clickable-row");
      tr.appendChild(el("td", "mono-note", r.rule_id));
      tr.appendChild(el("td", "", r.tier));
      tr.appendChild(el("td", "", r.capability_name));
      tr.appendChild(el("td", "", r.current_provider_label));
      tr.appendChild(
        el("td", "", r.weight_points + " pts" + (r.mandatory ? " (Gate)" : ""))
      );
      const stTd = el("td");
      const chipCls =
        r.status === "PASSED"
          ? "status-chip"
          : r.status === "EXCEPTION_APPROVED"
          ? "status-chip chip-warn"
          : "status-chip chip-danger";
      stTd.appendChild(el("span", chipCls, r.status));
      tr.appendChild(stTd);
      tr.appendChild(
        el(
          "td",
          "muted-note",
          r.gap_reasons && r.gap_reasons.length
            ? r.gap_reasons.join(" ")
            : r.exception_note || "Compliant"
        )
      );
      tr.addEventListener("click", () => {
        state.inspectorContext = { kind: "slot", id: r.slot_id, data: tpl };
        activateRightTrayTab("inspector");
        renderRightInspector();
      });
      tbody.appendChild(tr);
    });
    tbl.appendChild(tbody);
    tWrap.appendChild(tbl);
    ctrlCard.appendChild(tWrap);
    stage.appendChild(ctrlCard);
  }

  function renderEndUserJourney4Recommendations(stage) {
    const ev = state.currentEvaluation;
    if (!ev) {
      return;
    }
    const recs = ev.recommendations || [];

    const hdrCard = el("div", "card");
    const hdr = el("div", "card-header");
    const left = el("div", "");
    left.appendChild(
      el("h3", "", "User Journey 4: Agent Deployment Template Remediation Recommendations")
    );
    left.appendChild(
      el(
        "p",
        "muted-note",
        recs.length
          ? "Found " +
              recs.length +
              " actionable recommendation(s). Inspect configuration, Dynamic Model Armor JSON, and Terraform Paved-Path diffs in the Right Tray."
          : "Zero open remediation items! Your template meets all mandatory and best-practice gates."
      )
    );
    hdr.appendChild(left);
    const goUj5Btn = el("button", "primary-btn", "Accept Fixes or Make Changes (UJ5) ->");
    goUj5Btn.type = "button";
    goUj5Btn.addEventListener("click", () => selectTreeNode("uj5-remediate-deploy"));
    hdr.appendChild(goUj5Btn);
    hdrCard.appendChild(hdr);
    stage.appendChild(hdrCard);

    recs.forEach((rec) => {
      const rCard = el(
        "div",
        "rec-card" + (rec.severity === "MANDATORY_GATE" ? " rec-mandatory" : "")
      );
      const top = el("div", "card-header");
      const tLeft = el("div", "");
      tLeft.appendChild(el("h4", "slot-card-title", rec.rule_id + ": " + rec.title));
      tLeft.appendChild(el("p", "muted-note", "Gap: " + rec.finding_detail));
      top.appendChild(tLeft);

      const badges = el("div", "btn-row");
      badges.appendChild(
        el(
          "span",
          rec.severity === "MANDATORY_GATE" ? "status-chip chip-danger" : "status-chip chip-warn",
          rec.severity === "MANDATORY_GATE" ? "Mandatory Gate" : "Best Practice"
        )
      );
      badges.appendChild(el("span", "status-chip", "+" + rec.score_uplift_pts + " pts"));
      const deltaSign = rec.monthly_cost_delta_usd <= 0 ? "" : "+";
      badges.appendChild(
        el("span", "mono-pill", deltaSign + fmtUsd(rec.monthly_cost_delta_usd) + "/mo")
      );
      top.appendChild(badges);
      rCard.appendChild(top);

      rCard.appendChild(
        el("p", "", "Recommended Remediation: " + rec.recommendation_summary)
      );

      const actRow = el("div", "rec-actions-row");
      const diffBtn = el("button", "small-btn", "Inspect Diff & Paved-Path HCL in Right Tray");
      diffBtn.type = "button";
      diffBtn.addEventListener("click", () => {
        state.inspectorContext = { kind: "remediation", id: rec.rule_id, data: rec };
        activateRightTrayTab("inspector");
        renderRightInspector();
      });
      const jumpAcceptBtn = el("button", "primary-btn", "Resolve in UJ5 ->");
      jumpAcceptBtn.type = "button";
      jumpAcceptBtn.addEventListener("click", () => {
        state.inspectorContext = { kind: "remediation", id: rec.rule_id, data: rec };
        selectTreeNode("uj5-remediate-deploy");
      });
      actRow.appendChild(diffBtn);
      actRow.appendChild(jumpAcceptBtn);
      rCard.appendChild(actRow);
      stage.appendChild(rCard);
    });
  }

  function renderEndUserJourney5RemediateAndDeploy(stage) {
    const tpl = state.workingTemplate;
    const ev = state.currentEvaluation;
    if (!tpl || !ev) {
      return;
    }
    const recs = ev.recommendations || [];

    // Summary & Bulk Accept Banner
    const topCard = el("div", "card");
    const hdr = el("div", "card-header");
    const left = el("div", "");
    left.appendChild(
      el(
        "h3",
        "",
        "User Journey 5: Accept Remediation Recommendations, Make Custom Changes, or Deploy"
      )
    );
    left.appendChild(
      el(
        "p",
        "muted-note",
        "Initial Score: " +
          state.initialEvalScore +
          "/100 -> Current Score: " +
          ev.overall_score +
          "/100 (Required Gate: " +
          ev.passing_threshold +
          "/100)."
      )
    );
    hdr.appendChild(left);

    if (recs.length > 0) {
      const acceptAllBtn = el("button", "primary-btn", "Accept All " + recs.length + " Recommendations");
      acceptAllBtn.type = "button";
      acceptAllBtn.addEventListener("click", async () => {
        acceptAllBtn.disabled = true;
        try {
          for (const rec of recs) {
            const res = await apiPost("/api/templates/remediate", {
              template: state.workingTemplate,
              rule_id: rec.rule_id,
              action: "accept",
            });
            state.workingTemplate = res.template;
            state.currentEvaluation = res.evaluation;
            if (res.platform_services) {
              updatePlatformServices(res.platform_services, true);
            }
          }
          showGlobalAlert(
            "Applied all recommendations. Score updated to " +
              state.currentEvaluation.overall_score +
              "/100!",
            false
          );
          renderAll();
        } catch (err) {
          showGlobalAlert("Remediation failed: " + err.message, true);
        } finally {
          acceptAllBtn.disabled = false;
        }
      });
      hdr.appendChild(acceptAllBtn);
    }
    topCard.appendChild(hdr);
    stage.appendChild(topCard);

    // Individual Recommendation Action Cards
    recs.forEach((rec) => {
      const rCard = el(
        "div",
        "rec-card" + (rec.severity === "MANDATORY_GATE" ? " rec-mandatory" : "")
      );
      const rTop = el("div", "card-header");
      rTop.appendChild(
        el("h4", "slot-card-title", rec.rule_id + ": " + rec.title + " (+" + rec.score_uplift_pts + " pts)")
      );
      rTop.appendChild(el("span", "subtle-tag", rec.recommended_provider_label));
      rCard.appendChild(rTop);
      rCard.appendChild(el("p", "muted-note", rec.finding_detail));
      rCard.appendChild(el("p", "", rec.recommendation_summary));

      const actRow = el("div", "rec-actions-row");

      const acceptBtn = el("button", "success-btn", "Accept Recommendation");
      acceptBtn.type = "button";
      acceptBtn.addEventListener("click", async () => {
        acceptBtn.disabled = true;
        try {
          const res = await apiPost("/api/templates/remediate", {
            template: state.workingTemplate,
            rule_id: rec.rule_id,
            action: "accept",
          });
          state.workingTemplate = res.template;
          state.currentEvaluation = res.evaluation;
          if (res.platform_services) {
            updatePlatformServices(res.platform_services, true);
          }
          renderAll();
        } catch (err) {
          showGlobalAlert(err.message, true);
        } finally {
          acceptBtn.disabled = false;
        }
      });
      actRow.appendChild(acceptBtn);

      if (rec.supports_closed_loop_eval) {
        const flyBtn = el("button", "primary-btn", "Run 6-Stage Closed-Loop Optimizer Live");
        flyBtn.type = "button";
        flyBtn.addEventListener("click", async () => {
          flyBtn.disabled = true;
          flyBtn.textContent = "Optimizing Cross-Cloud Traces...";
          try {
            const flyRes = await apiPost("/api/steward/closed-loop-eval", {});
            const remRes = await apiPost("/api/templates/remediate", {
              template: state.workingTemplate,
              rule_id: rec.rule_id,
              action: "customize",
              custom_provider: "coexistence_bridge",
              custom_parameters: {
                system_instruction:
                  flyRes.v2_prompt_text || state.workingTemplate.system_instruction,
              },
            });
            state.workingTemplate = remRes.template;
            state.workingTemplate.behavior_score =
              (flyRes.v2_candidate && flyRes.v2_candidate.behavior_score) || 96.4;
            await refreshWorkingEvaluation(true);
            showGlobalAlert(
              "6-Stage Closed-Loop Optimizer promoted Golden Blueprint v2 (" +
                state.workingTemplate.behavior_score +
                "/100)!",
              false
            );
            renderAll();
          } catch (err) {
            showGlobalAlert("Optimizer error: " + err.message, true);
          } finally {
            flyBtn.disabled = false;
            flyBtn.textContent = "Run 6-Stage Closed-Loop Optimizer Live";
          }
        });
        actRow.appendChild(flyBtn);
      }

      const customBtn = el("button", "secondary-btn", "Make Custom Changes in Right Tray");
      customBtn.type = "button";
      customBtn.addEventListener("click", () => {
        state.inspectorContext = { kind: "remediation", id: rec.rule_id, data: rec };
        activateRightTrayTab("inspector");
        renderRightInspector();
      });
      actRow.appendChild(customBtn);

      const excBtn = el("button", "small-btn warn", "Request Exception");
      excBtn.type = "button";
      excBtn.addEventListener("click", async () => {
        const res = await apiPost("/api/templates/remediate", {
          template: state.workingTemplate,
          rule_id: rec.rule_id,
          action: "exception",
          exception_reason: "Operational exception logged by agent owner pending review.",
        });
        state.workingTemplate = res.template;
        state.currentEvaluation = res.evaluation;
        renderAll();
      });
      actRow.appendChild(excBtn);

      rCard.appendChild(actRow);
      stage.appendChild(rCard);
    });

    // Governed Deployment Card
    const depCard = el("div", "card");
    depCard.appendChild(
      el(
        "h3",
        "",
        ev.gate_passed
          ? "Deployment Gate Passed: Deploy Governed Agent Template"
          : "Deployment Gate Locked Until Score >= " +
              ev.passing_threshold +
              " & Mandatory Gates Resolved"
      )
    );
    depCard.appendChild(
      el(
        "p",
        "muted-note",
        "Deploying records live operational telemetry into Persona 2 (Governance Operations) and per-component cost attribution into Persona 3 (Executive Management)."
      )
    );

    const depForm = el("div", "form-grid");
    const appFg = el("div", "field-group");
    const appLbl = el("label", "", "Governance Approver Principal");
    appLbl.setAttribute("for", "deploy-approver-input");
    const appInp = el("input", "ctrl-input");
    appInp.id = "deploy-approver-input";
    appInp.type = "text";
    appInp.value = "gov-steward-lead";
    appFg.appendChild(appLbl);
    appFg.appendChild(appInp);
    depForm.appendChild(appFg);

    const vpFg = el("div", "field-group");
    const vpLbl = el("label", "", "Optional VP Exception Ticket");
    vpLbl.setAttribute("for", "deploy-vp-input");
    const vpInp = el("input", "ctrl-input");
    vpInp.id = "deploy-vp-input";
    vpInp.type = "text";
    vpInp.placeholder = "e.g. VP-GOV-2026-108";
    vpFg.appendChild(vpLbl);
    vpFg.appendChild(vpInp);
    depForm.appendChild(vpFg);
    depCard.appendChild(depForm);

    const depBtnRow = el("div", "btn-row");
    depBtnRow.style.marginBlockStart = "0.85rem";
    const deployBtn = el("button", "success-btn", "Deploy Governed Agent Template");
    deployBtn.type = "button";
    deployBtn.disabled = !ev.gate_passed;
    deployBtn.addEventListener("click", async () => {
      deployBtn.disabled = true;
      deployBtn.textContent = "Deploying Governed Template...";
      try {
        const res = await apiPost("/api/templates/deploy", {
          template: state.workingTemplate,
          initial_score: state.initialEvalScore,
          approver_principal: appInp.value.trim() || "gov-steward-lead",
          vp_exception_ticket: vpInp.value.trim() || null,
        });
        state.lastDeploymentReceipt = res.deployment;
        state.opsMetrics = res.operations_metrics;
        state.execCosts = res.executive_costs;
        state.walletState = res.wallet_state;
        state.recentMemories = res.recent_memories || state.recentMemories;
        if (res.platform_services) {
          updatePlatformServices(res.platform_services, true);
        }
        showGlobalAlert(
          "Deployed " +
            res.deployment.deployment_id +
            " (" +
            res.deployment.agent_name +
            ") - Live metrics & costs synced to Personas 2 and 3!",
          false
        );
        renderAll();
      } catch (err) {
        showGlobalAlert("Deployment blocked: " + err.message, true);
      } finally {
        deployBtn.disabled = !state.currentEvaluation.gate_passed;
        deployBtn.textContent = "Deploy Governed Agent Template";
      }
    });
    depBtnRow.appendChild(deployBtn);
    depCard.appendChild(depBtnRow);

    if (state.lastDeploymentReceipt) {
      const recBox = el("div", "info-banner");
      recBox.style.marginBlockStart = "0.85rem";
      recBox.textContent =
        "Deployment Receipt " +
        state.lastDeploymentReceipt.deployment_id +
        " | Score: " +
        state.lastDeploymentReceipt.initial_eval_score +
        " -> " +
        state.lastDeploymentReceipt.final_eval_score +
        " | Monthly Run-Rate: " +
        fmtUsd(state.lastDeploymentReceipt.monthly_run_rate_usd) +
        " | Trace: " +
        state.lastDeploymentReceipt.trace_id;
      depCard.appendChild(recBox);
    }

    stage.appendChild(depCard);
    stage.appendChild(renderNineSlotVisualCanvas(tpl, true, async () => {
      await refreshWorkingEvaluation(true);
      renderAll();
    }));
  }

  /* ================= PERSONA 2 CENTER VIEWS (GOVERNANCE OPERATIONS) ================= */
  function renderPersona2Header(headerBox) {
    const top = el("div", "center-header-top");
    const left = el("div", "");
    left.appendChild(
      el("div", "breadcrumb-line", "Persona 2: Agent Governance Operations")
    );
    const titles = {
      "ops-rubric": "Agent Deployment Template Rubric Studio",
      "ops-templates": "Standard Template & Component Configuration Studio",
      "ops-metrics-overview": "Fleet Operational Metrics & Component Adoption",
      "ops-metrics-ledger": "Governed Agent Deployment Audit Ledger",
    };
    left.appendChild(
      el("h2", "", titles[state.activeNode] || "Day-2 Live Runtime & Verification Controls")
    );
    left.appendChild(
      el(
        "p",
        "muted-note",
        "Changes saved in Rubric Studio or Template Studio immediately govern End User (Persona 1) evaluations and templates."
      )
    );
    top.appendChild(left);

    const right = el("div", "btn-row");
    if (state.opsMetrics) {
      right.appendChild(
        el("span", "status-chip", state.opsMetrics.total_deployments + " Governed Deployments")
      );
      right.appendChild(
        el(
          "span",
          "mono-pill",
          state.opsMetrics.remediated_prior_to_deploy_pct + "% Remediated Pre-Deploy"
        )
      );
    }
    headerBox.appendChild(top);
  }

  function renderOpsRubricStudio(stage) {
    if (!state.rubric) {
      return;
    }
    const rub = state.rubric;
    const card = el("div", "card");
    const hdr = el("div", "card-header");
    hdr.appendChild(el("h3", "", "Global Rubric Thresholds & Coexistence Policy"));

    const saveBtn = el("button", "primary-btn", "Save & Publish Rubric to Persona 1");
    saveBtn.type = "button";
    saveBtn.addEventListener("click", async () => {
      saveBtn.disabled = true;
      try {
        const res = await apiPost("/api/ops/rubric", rub);
        state.rubric = res.rubric;
        state.templates = res.templates;
        state.sampleUploads = res.sample_uploads || state.sampleUploads;
        await refreshWorkingEvaluation(false);
        showGlobalAlert("Published updated Rubric. Persona 1 evaluations now enforce new weights & gates!", false);
        renderAll();
      } catch (err) {
        showGlobalAlert("Failed saving rubric: " + err.message, true);
      } finally {
        saveBtn.disabled = false;
      }
    });
    hdr.appendChild(saveBtn);
    card.appendChild(hdr);

    const fGrid = el("div", "form-grid");
    const thFg = el("div", "field-group");
    const thLbl = el("label", "", "Minimum Passing Score Threshold (50-100)");
    thLbl.setAttribute("for", "rubric-pass-input");
    const thInp = el("input", "ctrl-input");
    thInp.id = "rubric-pass-input";
    thInp.type = "number";
    thInp.min = "50";
    thInp.max = "100";
    thInp.value = String(rub.passing_score_threshold);
    thInp.addEventListener("change", () => {
      rub.passing_score_threshold = Math.min(100, Math.max(50, parseFloat(thInp.value) || 85));
    });
    thFg.appendChild(thLbl);
    thFg.appendChild(thInp);
    fGrid.appendChild(thFg);

    const coexFg = el("div", "field-group");
    const coexLbl = el("label", "", "Tier-1 Enterprise Coexistence Enforcement");
    coexLbl.setAttribute("for", "rubric-coex-select");
    const coexSel = el("select", "ctrl-select");
    coexSel.id = "rubric-coex-select";
    [
      ["true", "Require Tier-1 Corporate Sync or Coexistence Bridge"],
      ["false", "Allow Standalone GCP Services on Tier-1"],
    ].forEach(([v, txt]) => {
      const o = el("option", "", txt);
      o.value = v;
      if (String(rub.enforce_tier1_coexistence_hooks) === v) {
        o.selected = true;
      }
      coexSel.appendChild(o);
    });
    coexSel.addEventListener("change", () => {
      rub.enforce_tier1_coexistence_hooks = coexSel.value === "true";
    });
    coexFg.appendChild(coexLbl);
    coexFg.appendChild(coexSel);
    fGrid.appendChild(coexFg);
    card.appendChild(fGrid);

    const tWrap = el("div", "table-scroll-wrap");
    tWrap.style.marginBlockStart = "1rem";
    const tbl = el("table", "data-table");
    tbl.appendChild(
      el("caption", "", "Click any rubric rule to edit its full remediation prescription in the Right Tray")
    );
    const thead = el("thead");
    const htr = el("tr");
    ["Rule ID", "Tier", "Rule Title", "Gate Type", "Weight Pts", "Auto-Fix Target", "Active"].forEach(
      (h) => {
        const th = el("th", "", h);
        th.setAttribute("scope", "col");
        htr.appendChild(th);
      }
    );
    thead.appendChild(htr);
    tbl.appendChild(thead);

    const tbody = el("tbody");
    rub.rules.forEach((rule) => {
      const tr = el("tr", "clickable-row");
      tr.appendChild(el("td", "mono-note", rule.rule_id));
      tr.appendChild(el("td", "", rule.tier));
      tr.appendChild(el("td", "", rule.title));

      // Gate toggle
      const gateTd = el("td");
      const gateBtn = el(
        "button",
        rule.mandatory ? "small-btn danger" : "small-btn",
        rule.mandatory ? "Mandatory Gate" : "Advisory"
      );
      gateBtn.type = "button";
      gateBtn.addEventListener("click", (ev) => {
        ev.stopPropagation();
        rule.mandatory = !rule.mandatory;
        renderOpsRubricStudioStage();
      });
      gateTd.appendChild(gateBtn);
      tr.appendChild(gateTd);

      // Weight input
      const wtTd = el("td");
      const wtInp = el("input", "ctrl-input");
      wtInp.type = "number";
      wtInp.min = "1";
      wtInp.max = "40";
      wtInp.style.inlineSize = "72px";
      wtInp.setAttribute("aria-label", "Weight points for " + rule.rule_id);
      wtInp.value = String(rule.weight_points);
      wtInp.addEventListener("click", (ev) => ev.stopPropagation());
      wtInp.addEventListener("change", () => {
        rule.weight_points = Math.min(40, Math.max(1, parseInt(wtInp.value, 10) || 10));
      });
      wtTd.appendChild(wtInp);
      tr.appendChild(wtTd);

      tr.appendChild(el("td", "", providerShortLabel(rule.remediation_provider)));

      const enTd = el("td");
      const enChk = el("input");
      enChk.type = "checkbox";
      enChk.checked = Boolean(rule.enabled);
      enChk.setAttribute("aria-label", "Enable " + rule.rule_id);
      enChk.addEventListener("click", (ev) => ev.stopPropagation());
      enChk.addEventListener("change", () => {
        rule.enabled = enChk.checked;
      });
      enTd.appendChild(enChk);
      tr.appendChild(enTd);

      tr.addEventListener("click", () => {
        state.inspectorContext = { kind: "rubric_rule", id: rule.rule_id, data: rule };
        activateRightTrayTab("inspector");
        renderRightInspector();
      });
      tbody.appendChild(tr);
    });
    tbl.appendChild(tbody);
    tWrap.appendChild(tbl);
    card.appendChild(tWrap);
    stage.appendChild(card);

    function renderOpsRubricStudioStage() {
      renderCenterStage();
      renderRightInspector();
    }
  }

  function renderOpsTemplateStudio(stage) {
    if (!state.opsSelectedTemplate && state.templates.length) {
      state.opsSelectedTemplate = deepClone(state.templates[0]);
    }
    const tpl = state.opsSelectedTemplate;
    if (!tpl) {
      return;
    }

    const barCard = el("div", "card");
    const hdr = el("div", "card-header");
    hdr.appendChild(el("h3", "", "Select or Author a Standard Agent Deployment Template"));

    const actions = el("div", "btn-row");
    const newBtn = el("button", "secondary-btn", "+ New Standard Template");
    newBtn.type = "button";
    newBtn.addEventListener("click", () => {
      const base = deepClone(state.templates[0]);
      const idx = state.templates.length + 1;
      base.template_id = "tpl-ops-standard-" + idx;
      base.name = "Standard Template " + idx + ": Regulated Multi-BU Blueprint";
      base.agent_name = "regulated-bu-specialist-" + idx;
      base.risk_tier = "AG3";
      base.sdp_pii_mode = "BLOCK_ON_MATCH";
      state.opsSelectedTemplate = base;
      renderAll();
    });

    const saveTplBtn = el("button", "primary-btn", "Save Template Configuration");
    saveTplBtn.type = "button";
    saveTplBtn.addEventListener("click", async () => {
      saveTplBtn.disabled = true;
      try {
        const res = await apiPost("/api/ops/templates", tpl);
        state.templates = res.templates;
        state.opsSelectedTemplate = deepClone(res.template);
        showGlobalAlert(
          "Saved template '" + res.template.name + "' - immediately live in Persona 1!",
          false
        );
        renderAll();
      } catch (err) {
        showGlobalAlert("Save failed: " + err.message, true);
      } finally {
        saveTplBtn.disabled = false;
      }
    });
    actions.appendChild(newBtn);
    actions.appendChild(saveTplBtn);
    hdr.appendChild(actions);
    barCard.appendChild(hdr);

    const selRow = el("div", "btn-row");
    state.templates.forEach((t) => {
      const b = el(
        "button",
        tpl.template_id === t.template_id ? "primary-btn" : "small-btn",
        t.name
      );
      b.type = "button";
      b.addEventListener("click", () => {
        state.opsSelectedTemplate = deepClone(t);
        renderAll();
      });
      selRow.appendChild(b);
    });
    barCard.appendChild(selRow);

    const fGrid = el("div", "form-grid");
    fGrid.style.marginBlockStart = "0.9rem";

    const nameFg = el("div", "field-group");
    const nameLbl = el("label", "", "Template Display Name");
    nameLbl.setAttribute("for", "ops-tpl-name");
    const nameInp = el("input", "ctrl-input");
    nameInp.id = "ops-tpl-name";
    nameInp.type = "text";
    nameInp.value = tpl.name;
    nameInp.addEventListener("change", () => {
      tpl.name = nameInp.value.trim() || tpl.name;
    });
    nameFg.appendChild(nameLbl);
    nameFg.appendChild(nameInp);
    fGrid.appendChild(nameFg);

    const sdpFg = el("div", "field-group");
    const sdpLbl = el("label", "", "Default SDP PII Policy");
    sdpLbl.setAttribute("for", "ops-tpl-sdp");
    const sdpSel = el("select", "ctrl-select");
    sdpSel.id = "ops-tpl-sdp";
    ["DEIDENTIFY_INLINE", "BLOCK_ON_MATCH", "INSPECT_ONLY"].forEach((m) => {
      const o = el("option", "", m);
      o.value = m;
      if (tpl.sdp_pii_mode === m) {
        o.selected = true;
      }
      sdpSel.appendChild(o);
    });
    sdpSel.addEventListener("change", () => {
      tpl.sdp_pii_mode = sdpSel.value;
    });
    sdpFg.appendChild(sdpLbl);
    sdpFg.appendChild(sdpSel);
    fGrid.appendChild(sdpFg);

    const celFg = el("div", "field-group");
    const celLbl = el("label", "", "Per-Tool UAP CEL Gate");
    celLbl.setAttribute("for", "ops-tpl-cel");
    const celSel = el("select", "ctrl-select");
    celSel.id = "ops-tpl-cel";
    [
      ["true", "Enforced (Block destructiveHint=true)"],
      ["false", "Disabled (Coarse Gateway Scope)"],
    ].forEach(([v, txt]) => {
      const o = el("option", "", txt);
      o.value = v;
      if (String(tpl.uap_cel_per_tool_enforced) === v) {
        o.selected = true;
      }
      celSel.appendChild(o);
    });
    celSel.addEventListener("change", () => {
      tpl.uap_cel_per_tool_enforced = celSel.value === "true";
    });
    celFg.appendChild(celLbl);
    celFg.appendChild(celSel);
    fGrid.appendChild(celFg);

    barCard.appendChild(fGrid);
    stage.appendChild(barCard);

    stage.appendChild(
      renderNineSlotVisualCanvas(tpl, true, () => {
        renderRightInspector();
      })
    );
  }

  function renderOpsMetricsView(stage, showLedgerOnly) {
    const m = state.opsMetrics;
    if (!m) {
      return;
    }

    const kpis = el("div", "kpi-grid");
    const k1 = el("div", "kpi-card");
    k1.appendChild(el("div", "kpi-label", "Total Agent Deployments"));
    k1.appendChild(el("div", "kpi-value", String(m.total_deployments)));
    k1.appendChild(
      el(
        "div",
        "kpi-sub",
        m.standard_template_count +
          " Standard | " +
          m.custom_or_uploaded_count +
          " Custom / Uploaded"
      )
    );
    kpis.appendChild(k1);

    const k2 = el("div", "kpi-card kpi-success");
    k2.appendChild(el("div", "kpi-label", "Remediated Prior to Deployment"));
    k2.appendChild(
      el(
        "div",
        "kpi-value",
        m.remediated_prior_to_deploy_pct +
          "% (" +
          m.remediated_prior_to_deploy_count +
          "/" +
          m.total_deployments +
          ")"
      )
    );
    k2.appendChild(
      el("div", "kpi-sub", m.clean_first_pass_count + " clean first-pass deployments")
    );
    kpis.appendChild(k2);

    const k3 = el("div", "kpi-card kpi-success");
    k3.appendChild(el("div", "kpi-label", "Avg Evaluation Score Uplift"));
    k3.appendChild(
      el("div", "kpi-value", m.avg_initial_eval_score + " -> " + m.avg_final_eval_score)
    );
    k3.appendChild(el("div", "kpi-sub", "+" + m.avg_score_uplift + " pts pre-deploy remediation gain"));
    kpis.appendChild(k3);

    const orig = m.origin_breakdown || {};
    const k4 = el("div", "kpi-card");
    k4.appendChild(el("div", "kpi-label", "Template Composition Origin"));
    k4.appendChild(
      el(
        "div",
        "kpi-value",
        (orig.custom_composed || 0) + " Custom | " + (orig.uploaded_manifest || 0) + " Uploaded"
      )
    );
    k4.appendChild(
      el(
        "div",
        "kpi-sub",
        (orig.standard_enterprise_mock || 0) +
          " Mocked Std | " +
          (orig.standard_gcp_native || 0) +
          " GCP Std"
      )
    );
    kpis.appendChild(k4);
    stage.appendChild(kpis);

    if (!showLedgerOnly) {
      const adoptCard = el("div", "card");
      const aHdr = el("div", "card-header");
      const aLeft = el("div", "");
      aLeft.appendChild(
        el("h3", "", platformLabel() + " Component Selection Mix Across All Deployments")
      );
      aLeft.appendChild(
        el(
          "p",
          "muted-note",
          "Tracks how often each of the 9 platform slots was deployed with " +
            mockStackShortLabel() +
            ", GCP Agent Platform, or 4-Tier Coexistence Bridge."
        )
      );
      aHdr.appendChild(aLeft);
      const leg = el("div", "btn-row");
      leg.appendChild(el("span", "subtle-tag", mockStackShortLabel()));
      leg.appendChild(el("span", "status-chip chip-ready", "GCP Native"));
      leg.appendChild(el("span", "status-chip", "Coexistence Bridge"));
      aHdr.appendChild(leg);
      adoptCard.appendChild(aHdr);

      const tot = Math.max(1, m.total_deployments);
      (m.component_adoption || []).forEach((slot) => {
        const row = el("div", "bar-row");
        row.appendChild(el("strong", "", slot.step + ". " + slot.capability_name));

        const track = el("div", "bar-track");
        const cMock = slot.counts.enterprise_mock || 0;
        const cGcp = slot.counts.gcp_native || 0;
        const cCoex = slot.counts.coexistence_bridge || 0;
        if (cMock > 0) {
          const s = el("div", "bar-seg-mock");
          s.style.inlineSize = (cMock / tot) * 100 + "%";
          track.appendChild(s);
        }
        if (cGcp > 0) {
          const s = el("div", "bar-seg-gcp");
          s.style.inlineSize = (cGcp / tot) * 100 + "%";
          track.appendChild(s);
        }
        if (cCoex > 0) {
          const s = el("div", "bar-seg-coex");
          s.style.inlineSize = (cCoex / tot) * 100 + "%";
          track.appendChild(s);
        }
        row.appendChild(track);
        row.appendChild(
          el("span", "mono-note", cMock + "M / " + cGcp + "G / " + cCoex + "C")
        );
        adoptCard.appendChild(row);
      });
      stage.appendChild(adoptCard);
    }

    // Searchable Deployment Governance Ledger Table
    const ledgerCard = el("div", "card heavy-below-fold");
    const lHdr = el("div", "card-header");
    lHdr.appendChild(
      el("h3", "", "All Agent Deployments (Click Any Row to Inspect in Right Tray)")
    );
    const searchWrap = el("div", "field-group");
    const sLbl = el("label", "visually-hidden", "Filter deployments by agent or BU");
    sLbl.setAttribute("for", "ops-dep-search");
    const sInp = el("input", "ctrl-input");
    sInp.id = "ops-dep-search";
    sInp.type = "search";
    sInp.placeholder = "Filter by agent, ID, or BU...";
    sInp.value = state.opsSearchQuery;
    sInp.addEventListener("input", () => {
      state.opsSearchQuery = sInp.value;
      renderCenterStage();
    });
    searchWrap.appendChild(sLbl);
    searchWrap.appendChild(sInp);
    lHdr.appendChild(searchWrap);
    ledgerCard.appendChild(lHdr);

    const q = state.opsSearchQuery.trim().toLowerCase();
    const rows = (m.deployments || []).filter((d) => {
      if (!q) {
        return true;
      }
      return (
        d.agent_name.toLowerCase().includes(q) ||
        d.deployment_id.toLowerCase().includes(q) ||
        String(d.business_unit_label || "").toLowerCase().includes(q)
      );
    });

    const tWrap = el("div", "table-scroll-wrap");
    const tbl = el("table", "data-table");
    tbl.appendChild(el("caption", "", "Operational Governance History Across Agent Deployments"));
    const thead = el("thead");
    const htr = el("tr");
    [
      "Deployment ID",
      "Agent Workload",
      "Business Unit",
      "Origin",
      "Initial -> Deployed Score",
      "Remediated?",
      "Risk",
    ].forEach((h) => {
      const th = el("th", "", h);
      th.setAttribute("scope", "col");
      htr.appendChild(th);
    });
    thead.appendChild(htr);
    tbl.appendChild(thead);

    const tbody = el("tbody");
    rows.forEach((d) => {
      const tr = el("tr", "clickable-row");
      tr.appendChild(el("td", "mono-note", d.deployment_id));
      tr.appendChild(el("td", "", d.agent_name));
      tr.appendChild(el("td", "", d.business_unit_label || d.business_unit));
      tr.appendChild(el("td", "", originLabel(d.origin)));
      tr.appendChild(
        el("td", "mono-note", d.initial_eval_score + " -> " + d.final_eval_score)
      );
      const remTd = el("td");
      remTd.appendChild(
        el(
          "span",
          d.remediated_prior_to_deploy ? "status-chip" : "subtle-tag",
          d.remediated_prior_to_deploy
            ? "Yes (" + d.remediations_applied_count + " fixes)"
            : "First-Pass Clean"
        )
      );
      tr.appendChild(remTd);
      tr.appendChild(el("td", "", d.risk_tier));
      tr.addEventListener("click", () => {
        state.inspectorContext = { kind: "deployment", id: d.deployment_id, data: d };
        activateRightTrayTab("inspector");
        renderRightInspector();
      });
      tbody.appendChild(tr);
    });
    tbl.appendChild(tbody);
    tWrap.appendChild(tbl);
    ledgerCard.appendChild(tWrap);
    stage.appendChild(ledgerCard);
  }

  function renderOpsDay2Controls(stage) {
    if (state.activeNode === "ops-day2-steward") {
      const grid = el("div", "template-card-grid");

      // Kill switch
      const ksCard = el("div", "card");
      ksCard.appendChild(el("h3", "", "Centralized Kill Switch"));
      const curStatus = (state.agentState && state.agentState.status) || "ACTIVE";
      ksCard.appendChild(
        el(
          "p",
          "muted-note",
          "Current State: " + curStatus + " (halts model, MCP, and A2A execution atomically)."
        )
      );
      const ksBtns = el("div", "btn-row");
      ["ACTIVE", "PAUSED", "DISABLED"].forEach((st) => {
        const cls = st === "ACTIVE" ? "small-btn" : st === "PAUSED" ? "small-btn warn" : "small-btn danger";
        const b = el("button", cls, "Set " + st);
        b.type = "button";
        b.addEventListener("click", async () => {
          const res = await apiPost("/api/steward/kill-switch", { status: st });
          state.agentState = res.agent_state;
          updatePlatformServices(res.platform_services, true);
          activateRightTrayTab("pipeline");
          renderAll();
        });
        ksBtns.appendChild(b);
      });
      ksCard.appendChild(ksBtns);
      grid.appendChild(ksCard);

      // Atomic Wallet
      const wlCard = el("div", "card");
      wlCard.appendChild(el("h3", "", terms().wallet_name || "Atomic Nano-USD Wallet"));
      const spent = (((state.walletState && state.walletState.spent_nano_usd) || 0) / 1e9).toFixed(6);
      const cap = (((state.walletState && state.walletState.monthly_cap_nano_usd) || 0) / 1e9).toFixed(4);
      wlCard.appendChild(el("p", "mono-note", "$" + spent + " spent / $" + cap + " cap"));
      const wBtns = el("div", "btn-row");
      const bNorm = el("button", "small-btn", "Reset $15.00 Sandbox Cap");
      bNorm.type = "button";
      bNorm.addEventListener("click", async () => {
        const res = await apiPost("/api/steward/wallet-cap", {
          monthly_cap_nano_usd: 15000000000,
          reset_spend: true,
        });
        state.walletState = res.wallet_state;
        updatePlatformServices(res.platform_services, true);
        renderAll();
      });
      const bTight = el("button", "small-btn warn", "Simulate 403 Cap Exhaustion");
      bTight.type = "button";
      bTight.addEventListener("click", async () => {
        const res = await apiPost("/api/steward/wallet-cap", {
          monthly_cap_nano_usd: 1000,
          reset_spend: false,
        });
        state.walletState = res.wallet_state;
        updatePlatformServices(res.platform_services, true);
        renderAll();
      });
      wBtns.appendChild(bNorm);
      wBtns.appendChild(bTight);
      wlCard.appendChild(wBtns);
      grid.appendChild(wlCard);

      // ADR-011 OBO
      const oboCard = el("div", "card");
      oboCard.appendChild(el("h3", "", "SPIFFE & ADR-011 azp OBO Verifier"));
      const out = el("p", "mono-note", (state.identityPosture && state.identityPosture.summary) || "");
      const oboBtn = el("button", "small-btn", "Verify ADR-011 Dual-Token Pair");
      oboBtn.type = "button";
      oboBtn.addEventListener("click", async () => {
        const res = await apiPost("/api/steward/obo-verify", {});
        out.textContent =
          "azp=" +
          res.adr011_valid_pair.authorized_party_azp +
          " verified=true | forged_azp_blocked=" +
          res.mismatched_azp_blocked_fail_closed;
        updatePlatformServices(res.platform_services, true);
      });
      oboCard.appendChild(out);
      oboCard.appendChild(oboBtn);
      grid.appendChild(oboCard);
      stage.appendChild(grid);
      return;
    }

    if (state.activeNode === "ops-day2-armor") {
      const card = el("div", "card");
      card.appendChild(el("h3", "", "Dynamic Per-Request Model Armor Policy Router & Threat Tester"));
      const fGrid = el("div", "form-grid");
      const buSel = el("select", "ctrl-select");
      buSel.id = "lab-bu-sel";
      Object.entries(terms().business_units || { core_cable: "Core Cable", intl_sky: "Intl Strict" }).forEach(
        ([k, v]) => {
          const o = el("option", "", v);
          o.value = k;
          buSel.appendChild(o);
        }
      );
      const sdpSel = el("select", "ctrl-select");
      sdpSel.id = "lab-sdp-sel";
      ["DEIDENTIFY_INLINE", "BLOCK_ON_MATCH", "INSPECT_ONLY"].forEach((m) => {
        const o = el("option", "", m);
        o.value = m;
        sdpSel.appendChild(o);
      });
      const fg1 = el("div", "field-group");
      const l1 = el("label", "", "Business Unit");
      l1.setAttribute("for", "lab-bu-sel");
      fg1.appendChild(l1);
      fg1.appendChild(buSel);
      const fg2 = el("div", "field-group");
      const l2 = el("label", "", "SDP PII Mode");
      l2.setAttribute("for", "lab-sdp-sel");
      fg2.appendChild(l2);
      fg2.appendChild(sdpSel);
      fGrid.appendChild(fg1);
      fGrid.appendChild(fg2);
      card.appendChild(fGrid);

      const taLbl = el("label", "ctrl-label", "Sample Payload");
      taLbl.setAttribute("for", "lab-threat-ta");
      const ta = el("textarea", "prompt-textarea");
      ta.id = "lab-threat-ta";
      ta.rows = 2;
      ta.value = "Subscriber SSN 123-45-6789 on CPE MAC aa:bb:cc:dd:ee:ff";
      card.appendChild(taLbl);
      card.appendChild(ta);

      const verdictBox = el("div", "code-box", "Click Inspect Payload to test Dynamic Policy Router.");
      const runBtn = el("button", "primary-btn", "Inspect Payload");
      runBtn.type = "button";
      runBtn.addEventListener("click", async () => {
        const res = await apiPost("/api/steward/guardrail-test", {
          sample_text: ta.value,
          dynamic_policy: {
            business_unit: buSel.value,
            risk_tier: "AG3",
            pi_and_jailbreak_threshold: "LOW_AND_ABOVE",
            malicious_uri_filter: true,
            sdp_pii_mode: sdpSel.value,
            rai_sensitivity: "MEDIUM_AND_ABOVE",
            ensemble_role: "tier0_prefilter",
          },
        });
        verdictBox.textContent = JSON.stringify(
          {
            allowed: res.allowed,
            action_taken: res.action_taken,
            resolved_template: res.resolved_template,
            sanitized_text: res.sanitized_text,
          },
          null,
          2
        );
        updatePlatformServices(res.platform_services, true);
      });
      card.appendChild(runBtn);
      card.appendChild(verdictBox);
      stage.appendChild(card);
      return;
    }

    if (state.activeNode === "ops-day2-flywheel") {
      const card = el("div", "card");
      const hdr = el("div", "card-header");
      hdr.appendChild(el("h3", "", "6-Stage Cross-Cloud Closed-Loop Evaluation & Prompt Optimizer"));
      const runBtn = el("button", "primary-btn", "Run 6-Stage Optimization Flywheel");
      runBtn.type = "button";
      const outBox = el(
        "pre",
        "code-box",
        (state.promptRegistry && state.promptRegistry.v2_prompt) || ""
      );
      runBtn.addEventListener("click", async () => {
        runBtn.disabled = true;
        runBtn.textContent = "Running 6 Stages...";
        try {
          const res = await apiPost("/api/steward/closed-loop-eval", {});
          outBox.textContent =
            "Promoted Golden Blueprint v2 (" +
            res.v2_candidate.behavior_score +
            "/100 in " +
            res.elapsed_seconds +
            "s)\n\n" +
            (res.v2_prompt_text || "");
          updatePlatformServices(res.platform_services, true);
        } finally {
          runBtn.disabled = false;
          runBtn.textContent = "Run 6-Stage Optimization Flywheel";
        }
      });
      hdr.appendChild(runBtn);
      card.appendChild(hdr);
      card.appendChild(outBox);
      stage.appendChild(card);
      return;
    }

    // 8 Proofs
    const pCard = el("div", "card");
    const pHdr = el("div", "card-header");
    pHdr.appendChild(el("h3", "", "8 Live Modular Coexistence Proofs"));
    const allBtn = el("button", "primary-btn", "Run All 8 Live Proofs");
    allBtn.type = "button";
    const grid = el("div", "template-card-grid");
    PROOF_DEFINITIONS.forEach((def) => {
      const box = el("div", "template-choice-card");
      box.appendChild(el("strong", "", def.title));
      box.appendChild(el("div", "mono-note", "Consolidates: " + def.vendors));
      const resLine = el("div", "muted-note", "Ready");
      resLine.id = "day2-proof-" + def.id;
      const b = el("button", "small-btn", "Run Proof #" + def.id);
      b.type = "button";
      b.addEventListener("click", async () => {
        resLine.textContent = "Running...";
        const res = await apiPost("/api/steward/proofs/" + def.id, {});
        resLine.textContent =
          "[" + (res.passed ? "PASS" : "FAIL") + " " + res.latency_ms + "ms] " + res.measured_evidence;
        updatePlatformServices(res.platform_services, true);
      });
      box.appendChild(resLine);
      box.appendChild(b);
      grid.appendChild(box);
    });
    allBtn.addEventListener("click", async () => {
      allBtn.disabled = true;
      const res = await apiPost("/api/steward/proofs-all", {});
      (res.proofs || []).forEach((p) => {
        const n = document.getElementById("day2-proof-" + p.proof_id);
        if (n) {
          n.textContent = "[" + (p.passed ? "PASS" : "FAIL") + "] " + p.measured_evidence;
        }
      });
      updatePlatformServices(res.platform_services, true);
      allBtn.disabled = false;
    });
    pHdr.appendChild(allBtn);
    pCard.appendChild(pHdr);
    pCard.appendChild(grid);
    stage.appendChild(pCard);
  }

  /* ================= PERSONA 3 CENTER VIEWS (EXECUTIVE FINOPS) ================= */
  async function refreshExecutiveData() {
    const qs =
      "?business_unit=" +
      encodeURIComponent(state.execBuFilter) +
      "&origin=" +
      encodeURIComponent(state.execOriginFilter);
    state.execCosts = await apiGet("/api/executive/costs" + qs);
    renderAll();
  }

  function renderPersona3Header(headerBox) {
    const top = el("div", "center-header-top");
    const left = el("div", "");
    left.appendChild(
      el("div", "breadcrumb-line", "Persona 3: Agent Governance Operations Executive Management")
    );
    const titles = {
      "exec-deployments": "Per-Agent Template Deployment Cost Attribution",
      "exec-components": "Aggregate " + platformLabel() + " Governance Component Cost Rollup",
      "exec-tco": "Enterprise Scale TCO & Point-Vendor Consolidation Simulator",
    };
    left.appendChild(el("h2", "", titles[state.activeNode] || "Executive FinOps Overview"));
    left.appendChild(
      el(
        "p",
        "muted-note",
        "Historical and live cost attribution across every agent deployment and all 9 governance platform components."
      )
    );
    top.appendChild(left);

    if (state.activeNode !== "exec-tco") {
      const filters = el("div", "btn-row");
      const buLbl = el("label", "ctrl-label", "BU:");
      buLbl.setAttribute("for", "exec-bu-filter");
      const buSel = el("select", "ctrl-select");
      buSel.id = "exec-bu-filter";
      buSel.style.inlineSize = "auto";
      const buOpts = Object.assign(
        { all: "All Business Units" },
        terms().business_units || {}
      );
      Object.entries(buOpts).forEach(([k, v]) => {
        const o = el("option", "", v);
        o.value = k;
        if (state.execBuFilter === k) {
          o.selected = true;
        }
        buSel.appendChild(o);
      });
      buSel.addEventListener("change", () => {
        state.execBuFilter = buSel.value;
        refreshExecutiveData();
      });

      const orLbl = el("label", "ctrl-label", "Template:");
      orLbl.setAttribute("for", "exec-origin-filter");
      const orSel = el("select", "ctrl-select");
      orSel.id = "exec-origin-filter";
      orSel.style.inlineSize = "auto";
      [
        ["all", "All Template Types"],
        ["standard_enterprise_mock", mockStackShortLabel()],
        ["standard_gcp_native", "GCP Agent Platform"],
        ["custom_composed", "Custom Composed"],
        ["uploaded_manifest", "Uploaded Manifest"],
      ].forEach(([k, v]) => {
        const o = el("option", "", v);
        o.value = k;
        if (state.execOriginFilter === k) {
          o.selected = true;
        }
        orSel.appendChild(o);
      });
      orSel.addEventListener("change", () => {
        state.execOriginFilter = orSel.value;
        refreshExecutiveData();
      });

      filters.appendChild(buLbl);
      filters.appendChild(buSel);
      filters.appendChild(orLbl);
      filters.appendChild(orSel);
      top.appendChild(filters);
    }

    headerBox.appendChild(top);
  }

  function renderExecutiveKpis(stage, ex) {
    const kpis = el("div", "kpi-grid");
    const k1 = el("div", "kpi-card");
    k1.appendChild(el("div", "kpi-label", "Historical Cumulative Spend"));
    k1.appendChild(el("div", "kpi-value", fmtIntUsd(ex.total_historical_cumulative_usd)));
    k1.appendChild(
      el(
        "div",
        "kpi-sub",
        "Across " + ex.deployment_count + " historical + live deployments (incl. onboarding)"
      )
    );
    kpis.appendChild(k1);

    const k2 = el("div", "kpi-card");
    k2.appendChild(el("div", "kpi-label", "Active Monthly Run-Rate"));
    k2.appendChild(el("div", "kpi-value", fmtIntUsd(ex.total_monthly_run_rate_usd) + "/mo"));
    k2.appendChild(
      el("div", "kpi-sub", fmtIntUsd(ex.projected_annual_run_rate_usd) + "/yr annualized run-rate")
    );
    kpis.appendChild(k2);

    const k3 = el("div", "kpi-card");
    k3.appendChild(el("div", "kpi-label", "Avg Monthly Cost / Deployment"));
    k3.appendChild(el("div", "kpi-value", fmtUsd(ex.avg_cost_per_deployment_monthly_usd)));
    k3.appendChild(
      el("div", "kpi-sub", "One-time onboarding/eval total: " + fmtIntUsd(ex.total_onboarding_eval_usd))
    );
    kpis.appendChild(k3);

    const k4 = el("div", "kpi-card kpi-success");
    k4.appendChild(el("div", "kpi-label", "Annualized Consolidation Savings"));
    k4.appendChild(
      el("div", "kpi-value", fmtIntUsd(ex.projected_annual_consolidation_savings_usd) + "/yr")
    );
    k4.appendChild(el("div", "kpi-sub", "Saved vs. un-consolidated 3P guardrail & MicroVM sprawl"));
    kpis.appendChild(k4);
    stage.appendChild(kpis);
  }

  function renderExecutiveDeploymentsView(stage) {
    const ex = state.execCosts;
    if (!ex) {
      return;
    }
    renderExecutiveKpis(stage, ex);

    const card = el("div", "card");
    card.appendChild(
      el(
        "h3",
        "",
        "Cost Per Agent Template Deployment (Click Any Deployment for Itemized 9-Component Breakdown)"
      )
    );

    const tWrap = el("div", "table-scroll-wrap");
    const tbl = el("table", "data-table");
    tbl.appendChild(
      el("caption", "", "Per-Deployment Onboarding, Monthly Run-Rate, and Cumulative Spend")
    );
    const thead = el("thead");
    const htr = el("tr");
    [
      "Deployment",
      "Agent Workload",
      "Business Unit",
      "Template Origin",
      "Volume (M/mo)",
      "Onboarding/Eval",
      "Monthly Run-Rate",
      "Historical Total",
    ].forEach((h) => {
      const th = el("th", "", h);
      th.setAttribute("scope", "col");
      htr.appendChild(th);
    });
    thead.appendChild(htr);
    tbl.appendChild(thead);

    const tbody = el("tbody");
    (ex.deployments || []).forEach((d) => {
      const tr = el("tr", "clickable-row");
      tr.appendChild(el("td", "mono-note", d.deployment_id));
      tr.appendChild(el("td", "", d.agent_name));
      tr.appendChild(el("td", "", d.business_unit_label || d.business_unit));
      tr.appendChild(el("td", "", originLabel(d.origin)));
      tr.appendChild(el("td", "mono-note", d.estimated_monthly_turns_millions + "M"));
      tr.appendChild(el("td", "mono-note", fmtUsd(d.onboarding_eval_cost_usd)));
      tr.appendChild(el("td", "mono-note", fmtUsd(d.monthly_run_rate_usd)));
      tr.appendChild(el("td", "mono-note", fmtUsd(d.historical_cumulative_usd)));

      tr.addEventListener("click", () => {
        state.inspectorContext = { kind: "exec_deployment", id: d.deployment_id, data: d };
        activateRightTrayTab("inspector");
        renderRightInspector();
      });
      tbody.appendChild(tr);
    });
    tbl.appendChild(tbody);
    tWrap.appendChild(tbl);
    card.appendChild(tWrap);
    stage.appendChild(card);
  }

  function renderExecutiveComponentRollupView(stage) {
    const ex = state.execCosts;
    if (!ex) {
      return;
    }
    renderExecutiveKpis(stage, ex);

    const rollup = ex.component_cost_rollup || [];
    const maxHist = Math.max(
      1,
      ...rollup.map((c) => Number(c.historical_cumulative_usd || 0))
    );

    const chartCard = el("div", "card");
    const cHdr = el("div", "card-header");
    cHdr.appendChild(
      el(
        "h3",
        "",
        "Aggregate Historical Spend by " +
          platformLabel() +
          " Governance Component (All Deployments)"
      )
    );
    const leg = el("div", "btn-row");
    leg.appendChild(el("span", "subtle-tag", mockStackShortLabel()));
    leg.appendChild(el("span", "status-chip chip-ready", "GCP Native"));
    leg.appendChild(el("span", "status-chip", "Coexistence Bridge"));
    cHdr.appendChild(leg);
    chartCard.appendChild(cHdr);

    rollup.forEach((comp) => {
      const row = el("div", "bar-row");
      row.style.cursor = "pointer";
      row.appendChild(el("strong", "", comp.step + ". " + comp.capability_name));

      const track = el("div", "bar-track");
      const sp = comp.spend_by_provider_usd || {};
      [
        ["enterprise_mock", "bar-seg-mock"],
        ["gcp_native", "bar-seg-gcp"],
        ["coexistence_bridge", "bar-seg-coex"],
      ].forEach(([k, cls]) => {
        const v = Number(sp[k] || 0);
        if (v > 0) {
          const seg = el("div", cls);
          seg.style.inlineSize = (v / maxHist) * 100 + "%";
          track.appendChild(seg);
        }
      });
      row.appendChild(track);
      row.appendChild(
        el(
          "span",
          "mono-note",
          fmtIntUsd(comp.historical_cumulative_usd) + " (" + comp.share_of_total_pct + "%)"
        )
      );
      row.addEventListener("click", () => {
        state.inspectorContext = { kind: "exec_component", id: comp.slot_id, data: comp };
        activateRightTrayTab("inspector");
        renderRightInspector();
      });
      chartCard.appendChild(row);
    });
    stage.appendChild(chartCard);

    // Semantic Component Cost Rollup Table
    const tblCard = el("div", "card heavy-below-fold");
    const tWrap = el("div", "table-scroll-wrap");
    const tbl = el("table", "data-table");
    tbl.appendChild(
      el(
        "caption",
        "",
        "Aggregate Cost Breakdown Per Governance Component Across Historical Agent Deployments"
      )
    );
    const thead = el("thead");
    const htr = el("tr");
    [
      "Component",
      "Tier",
      "Mocked Stack Spend",
      "GCP Native Spend",
      "Coexistence Spend",
      "Monthly Run-Rate",
      "Historical Total",
      "Share %",
    ].forEach((h) => {
      const th = el("th", "", h);
      th.setAttribute("scope", "col");
      htr.appendChild(th);
    });
    thead.appendChild(htr);
    tbl.appendChild(thead);

    const tbody = el("tbody");
    rollup.forEach((comp) => {
      const sp = comp.spend_by_provider_usd || {};
      const tr = el("tr", "clickable-row");
      tr.appendChild(el("td", "", comp.step + ". " + comp.capability_name));
      tr.appendChild(el("td", "", comp.tier));
      tr.appendChild(el("td", "mono-note", fmtUsd(sp.enterprise_mock || 0)));
      tr.appendChild(el("td", "mono-note", fmtUsd(sp.gcp_native || 0)));
      tr.appendChild(el("td", "mono-note", fmtUsd(sp.coexistence_bridge || 0)));
      tr.appendChild(el("td", "mono-note", fmtUsd(comp.monthly_run_rate_usd)));
      tr.appendChild(el("td", "mono-note", fmtUsd(comp.historical_cumulative_usd)));
      tr.appendChild(el("td", "mono-note", comp.share_of_total_pct + "%"));
      tr.addEventListener("click", () => {
        state.inspectorContext = { kind: "exec_component", id: comp.slot_id, data: comp };
        activateRightTrayTab("inspector");
        renderRightInspector();
      });
      tbody.appendChild(tr);
    });
    tbl.appendChild(tbody);
    tWrap.appendChild(tbl);
    tblCard.appendChild(tWrap);
    stage.appendChild(tblCard);
  }

  function renderExecutiveTcoSimulator(stage) {
    const card = el("div", "card");
    card.appendChild(
      el("h3", "", "Enterprise Guardrail & Coexistence Scale Simulator (1,000 Tokens / Turn)")
    );
    card.appendChild(
      el(
        "p",
        "muted-note",
        "Models annual run-rate across enterprise turn volumes anchored to published public list pricing ($0.10 / 1M tokens Model Armor + 20% Ensemble Tier-0 escalation)."
      )
    );

    const sliderLbl = el("label", "ctrl-label", "Daily Enterprise Turn Volume: 10,000,000 turns / day");
    sliderLbl.setAttribute("for", "exec-tco-slider");
    const slider = el("input", "full-slider");
    slider.id = "exec-tco-slider";
    slider.type = "range";
    slider.min = "1000000";
    slider.max = "50000000";
    slider.step = "1000000";
    slider.value = "10000000";
    card.appendChild(sliderLbl);
    card.appendChild(slider);

    const kpiBox = el("div", "kpi-grid");
    card.appendChild(kpiBox);

    const populateTcoCards = (tco) => {
      if (!tco) {
        return;
      }
      kpiBox.replaceChildren();
      const ensVal =
        tco.ensemble_tier0_hybrid_annual_usd ||
        Math.round(tco.google_model_armor_annual_usd + 0.2 * tco.aws_bedrock_guardrails_annual_usd);
      [
        ["Azure AI Content Safety", tco.azure_content_safety_annual_usd, "List baseline", ""],
        ["AWS Bedrock Guardrails", tco.aws_bedrock_guardrails_annual_usd, "Standalone API", ""],
        [
          "Google Model Armor ($0.10/1M)",
          tco.google_model_armor_annual_usd,
          "Saves " + fmtIntUsd(tco.annual_savings_vs_azure_usd) + "/yr (90%)",
          "kpi-success",
        ],
        [
          "Ensemble Tier-0 Hybrid",
          ensVal,
          "100% Inline SDP/URL + 20% Voter",
          "kpi-success",
        ],
      ].forEach(([lbl, val, sub, cls]) => {
        const k = el("div", "kpi-card " + cls);
        k.appendChild(el("div", "kpi-label", lbl));
        k.appendChild(el("div", "kpi-value", fmtIntUsd(val) + "/yr"));
        k.appendChild(el("div", "kpi-sub", sub));
        kpiBox.appendChild(k);
      });
    };

    populateTcoCards(state.tcoDefault);
    slider.addEventListener("input", async () => {
      const turns = parseInt(slider.value, 10);
      sliderLbl.textContent =
        "Daily Enterprise Turn Volume: " + turns.toLocaleString() + " turns / day";
      const tco = await apiPost("/api/steward/tco", {
        daily_turns: turns,
        tokens_per_turn: 1000,
      });
      populateTcoCards(tco);
    });

    stage.appendChild(card);
  }

  /* ================= ZONE 4 RENDERER: RIGHT DYNAMIC MENU TRAY ================= */
  function activateRightTrayTab(mode) {
    state.rightTrayTab = mode;
    const tInsp = document.getElementById("tray-tab-inspector");
    const tPipe = document.getElementById("tray-tab-pipeline");
    const vInsp = document.getElementById("tray-inspector-view");
    const vPipe = document.getElementById("tray-pipeline-view");

    const isInsp = mode === "inspector";
    tInsp.classList.toggle("active", isInsp);
    tInsp.setAttribute("aria-selected", String(isInsp));
    tInsp.setAttribute("tabindex", isInsp ? "0" : "-1");

    tPipe.classList.toggle("active", !isInsp);
    tPipe.setAttribute("aria-selected", String(!isInsp));
    tPipe.setAttribute("tabindex", !isInsp ? "0" : "-1");

    vInsp.classList.toggle("hidden", !isInsp);
    vPipe.classList.toggle("hidden", isInsp);
  }

  function renderRightInspector() {
    const box = document.getElementById("tray-inspector-content");
    if (!box) {
      return;
    }
    box.replaceChildren();
    const ctx = state.inspectorContext || {};

    // 1. Remediation Diff & Custom Override Editor
    if (ctx.kind === "remediation" && ctx.data) {
      const rec = ctx.data;
      const spec = state.slotById[rec.slot_id] || state.slotCatalog[0];
      box.appendChild(el("span", "status-chip chip-warn", "Remediation Inspector"));
      box.appendChild(el("h3", "slot-card-title", rec.rule_id + ": " + rec.title));
      box.appendChild(el("p", "muted-note", rec.finding_detail));

      box.appendChild(el("strong", "ctrl-label", "Current Non-Compliant Config"));
      box.appendChild(el("pre", "code-box", JSON.stringify(rec.before_config, null, 2)));

      box.appendChild(el("strong", "ctrl-label", "Recommended Target Patch"));
      box.appendChild(el("pre", "code-box", JSON.stringify(rec.after_config, null, 2)));

      if (rec.terraform_hcl_preview) {
        box.appendChild(el("strong", "ctrl-label", "Generated Terraform Paved-Path HCL"));
        box.appendChild(el("pre", "code-box", rec.terraform_hcl_preview));
      }

      // Manual customization controls (Persona 1 UJ5)
      if (state.activePersona === "end-user" && state.workingTemplate) {
        const editCard = el("div", "tier-block");
        editCard.appendChild(el("h4", "tier-block-title", "Manual Override & Custom Parameter Editor"));

        const pLbl = el("label", "ctrl-label", "Select Target Provider");
        pLbl.setAttribute("for", "tray-custom-prov");
        const pSel = el("select", "ctrl-select");
        pSel.id = "tray-custom-prov";
        ["coexistence_bridge", "gcp_native", "enterprise_mock"].forEach((pv) => {
          const o = el("option", "", providerShortLabel(pv));
          o.value = pv;
          if (pv === rec.recommended_provider) {
            o.selected = true;
          }
          pSel.appendChild(o);
        });
        editCard.appendChild(pLbl);
        editCard.appendChild(pSel);

        const applyCustomBtn = el("button", "primary-btn", "Apply Custom Override");
        applyCustomBtn.type = "button";
        applyCustomBtn.style.marginBlockStart = "0.6rem";
        applyCustomBtn.addEventListener("click", async () => {
          const res = await apiPost("/api/templates/remediate", {
            template: state.workingTemplate,
            rule_id: rec.rule_id,
            action: "customize",
            custom_provider: pSel.value,
            custom_parameters: {
              sdp_pii_mode:
                state.workingTemplate.business_unit === "intl_sky"
                  ? "BLOCK_ON_MATCH"
                  : "DEIDENTIFY_INLINE",
              uap_cel_per_tool_enforced: true,
              clear_static_secrets: true,
              intake_id:
                state.workingTemplate.intake_id ||
                (state.tenant && state.tenant.governance_defaults.intake_record_id) ||
                "INT-2026-01",
            },
          });
          state.workingTemplate = res.template;
          state.currentEvaluation = res.evaluation;
          if (res.platform_services) {
            updatePlatformServices(res.platform_services, true);
          }
          showGlobalAlert("Applied custom override for " + rec.rule_id + ".", false);
          renderAll();
        });
        editCard.appendChild(applyCustomBtn);
        box.appendChild(editCard);
      }
      return;
    }

    // 2. Rubric Rule Inspector (Persona 2)
    if (ctx.kind === "rubric_rule" && ctx.data) {
      const rule = ctx.data;
      box.appendChild(el("span", "status-chip chip-ready", "Rubric Rule Editor"));
      box.appendChild(el("h3", "slot-card-title", rule.rule_id + ": " + rule.title));
      box.appendChild(el("p", "muted-note", rule.description));

      const remLbl = el("label", "ctrl-label", "Remediation Prescription Text");
      remLbl.setAttribute("for", "tray-rule-rem-txt");
      const remTa = el("textarea", "prompt-textarea");
      remTa.id = "tray-rule-rem-txt";
      remTa.rows = 3;
      remTa.value = rule.remediation_summary || "";
      remTa.addEventListener("change", () => {
        rule.remediation_summary = remTa.value;
      });
      box.appendChild(remLbl);
      box.appendChild(remTa);

      const provLbl = el("label", "ctrl-label", "Recommended Auto-Fix Provider");
      provLbl.setAttribute("for", "tray-rule-prov");
      const provSel = el("select", "ctrl-select");
      provSel.id = "tray-rule-prov";
      ["coexistence_bridge", "gcp_native", "enterprise_mock"].forEach((pv) => {
        const o = el("option", "", providerShortLabel(pv));
        o.value = pv;
        if (rule.remediation_provider === pv) {
          o.selected = true;
        }
        provSel.appendChild(o);
      });
      provSel.addEventListener("change", () => {
        rule.remediation_provider = provSel.value;
        renderCenterStage();
      });
      box.appendChild(provLbl);
      box.appendChild(provSel);
      return;
    }

    // 3. Deployment Audit or Executive Per-Deployment 9-Component Cost Breakdown
    if ((ctx.kind === "deployment" || ctx.kind === "exec_deployment") && ctx.data) {
      const d = ctx.data;
      box.appendChild(el("span", "status-chip", d.deployment_id));
      box.appendChild(el("h3", "slot-card-title", d.agent_name));
      box.appendChild(
        el(
          "p",
          "muted-note",
          (d.business_unit_label || d.business_unit) +
            " | " +
            originLabel(d.origin) +
            " | Score: " +
            d.initial_eval_score +
            " -> " +
            d.final_eval_score
        )
      );
      box.appendChild(
        el(
          "div",
          "mono-note",
          "Monthly: " +
            fmtUsd(d.monthly_run_rate_usd) +
            " | Historical (" +
            d.months_active +
            " mo): " +
            fmtUsd(d.historical_cumulative_usd)
        )
      );

      const tbl = el("table", "data-table");
      tbl.appendChild(el("caption", "", "Itemized 9-Component Cost & Provider Attribution"));
      const tbody = el("tbody");
      (d.component_costs || []).forEach((cc) => {
        const tr = el("tr");
        tr.appendChild(el("td", "", cc.step + ". " + cc.capability_name));
        tr.appendChild(el("td", "", providerShortLabel(cc.provider)));
        tr.appendChild(el("td", "mono-note", fmtUsd(cc.historical_cumulative_usd)));
        tbody.appendChild(tr);
      });
      tbl.appendChild(tbody);
      box.appendChild(tbl);
      return;
    }

    // 4. Executive Aggregate Component Drill-Down
    if (ctx.kind === "exec_component" && ctx.data) {
      const c = ctx.data;
      box.appendChild(el("span", "status-chip chip-ready", c.tier + " Component FinOps"));
      box.appendChild(el("h3", "slot-card-title", c.step + ". " + c.capability_name));
      box.appendChild(
        el(
          "p",
          "muted-note",
          "Cumulative Historical Spend: " +
            fmtUsd(c.historical_cumulative_usd) +
            " (" +
            c.share_of_total_pct +
            "% of total governance spend)"
        )
      );
      box.appendChild(el("div", "mono-note", "Consolidates: " + c.consolidates));

      const tbl = el("table", "data-table");
      tbl.appendChild(el("caption", "", "Top Consuming Agent Deployments"));
      const tbody = el("tbody");
      (c.top_deployments || []).forEach((td) => {
        const tr = el("tr");
        tr.appendChild(el("td", "", td.agent_name));
        tr.appendChild(el("td", "", providerShortLabel(td.provider)));
        tr.appendChild(el("td", "mono-note", fmtUsd(td.historical_cumulative_usd)));
        tbody.appendChild(tr);
      });
      tbl.appendChild(tbody);
      box.appendChild(tbl);
      return;
    }

    // Default: Slot Component Inspector & Live Parameter Configurator
    const targetTpl =
      state.activePersona === "governance-ops" && state.activeNode === "ops-templates"
        ? state.opsSelectedTemplate
        : state.workingTemplate;
    const spec = state.slotById[ctx.id] || state.slotCatalog[0];
    if (!spec || !targetTpl) {
      return;
    }
    const sid = spec.slot_id;
    const comp = (targetTpl.components && targetTpl.components[sid]) || {
      slot_id: sid,
      provider: "coexistence_bridge",
      enabled: true,
    };

    box.appendChild(el("span", "status-chip chip-ready", spec.tier_label));
    box.appendChild(el("h3", "slot-card-title", "Slot " + spec.step + ": " + spec.capability_name));
    box.appendChild(el("div", "mono-note", "API Surface: " + spec.api_surface));
    box.appendChild(el("div", "muted-note", "Consolidates: " + spec.consolidates));

    const pLbl = el("label", "ctrl-label", "Selected Slot Provider");
    pLbl.setAttribute("for", "inspector-slot-prov");
    const pSel = el("select", "ctrl-select");
    pSel.id = "inspector-slot-prov";
    [
      ["coexistence_bridge", spec.provider_labels.coexistence_bridge],
      ["enterprise_mock", spec.provider_labels.enterprise_mock],
      ["gcp_native", spec.provider_labels.gcp_native],
      ["unconfigured", spec.provider_labels.unconfigured],
    ].forEach(([val, txt]) => {
      const o = el("option", "", txt);
      o.value = val;
      if (comp.provider === val) {
        o.selected = true;
      }
      pSel.appendChild(o);
    });
    pSel.addEventListener("change", async () => {
      const next = pSel.value;
      targetTpl.components[sid] = {
        slot_id: sid,
        provider: next,
        enabled: next !== "unconfigured",
        parameters: comp.parameters || {},
      };
      if (state.activePersona === "end-user") {
        targetTpl.origin = "custom_composed";
        await refreshWorkingEvaluation(true);
      }
      renderAll();
    });
    box.appendChild(pLbl);
    box.appendChild(pSel);

    const rates = spec.pricing[comp.provider] || spec.pricing.unconfigured;
    box.appendChild(
      el(
        "p",
        "mono-note",
        "Unit Rate: " +
          fmtUsd(rates.base_monthly_usd) +
          "/mo base + " +
          fmtUsd(rates.per_1m_turns_usd) +
          " per 1M turns"
      )
    );

    if (state.currentEvaluation && state.activePersona === "end-user") {
      box.appendChild(el("strong", "ctrl-label", "Dynamic Guardrail Policy Preview"));
      box.appendChild(
        el(
          "pre",
          "code-box",
          JSON.stringify(state.currentEvaluation.dynamic_guardrail_policy_preview, null, 2)
        )
      );
      box.appendChild(el("strong", "ctrl-label", "Terraform Paved-Path HCL Preview"));
      box.appendChild(
        el("pre", "code-box", state.currentEvaluation.terraform_paved_path_hcl || "")
      );
    }
  }

  /* ================= LIVE 9-SERVICE PIPELINE IN RIGHT TRAY ================= */
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
    if (!container) {
      return;
    }
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
      const row = el("div", "pipeline-step-row step-status-" + svc.status);
      row.setAttribute("role", "listitem");

      const rail = el("div", "pipeline-rail");
      rail.appendChild(el("div", "pipeline-node-circle", String(svc.step)));
      rail.appendChild(el("div", "pipeline-rail-line"));
      row.appendChild(rail);

      const card = el("div", "pipeline-card");
      const trigger = el("button", "pipeline-card-trigger");
      trigger.type = "button";
      trigger.setAttribute("aria-expanded", String(isExpanded));

      const top = el("div", "pipeline-card-top");
      top.appendChild(el("span", "pipeline-svc-name", svc.name));
      top.appendChild(el("span", statusChipClass(svc.status), svc.badge_label));
      trigger.appendChild(top);
      trigger.appendChild(el("p", "pipeline-svc-subtitle", svc.subtitle));

      trigger.addEventListener("click", () => {
        if (state.expandedServiceIds.has(svc.id)) {
          state.expandedServiceIds.delete(svc.id);
        } else {
          state.expandedServiceIds.add(svc.id);
        }
        renderVerticalPipeline();
      });
      card.appendChild(trigger);

      if (isExpanded) {
        const drawer = el("div", "pipeline-drawer");
        drawer.appendChild(el("div", "", svc.summary));
        drawer.appendChild(el("div", "mono-note", svc.api_surface));
        card.appendChild(drawer);
      }

      row.appendChild(card);
      container.appendChild(row);
    });
  }

  function updatePlatformServices(snapshot, animate) {
    if (!snapshot) {
      return;
    }
    state.platformSnapshot = snapshot;
    const evEl = document.getElementById("viz-last-event");
    if (evEl) {
      evEl.textContent = snapshot.last_event || "";
    }
    const trEl = document.getElementById("viz-trace-pill");
    if (trEl) {
      trEl.textContent = snapshot.trace_id
        ? "Trace: " + snapshot.trace_id.slice(0, 12) + "..."
        : "W3C + OTLP Ready";
    }
    if (animate && snapshot.services && snapshot.services.length) {
      const highlighted = snapshot.services.find(
        (s) => s.status === "BLOCKED" || s.status === "PAUSED_HITL"
      );
      if (highlighted) {
        state.expandedServiceIds = new Set([highlighted.id]);
      }
    }
    renderVerticalPipeline();
  }

  /* ================= MASTER CENTER STAGE DISPATCHER ================= */
  function renderCenterStage() {
    const hdrBox = document.getElementById("center-context-header");
    const stage = document.getElementById("center-stage-content");
    hdrBox.replaceChildren();
    stage.replaceChildren();

    if (state.activePersona === "governance-ops") {
      renderPersona2Header(hdrBox);
      if (state.activeNode === "ops-rubric") {
        renderOpsRubricStudio(stage);
      } else if (state.activeNode === "ops-templates") {
        renderOpsTemplateStudio(stage);
      } else if (state.activeNode === "ops-metrics-overview") {
        renderOpsMetricsView(stage, false);
      } else if (state.activeNode === "ops-metrics-ledger") {
        renderOpsMetricsView(stage, true);
      } else {
        renderOpsDay2Controls(stage);
      }
      return;
    }

    if (state.activePersona === "executive") {
      renderPersona3Header(hdrBox);
      if (state.activeNode === "exec-components") {
        renderExecutiveComponentRollupView(stage);
      } else if (state.activeNode === "exec-tco") {
        renderExecutiveTcoSimulator(stage);
      } else {
        renderExecutiveDeploymentsView(stage);
      }
      return;
    }

    // Default: Persona 1 (End User)
    renderPersona1Header(hdrBox);
    if (state.activeNode === "uj2-upload") {
      renderEndUserJourney2Upload(stage);
    } else if (state.activeNode === "uj3-evaluate") {
      renderEndUserJourney3Evaluate(stage);
    } else if (state.activeNode === "uj4-recommendations") {
      renderEndUserJourney4Recommendations(stage);
    } else if (state.activeNode === "uj5-remediate-deploy") {
      renderEndUserJourney5RemediateAndDeploy(stage);
    } else {
      renderEndUserJourney1(stage);
    }
  }

  function renderAll() {
    renderLeftMenuTree();
    renderCenterStage();
    renderRightInspector();
    renderVerticalPipeline();
  }

  function applyTenantBranding(tenant) {
    if (!tenant) {
      return;
    }
    state.tenant = tenant;
    document.getElementById("app-title").textContent = tenant.agent_title;
    document.getElementById("org-subtitle").textContent = tenant.organization_display_name;
    document.getElementById("brand-badge").textContent = tenant.theme.badge_text;
    const vizTitle = document.getElementById("viz-panel-title");
    if (vizTitle && tenant.terminology && tenant.terminology.platform_name) {
      vizTitle.textContent = tenant.terminology.platform_name + " 4-Tier Pipeline";
    }
  }

  function wireShellInteractions() {
    const personaOrder = ["end-user", "governance-ops", "executive"];
    document.querySelectorAll(".persona-tab").forEach((btn, idx) => {
      btn.addEventListener("click", () => {
        setActivePersona(btn.getAttribute("data-persona"), null, true);
      });
      btn.addEventListener("keydown", (ev) => {
        let next = -1;
        if (ev.key === "ArrowRight") {
          next = (idx + 1) % personaOrder.length;
        } else if (ev.key === "ArrowLeft") {
          next = (idx - 1 + personaOrder.length) % personaOrder.length;
        } else if (ev.key === "Home") {
          next = 0;
        } else if (ev.key === "End") {
          next = personaOrder.length - 1;
        }
        if (next >= 0) {
          ev.preventDefault();
          const targetPersona = personaOrder[next];
          setActivePersona(targetPersona, null, true);
          document.getElementById("persona-tab-" + targetPersona).focus();
        }
      });
    });

    const trayToggle = document.getElementById("btn-toggle-right-tray");
    trayToggle.addEventListener("click", () => {
      state.rightTrayOpen = !state.rightTrayOpen;
      document
        .getElementById("app-grid-shell")
        .classList.toggle("tray-collapsed", !state.rightTrayOpen);
      trayToggle.setAttribute("aria-expanded", String(state.rightTrayOpen));
      trayToggle.textContent = state.rightTrayOpen
        ? "Hide Inspector Tray"
        : "Show Inspector Tray";
    });

    document
      .getElementById("tray-tab-inspector")
      .addEventListener("click", () => activateRightTrayTab("inspector"));
    document
      .getElementById("tray-tab-pipeline")
      .addEventListener("click", () => activateRightTrayTab("pipeline"));

    document.getElementById("btn-expand-all").addEventListener("click", () => {
      state.expandAll = !state.expandAll;
      document.getElementById("btn-expand-all").textContent = state.expandAll
        ? "Collapse"
        : "Expand All";
      renderVerticalPipeline();
    });
    document.getElementById("btn-replay-flow").addEventListener("click", () => {
      renderVerticalPipeline();
    });

    window.addEventListener("popstate", () => {
      const p = resolveInitialPersonaFromUrl();
      setActivePersona(p, null, false);
    });
  }

  function resolveInitialPersonaFromUrl() {
    const path = window.location.pathname.toLowerCase();
    if (path.includes("governance-ops")) {
      return "governance-ops";
    }
    if (path.includes("executive")) {
      return "executive";
    }
    const params = new URLSearchParams(window.location.search);
    const qPersona = params.get("persona");
    if (qPersona === "governance-ops" || qPersona === "executive" || qPersona === "end-user") {
      return qPersona;
    }
    return "end-user";
  }

  async function init() {
    wireShellInteractions();
    const boot = await apiGet("/api/bootstrap");
    state.csrfToken = boot.csrf_token;
    state.architectureMode = boot.architecture_mode || "enterprise_hybrid";
    state.slotCatalog = boot.slot_catalog || [];
    state.slotById = {};
    state.slotCatalog.forEach((s) => {
      state.slotById[s.slot_id] = s;
    });
    state.templates = boot.templates || [];
    state.sampleUploads = boot.sample_uploads || [];
    state.rubric = boot.rubric || null;
    state.opsMetrics = boot.operations_metrics || null;
    state.execCosts = boot.executive_costs || null;
    state.tcoDefault = boot.tco_default || null;
    state.agentState = boot.agent_state || null;
    state.walletState = boot.wallet_state || null;
    state.identityPosture = boot.identity_posture || null;
    state.promptRegistry = boot.prompt_registry || null;
    state.candidates = boot.candidates || [];
    state.recentMemories = boot.recent_memories || [];

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

    if (state.templates[0]) {
      state.workingTemplate = deepClone(state.templates[0]);
      state.opsSelectedTemplate = deepClone(state.templates[0]);
      await refreshWorkingEvaluation(false);
      if (state.currentEvaluation) {
        state.initialEvalScore = state.currentEvaluation.overall_score;
      }
    }

    const initPersona = resolveInitialPersonaFromUrl();
    setActivePersona(initPersona, null, false);
  }

  document.addEventListener("DOMContentLoaded", init);
})();
