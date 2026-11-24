# Google Agent Platform 4-Tier A-La-Carte Coexistence: Technical Benchmark & Ensemble TCO

**Reference Application**: Cymbal Agent Governance, Optimization & Deployment Workbench  
**Generated**: 2026-11-24 18:08:30 UTC  
**Verification Result**: **8 / 8 Modular Capabilities Passed Live**  
**Reference Runtime**: ADK 2.0 (`Workflow` Graph) + Gemini Long-Term Availability (`gemini-3.8-flash`)

> **Advisory Benchmark & Sample Code Notice**: This benchmark report is generated from a reference architecture evaluation environment. All throughput, latency, and cost figures are illustrative, non-binding budgetary estimates based on publicly published list rates and stated traffic assumptions (`1,000` tokens per turn). Preview capabilities are evaluated under the Google Cloud Pre-GA Offerings Terms (`https://cloud.google.com/terms/service-terms`).

## 1. Executive Summary: Modular Tier-2 & Tier-3 Value Without Full-Stack Lock-In

Enterprise AI platform teams enforce mandatory Tier-1 foundations across corporate agent catalogs, AI gateways, OpenTelemetry / Langfuse collectors, SPIFFE / OIDC identity fabrics, and enterprise wallets. Rather than forcing full-stack replacement, the Cymbal Agent Governance, Optimization & Deployment Workbench defaults to 4-Tier A-La-Carte Coexistence (`CYMBAL_PLATFORM_MODE=enterprise_hybrid`), plugging modular runtime security, gVisor sandboxes, dynamic per-request guardrails, Terraform Paved Paths, and 6-stage closed-loop evaluation optimization directly into existing Tier-1 foundations while eliminating ~30 fragmented point-vendor bakeoffs.

## 2. Live 8-Capability Modular Coexistence Scorecard

| # | Modular Capability Verified Live | Standalone / Un-Integrated Gap Addressed | Measured Google Agent Platform Evidence | Point-Vendor Categories Consolidated | Latency | Verdict |
| :- | :--- | :--- | :--- | :--- | :---: | :---: |
| **1** | **Un-Bypassable Tenant Network Attachment (ACT + PSC-I) & Unified Kill Switch** | Opt-in HTTP proxy URL allows container socket bypass; PAUSED status blocks A2A only. | PSC-I /26 subnet (10.10.1.0/26) + ACT PRIVATE_RANGES_ONLY attachment verified; PAUSED state halted model, MCP, and A2A execution in a single atomic check. | `Agentgateway`, `Hush`, `Geordie`, `Harmonic` | `1085.22 ms` | **PASS** |
| **2** | **Inline Per-Tool & Semantic Payload Authorization (UAP Policy V2 CEL + SGP)** | Coarse mcp.use gateway scope grants all-or-nothing access to destructive tools in a pool. | MCP handshake ('') and read_only_hint=true audit tools ALLOWED; destructive_hint=true tool 'force_bypass_governance_gate' DENIED (403 PERMISSION_DENIED). | `Runlayer`, `Keycard`, `Arcade` | `0.09 ms` | **PASS** |
| **3** | **Zero-Secret Container Execution (SPIFFE AGENT_IDENTITY) & ADR-011 azp OBO** | Static bearer keys in pod env, sidecar 2x token exchange overhead, and pairwise sub OBO failure. | 0 static secrets in container env (spiffe://cymbal-agent-platform.svc.id.goog/ns/agent-runtime/sa/cymbal-ops-release-agent); ADR-011 azp correlation succeeded across divergent pairwise subjects while rejecting mismatched azp fail-closed. | `Keycard`, `Custom OBO Sidecars`, `HashiCorp Vault` | `3.53 ms` | **PASS** |
| **4** | **Dynamic Per-Request Model Armor Router + Inline SDP + 40-URL Phishing Floor** | Static template sprawl across BUs, fail-open outage defaults, and no inline PII/URL masking. | Dynamic policy routed BU inline mask (ALLOWED_WITH_INLINE_SDP_REDACTION) & strict BU block (BLOCKED_SDP_PII_POLICY) over 2 base templates; Base64 & phishing URL blocked. | `Straiker.ai`, `Static Template Sprawl Glue` | `661.37 ms` | **PASS** |
| **5** | **Durable Reviewer Checkpointing (RequestInput HITL) & Native gVisor Sandbox** | Stateless request SDK lacks multi-hour reviewer HITL checkpointing and isolated code execution. | Paused cleanly at interrupt 'ag3_deploy_1', resumed into A2A Paved-Path deployment, and computed gVisor readiness/anomaly z_score=524.89 sigma (15.23x jump). | `E2B MicroVMs`, `Custom State Checkpoint Glue` | `14293.03 ms` | **PASS** |
| **6** | **Longitudinal Governance Memory Bank with Strict JWT Principal Isolation** | Agents are stateless across sessions and lack native IAM/JWT per-reviewer memory isolation. | Persisted & recalled governance audit memory (9073492414257168384) for 'reviewer-alice-jwt' while 'reviewer-bob-jwt' observed 0 cross-tenant records. | `Mem0`, `Memori`, `Custom Memory ABAC Wrappers` | `2040.06 ms` | **PASS** |
| **7** | **Unified W3C + Langfuse OTLP Trace Join & Atomic Cost-per-Outcome Wallet** | Fragmented guardrail logs vs OTLP traces and post-response spend overshoot. | Joined 2 spans in Cloud Trace + OTLP resourceSpans (781b06ecd0bc49...); atomic 403 cap enforced; cost_per_outcome=440388 nano-USD. | `Revenium`, `Ascerta (Pay-i)`, `Faros`, `Custom Trace Joiners` | `1655.82 ms` | **PASS** |
| **8** | **A-La-Carte 6-Stage Cross-Cloud Trace -> Eval -> Prompt Optimizer -> Blueprint Gate** | Static CI YAML files cannot ingest cross-cloud OTLP traces, simulate 503 faults, or synthesize prompts. | Ingested AWS/Azure/GCP OTLP traces -> v1=58.0 (BLOCKED) -> synthesized v2 + few-shots -> passed 8/8 sims -> promoted blueprint (behavior_score=96.4). | `Veris Simulation`, `LangSmith` | `22069.98 ms` | **PASS** |

## 3. Guardrail Ensemble Coexistence & Tier-0 Pre-Filter TCO Analysis

Based on publicly published list pricing for `1,000`-token conversational turns across enterprise traffic volumes:

| Daily Turn Volume | Annual Turns | Azure AI Content Safety (Est.) | AWS Bedrock Guardrails (Est.) | Google Cloud Model Armor (`$0.10 / 1M tokens`) | Ensemble Tier-0 Hybrid (Model Armor + 20% Escalation) | Annual Savings vs. Azure |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| `1,000,000 / day` | `365,000,000` | `\$365,000` | `\$109,500` | `\$36,500` | `\$58,400` | **`\$328,500 / yr` (`90%`)** |
| `10,000,000 / day` | `3,650,000,000` | `\$3,650,000` | `\$1,095,000` | `\$365,000` | `\$584,000` | **`\$3,285,000 / yr` (`90%`)** |
| `25,000,000 / day` | `9,125,000,000` | `\$9,125,000` | `\$2,737,500` | `\$912,500` | `\$1,460,000` | **`\$8,212,500 / yr` (`90%`)** |
| `50,000,000 / day` | `18,250,000,000` | `\$18,250,000` | `\$5,475,000` | `\$1,825,000` | `\$2,920,000` | **`\$16,425,000 / yr` (`90%`)** |

### Architectural Multipliers for Multi-Guardrail Ensembles
1. **Dynamic Per-Request Policy Router (Zero Template Sprawl)**: Compiles per-request business-unit, risk-tier, and SDP action JSON payloads onto a bounded 2-template Floor-enforced pool (`cymbal-default-medium-gpp` and `cymbal-strict-ag3-gpp`).
2. **High-Speed Tier-0 Ensemble Pre-Filtering**: Inspects 100% of turns inline at `$0.10` / 1M tokens for SSN/MAC PII redaction, 40-URL phishing links, and Base64 prompt injections before invoking higher-cost downstream ensemble classifiers.
3. **A-La-Carte Multi-Cloud Trace Optimization**: Ingests OpenTelemetry / Langfuse traces from AWS, Azure, or GCP runtimes into `agentplatform.Client.evals` without requiring workload migration.
4. **Standardized Terraform Paved Paths**: Ships `infra/terraform/` modules pre-wired for Enterprise Catalog enrollment, Gateway proxy routing, OTLP collector export, and SPIFFE / OIDC Workload Identity Federation.
