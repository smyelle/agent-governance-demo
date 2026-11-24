# Google Agent Platform vs. Multi-System DIY Baseline: Technical Benchmark & TCO Analysis

**Reference Agent**: Cymbal Core Operations & Release Agent  
**Generated**: 2026-11-24 14:56:03 UTC  
**Verification Result**: **8 / 8 Differential Capabilities Passed Live**  
**Reference Runtime**: ADK 2.0 (`Workflow` Graph) + Gemini Long-Term Availability (`gemini-3.8-flash`)

> **Advisory Benchmark & Sample Code Notice**: This benchmark report is generated from a reference architecture evaluation environment. All throughput, latency, and cost figures are illustrative, non-binding budgetary estimates based on publicly published list rates and stated traffic assumptions (`1,000` tokens per turn). Preview capabilities are evaluated under the Google Cloud Pre-GA Offerings Terms (`https://cloud.google.com/terms/service-terms`).

## 1. Executive Summary: Consolidating 6 Specialist Vendor Categories into One Platform

Enterprise platform teams operating a custom multi-system baseline across Kubernetes proxies, point-vendor guardrails, Valkey usage streams, and separate observability stores face high integration maintenance and structural security boundaries. Running the automated 8-capability differential suite on the Cymbal Core Operations & Release Agent demonstrates how Google Agent Platform delivers Tier 1 through Tier 4 governance natively while also supporting modular hybrid coexistence (`CYMBAL_PLATFORM_MODE=enterprise_hybrid`).

## 2. Live 8-Capability Differential Proof Scorecard

| # | Capability Verified Live | Current Multi-System / DIY Baseline Limitation | Measured Google Agent Platform Evidence | Specialist Vendors Consolidated | Latency | Verdict |
| :- | :--- | :--- | :--- | :--- | :---: | :---: |
| **1** | **Un-Bypassable Tenant Network Attachment (ACT + PSC-I) & Unified Kill Switch** | Opt-in HTTP proxy URL allows container socket bypass; PAUSED status blocks A2A only. | PSC-I /26 subnet (10.10.1.0/26) + ACT PRIVATE_RANGES_ONLY attachment verified; PAUSED state halted model, MCP, and A2A execution in a single atomic check. | `Agentgateway`, `Hush`, `Geordie`, `Harmonic` | `0.03 ms` | **PASS** |
| **2** | **Inline Per-Tool & Semantic Payload Authorization (UAP Policy V2 CEL + SGP)** | Coarse mcp.use gateway scope grants all-or-nothing access to destructive tools in a pool. | MCP handshake ('') and read_only_hint=true tools ALLOWED; destructive_hint=true tool 'purge_production_valkey_stream' DENIED (403 PERMISSION_DENIED). | `Runlayer`, `Keycard`, `Arcade` | `0.01 ms` | **PASS** |
| **3** | **Zero-Secret Container Execution (SPIFFE AGENT_IDENTITY) & ADR-011 azp OBO** | Static bearer keys in pod env, sidecar 2x token exchange overhead, and pairwise sub OBO failure. | 0 static secrets in container env (spiffe://cymbal-agent-platform.svc.id.goog/ns/agent-runtime/sa/cymbal-ops-release-agent); ADR-011 azp correlation succeeded across divergent pairwise subjects while rejecting mismatched azp fail-closed. | `Keycard`, `Custom OBO Sidecars`, `HashiCorp Vault` | `0.52 ms` | **PASS** |
| **4** | **Org Safety Floor + Inline SDP PII Masking + 40-URL Phishing + Fail-Closed Guard** | 10x higher per-turn guardrail spend, cross-cloud hairpin latency, fail-open default, and no URL/PII masking. | SSN & MAC masked inline (ALLOWED_WITH_INLINE_SDP_REDACTION); Base64 injection blocked (BLOCKED_PROMPT_INJECTION); malicious URI blocked (BLOCKED_MALICIOUS_URI); provider outage blocked fail-closed (BLOCKED_FAIL_CLOSED). | `Straiker.ai`, `Azure AI Content Safety`, `AWS Bedrock Guardrails` | `0.05 ms` | **PASS** |
| **5** | **Durable Graph Checkpointing (RequestInput HITL) & Native gVisor Code Sandbox** | Stateless request SDK lacks multi-hour HITL graph checkpointing and isolated code execution. | Paused cleanly at interrupt 'ag3_rollback_1', resumed into A2A canary rollback, and computed gVisor anomaly z_score=432.95 sigma (15.28x p99 jump). | `E2B MicroVMs`, `Custom State Checkpoint Glue` | `231.14 ms` | **PASS** |
| **6** | **Longitudinal Cross-Session Memory Bank with Strict JWT Principal Isolation** | Agents are stateless across sessions and lack native IAM/JWT per-user memory isolation. | Persisted & recalled longitudinal memory (mem-7d07f8894c) for 'sre-alice-jwt' while 'sre-bob-jwt' observed 0 cross-tenant records. | `Mem0`, `Memori`, `Custom Memory ABAC Wrappers` | `0.03 ms` | **PASS** |
| **7** | **Unified Gateway-to-Guardrail-to-Agent Trace Join & Atomic Cost-per-Outcome Wallet** | Fragmented guardrail logs vs agent traces and post-response Valkey spend overshoot. | Joined 2 gateway+agent spans under W3C trace fb98d4c554b24008...; atomic preflight enforced 403 ceiling; recorded cost_per_resolved_incident=363000 nano-USD. | `Revenium`, `Ascerta (Pay-i)`, `Faros`, `Custom Trace Joiners` | `0.09 ms` | **PASS** |
| **8** | **Closed-Loop Trace -> 503 & Freeze Simulation -> Prompt Optimization -> Registry Gate** | Static CI YAML files cannot ingest failure traces, simulate 503 tool faults, or gate registry activation. | Scored v1=58.0 (BLOCKED) -> synthesized v2 -> passed 8/8 adversarial & 503 fault simulations -> promoted v2 (behavior_score=96.2). | `Veris Simulation`, `LangSmith` | `74.58 ms` | **PASS** |

## 3. Guardrail Total Cost of Ownership (TCO) Comparison

Based on publicly published list pricing for `1,000`-token conversational turns across enterprise traffic volumes:

| Daily Turn Volume | Annual Turns | Azure AI Content Safety (Est.) | AWS Bedrock Guardrails (Est.) | Google Cloud Model Armor (`$0.10 / 1M tokens`) | Annual Savings vs. Azure | Annual Savings vs. Bedrock |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| `1,000,000 / day` | `365,000,000` | `\$365,000` | `\$109,500` | `\$36,500` | **`\$328,500 / yr` (`90%`)** | **`\$73,000 / yr` (`67%`)** |
| `10,000,000 / day` | `3,650,000,000` | `\$3,650,000` | `\$1,095,000` | `\$365,000` | **`\$3,285,000 / yr` (`90%`)** | **`\$730,000 / yr` (`67%`)** |
| `25,000,000 / day` | `9,125,000,000` | `\$9,125,000` | `\$2,737,500` | `\$912,500` | **`\$8,212,500 / yr` (`90%`)** | **`\$1,825,000 / yr` (`67%`)** |
| `50,000,000 / day` | `18,250,000,000` | `\$18,250,000` | `\$5,475,000` | `\$1,825,000` | **`\$16,425,000 / yr` (`90%`)** | **`\$3,650,000 / yr` (`67%`)** |

### Architectural Cost & Latency Multipliers Beyond Per-Token List Price
1. **Zero Cross-Cloud Hairpin Penalty**: Model Armor inspects prompts and responses inline in `us-central1` without routing streamed chunks across cloud boundaries.
2. **Strict Fail-Closed Floor Enforcement**: Organization and project Floor Settings prevent individual teams from attaching a `no-guardrail` policy to a production gateway route.
3. **Inline Cloud SDP Redaction**: Pasted customer SSNs and CPE MAC addresses in SRE logs are masked inline (`[REDACTED_PII_SSN:***-**-6789]`) so incident triage continues safely without leaking regulated data.
4. **Atomic Pre-Flight Budget Ceiling + Cost-per-Outcome ROI**: Firestore transactional pre-flight reservations block over-cap spend (`HTTP 403 budget_exceeded`) before inference starts, while BigQuery `wallet_ledger` attributes exact nano-USD spend per resolved incident.
