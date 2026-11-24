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

variable "project_id" {
  description = "Target Google Cloud project ID hosting the governed agent runtime."
  type        = string
}

variable "region" {
  description = "Primary Google Cloud region (us-central1 required for Model Armor templates)."
  type        = string
  default     = "us-central1"
}

variable "agent_id" {
  description = "Canonical kebab-case agent identifier registered across Tier-1 & GCP catalogs."
  type        = string
  default     = "cymbal-governed-agent"
}

variable "candidate_id" {
  description = "Governance intake candidate identifier."
  type        = string
  default     = "CAND-101"
}

variable "enterprise_app_id" {
  description = "Enterprise CMDB & Dependency Supergraph application identifier."
  type        = string
  default     = "SVC-CYMBAL-101"
}

variable "intake_record_id" {
  description = "Approved compliance intake record identifier."
  type        = string
  default     = "ATLAS-2026-0841"
}

variable "architecture_mode" {
  description = "Operating mode: enterprise_hybrid (4-Tier A-La-Carte Coexistence) or google_native."
  type        = string
  default     = "enterprise_hybrid"
}

variable "container_image" {
  description = "Artifact Registry container URI for the Cloud Run / ADK 2.0 agent workload."
  type        = string
  default     = "us-central1-docker.pkg.dev/example-project/agents/governed-agent:v2"
}

variable "gateway_proxy_url" {
  description = "Mandatory Enterprise AI Gateway proxy endpoint for outbound model & MCP routing."
  type        = string
  default     = "https://ai-gateway.cymbal.example/v1"
}

variable "otlp_collector_endpoint" {
  description = "Enterprise OpenTelemetry OTLP collector endpoint (Langfuse / observability platform)."
  type        = string
  default     = "https://otlp-collector.cymbal.example/v1/traces"
}

variable "external_oidc_issuer_uri" {
  description = "External Enterprise IdP OIDC issuer URI for SPIFFE / Workload Identity Federation."
  type        = string
  default     = "https://login.cymbal-idp.example/tenant-01/v2.0"
}

variable "enable_spiffe_wif" {
  description = "Provision Workload Identity Pool & OIDC Provider for zero-secret OBO federation."
  type        = bool
  default     = true
}

variable "register_blueprint" {
  description = "Emit structured Golden Blueprint payload for Enterprise Catalog & Agent Registry sync."
  type        = bool
  default     = true
}
