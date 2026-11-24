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

output "governed_agent_service_uri" {
  description = "IAM-protected Cloud Run endpoint for the deployed ADK 2.0 agent."
  value       = google_cloud_run_v2_service.governed_agent_runtime.uri
}

output "zero_secret_workload_identity" {
  description = "Dedicated zero-secret Google Service Account email bound via SPIFFE / WIF."
  value       = google_service_account.agent_workload_sa.email
}

output "enterprise_catalog_registration_payload" {
  description = "Out-of-the-box registration manifest for Tier-1 Enterprise Catalog & GCP Agent Registry."
  value = var.register_blueprint ? jsonencode({
    agent_id                = var.agent_id
    candidate_id            = var.candidate_id
    enterprise_app_id       = var.enterprise_app_id
    intake_record_id        = var.intake_record_id
    architecture_mode       = var.architecture_mode
    endpoint_url            = google_cloud_run_v2_service.governed_agent_runtime.uri
    gateway_proxy_url       = var.gateway_proxy_url
    otlp_collector_endpoint = var.otlp_collector_endpoint
    spiffe_principal        = "spiffe://${var.project_id}.svc.id.goog/ns/agent-runtime/sa/${var.agent_id}"
    kill_switch_enabled     = true
  }) : ""
}
