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

provider "google" {
  project = var.project_id
  region  = var.region
}

locals {
  common_labels = {
    datacloud         = "antigravity"
    managed_by        = "paved_path_terraform"
    candidate_id      = lower(var.candidate_id)
    enterprise_app_id = lower(var.enterprise_app_id)
    architecture_mode = var.architecture_mode
  }
}

# 1. Zero-Secret Workload Identity & Least-Privilege Agent Service Account
resource "google_service_account" "agent_workload_sa" {
  account_id   = substr(replace(var.agent_id, "_", "-"), 0, 28)
  display_name = "Governed ADK 2.0 Agent Workload (${var.agent_id})"
  description  = "Zero-secret SPIFFE / WIF identity for ${var.enterprise_app_id}"
}

resource "google_project_iam_member" "agent_least_privilege_roles" {
  for_each = toset([
    "roles/aiplatform.user",
    "roles/modelarmor.user",
    "roles/cloudtrace.agent",
    "roles/logging.logWriter",
  ])
  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.agent_workload_sa.email}"
}

# 2. Standardized External IdP / OIDC Workload Identity Federation (ADR-011 azp binding)
resource "google_iam_workload_identity_pool" "enterprise_agent_pool" {
  count                     = var.enable_spiffe_wif ? 1 : 0
  workload_identity_pool_id = "${substr(var.agent_id, 0, 20)}-wif-pool"
  display_name              = "Enterprise IdP & SPIFFE Federation Pool"
  description               = "Federates external OIDC azp claims to zero-secret GCP credentials."
}

resource "google_iam_workload_identity_pool_provider" "enterprise_oidc_provider" {
  count                              = var.enable_spiffe_wif ? 1 : 0
  workload_identity_pool_id          = google_iam_workload_identity_pool.enterprise_agent_pool[0].workload_identity_pool_id
  workload_identity_pool_provider_id = "enterprise-oidc-idp"
  display_name                       = "Enterprise OIDC Provider (ADR-011 azp Verified)"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.client_azp" = "assertion.azp"
    "attribute.tenant_id"  = "assertion.tid"
  }

  attribute_condition = "assertion.azp != ''"

  oidc {
    issuer_uri = var.external_oidc_issuer_uri
  }
}

# 3. Private /26 PSC-Interface Network Attachment for Un-Bypassable Egress Governance
resource "google_compute_network" "agent_vpc" {
  name                    = "${var.agent_id}-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "agent_psci_subnet" {
  name                     = "${var.agent_id}-psci-subnet"
  ip_cidr_range            = "10.10.2.0/26"
  region                   = var.region
  network                  = google_compute_network.agent_vpc.id
  private_ip_google_access = true
}

resource "google_compute_network_attachment" "agent_psci_attachment" {
  name                  = "${var.agent_id}-psci-attachment"
  region                = var.region
  connection_preference = "ACCEPT_AUTOMATIC"
  subnetworks           = [google_compute_subnetwork.agent_psci_subnet.id]
}

# 4. IAM-Protected Cloud Run Agent Runtime Pre-Wired with Tier-1 Hooks
resource "google_cloud_run_v2_service" "governed_agent_runtime" {
  name                = var.agent_id
  location            = var.region
  deletion_protection = false
  ingress             = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
  labels              = local.common_labels

  template {
    service_account = google_service_account.agent_workload_sa.email

    scaling {
      min_instance_count = 0
      max_instance_count = 10
    }

    containers {
      image = var.container_image

      env {
        name  = "GOOGLE_GENAI_USE_ENTERPRISE"
        value = "TRUE"
      }
      env {
        name  = "GOOGLE_GENAI_API_TRANSPORT"
        value = "rest"
      }
      env {
        name  = "GEMINI_MODEL"
        value = "gemini-3.8-flash"
      }
      env {
        name  = "CYMBAL_PLATFORM_MODE"
        value = var.architecture_mode
      }
      env {
        name  = "HYBRID_GATEWAY_BASE_URL"
        value = var.gateway_proxy_url
      }
      env {
        name  = "HYBRID_OTLP_ENDPOINT"
        value = var.otlp_collector_endpoint
      }
      env {
        name  = "OTEL_EXPORTER_OTLP_ENDPOINT"
        value = var.otlp_collector_endpoint
      }
      env {
        name  = "OTEL_RESOURCE_ATTRIBUTES"
        value = "service.name=${var.agent_id},enterprise.app_id=${var.enterprise_app_id},enterprise.intake_id=${var.intake_record_id}"
      }
    }
  }
}
