# GCP Agent Runtime Paved-Path Blueprint (Terraform)

Standardized, one-click Infrastructure-as-Code module for deploying governed pro-code agents onto Google Cloud (**Cloud Run** and **Vertex AI Agent Runtime**) with day-one enterprise foundation hooks:

1. **Automatic Enterprise Catalog & Agent Registry Enrollment**: Emits `enterprise_catalog_registration_payload` linking approved intake metadata, CMDB/Supergraph `enterprise_app_id`, and runtime endpoint URL.
2. **Pre-Configured Enterprise AI Gateway Routing**: Injects `HYBRID_GATEWAY_BASE_URL` and private `/26` PSC-Interface (`10.10.2.0/26`) network attachment (`ACCEPT_AUTOMATIC`) to prevent container socket bypass.
3. **Native OpenTelemetry OTLP Exporter**: Pre-wires `OTEL_EXPORTER_OTLP_ENDPOINT` and `OTEL_RESOURCE_ATTRIBUTES` so `gen_ai.*` traces stream directly to external OTLP collectors (such as Langfuse) and Google Cloud Trace.
4. **Standardized SPIFFE & OIDC Workload Identity Federation (`ADR-011`)**: Provisions a zero-secret service account and Workload Identity Pool/Provider validating `assertion.azp` without static pod bearer keys.

## Usage

```bash
# Copyright 2026 Google LLC.
# SPDX-License-Identifier: Apache-2.0
cd infra/terraform
terraform init -backend=false
terraform validate
```
