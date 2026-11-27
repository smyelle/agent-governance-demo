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

"""Standalone OpenAI-Compatible Tier-0 Model Armor Gateway Middleware Adapter."""

from __future__ import annotations

from .app import app, create_app
from .guard_core import (
    DynamicGuardrailPolicyPayload,
    FailClosedModelArmorGuard,
    GuardrailVerdict,
    ModelArmorBlockedError,
    ProhibitedAgencyTierError,
    compile_dynamic_policy_to_base_template,
    mask_inline_pii,
    unpack_obfuscated_payloads,
)

__all__ = [
    "DynamicGuardrailPolicyPayload",
    "FailClosedModelArmorGuard",
    "GuardrailVerdict",
    "ModelArmorBlockedError",
    "ProhibitedAgencyTierError",
    "app",
    "compile_dynamic_policy_to_base_template",
    "create_app",
    "mask_inline_pii",
    "unpack_obfuscated_payloads",
]
