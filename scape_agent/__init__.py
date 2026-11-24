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

"""Exports `root_agent` and resumable ADK 2.0 `app` for Agent Runtime deployment."""

import os

# Configure gRPC C-core logging and fork behavior before grpc modules initialize
os.environ.setdefault("GRPC_VERBOSITY", "ERROR")
os.environ.setdefault("GRPC_ENABLE_FORK_SUPPORT", "0")

from scape_agent.agent import app, build_scape_workflow, governance_plugin, root_agent

__all__ = ["app", "build_scape_workflow", "governance_plugin", "root_agent"]
