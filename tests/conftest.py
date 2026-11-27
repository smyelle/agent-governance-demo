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

"""Shared pytest fixtures and marker registration for isolated test execution."""

from __future__ import annotations

from pathlib import Path

import pytest


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "live: marks live Vertex AI / Model Armor integration tests (deselect with '-m \"not live\"')",
    )


@pytest.fixture(autouse=True)
def _isolate_runtime_state_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Isolate writable runtime state so tests never mutate git-tracked config/prompts/."""
    runtime_dir = tmp_path / "runtime_state"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("CYMBAL_RUNTIME_STATE_DIR", str(runtime_dir))
