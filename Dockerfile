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

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    GOOGLE_GENAI_USE_ENTERPRISE=TRUE \
    GOOGLE_GENAI_API_TRANSPORT=rest \
    CYMBAL_RUNTIME_STATE_DIR=/tmp/cymbal_runtime_state

WORKDIR /app

COPY pyproject.toml README.md LICENSE /app/
COPY config /app/config
COPY cymbal_agent /app/cymbal_agent
COPY evals /app/evals
COPY services/__init__.py /app/services/__init__.py
COPY services/cymbal_ops_mcp_server /app/services/cymbal_ops_mcp_server
COPY web /app/web

RUN pip install --no-cache-dir /app \
    && useradd --create-home --uid 10001 appuser \
    && mkdir -p /tmp/cymbal_runtime_state \
    && chown -R appuser:appuser /tmp/cymbal_runtime_state /app/config/prompts

USER appuser

EXPOSE 8080

CMD ["python", "-m", "web.api"]
