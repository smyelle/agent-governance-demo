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
    BIND_HOST=0.0.0.0

WORKDIR /app

RUN pip install --no-cache-dir \
    "fastapi>=0.115.0" \
    "pydantic>=2.10.0" \
    "uvicorn[standard]>=0.32.0" \
    "httpx>=0.28.0" \
    "google-cloud-modelarmor>=0.2.0" \
    "google-auth>=2.36.0"

COPY __init__.py guard_core.py app.py /app/

RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8080

CMD ["python", "/app/app.py"]
