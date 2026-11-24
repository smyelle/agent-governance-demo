#!/usr/bin/env python3
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

"""Deterministic customer code-sharing, zero-leak, and Cymbal branding compliance gate.

Verifies every git-tracked file:
1. Prohibits PLAN.md, .env, *.local.yaml, *.zip, and binary/serialized artifacts.
2. Enforces Copyright 2026 Google LLC + Apache-2.0 license headers on code/configs.
3. Scans for internal Google or customer corporate FQDNs, shortlinks, GCP project
   numbers, credential tokens, and prohibited legacy customer/team names.
4. Enforces zero em-dashes or en-dashes in README.md, docs/, and web/.
5. Confirms root LICENSE and README.md customer disclaimers exist.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent

FORBIDDEN_FILENAMES = {
    "PLAN.md",
    ".env",
    "tenant_profile.local.yaml",
    "jwt_secret.txt",
}

FORBIDDEN_SUFFIXES = (
    ".pkl",
    ".pickle",
    ".tar.gz",
    ".tgz",
    ".whl",
    ".jar",
    ".zip",
    ".so",
    ".dylib",
    ".pem",
    ".key",
    ".local.yaml",
    ".local.yml",
    ".local.json",
)

HEADER_REQUIRED_SUFFIXES = (
    ".py",
    ".sh",
    ".yaml",
    ".yml",
    ".js",
    ".ts",
    ".css",
    ".html",
    ".toml",
)

HEADER_REQUIRED_NAMES = {
    "Dockerfile",
    ".gitignore",
    ".env.example",
}

# Constructed dynamically so this scanner file can safely scan itself without
# matching literal banned substrings.
FORBIDDEN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "argolis_domain",
        re.compile(r"altostrat" + r"\.com", re.IGNORECASE),
    ),
    (
        "google_corp_domain",
        re.compile(r"corp\.google" + r"\.com", re.IGNORECASE),
    ),
    (
        "google_internal_proxy",
        re.compile(r"(?:airlock-proxy|uplink\.goog|googlesource\.com)", re.IGNORECASE),
    ),
    (
        "google_internal_code_terms",
        re.compile(r"\b(?:google3|g3doc|citc|stubby)\b|//depot/", re.IGNORECASE),
    ),
    (
        "google_internal_shortlink",
        re.compile(r"(?<![A-Za-z0-9_./-])(?:go|b|cl)/[a-z0-9][a-z0-9_-]{2,}", re.IGNORECASE),
    ),
    (
        "customer_or_legacy_team_reference",
        re.compile(
            r"(?:com" + r"cast|dev" + r"x|codebig2\.net|azure-api\.net)",
            re.IGNORECASE,
        ),
    ),
    (
        "hardcoded_gcp_project_number",
        re.compile(r"projects/\d{11,13}\b|\b675154" + r"824791\b"),
    ),
    (
        "credential_or_private_key",
        re.compile(
            r"AIza[0-9A-Za-z_-]{25,}|ya29\.[0-9A-Za-z._-]+|"
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
            r"\bghp_[0-9A-Za-z]{25,}\b"
        ),
    ),
]

DASH_CHECK_PREFIXES = ("README.md", "docs/", "web/")
EM_OR_EN_DASH_RE = re.compile("[\u2013\u2014]")

REQUIRED_README_PHRASES = [
    "NOT OFFICIALLY SUPPORTED GOOGLE PRODUCTS",
    "Apache License, Version 2.0",
    "Pre-GA Offerings Terms",
    "non-binding budgetary estimates",
]


def get_tracked_files() -> list[str]:
    proc = subprocess.run(
        ["git", "ls-files"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def requires_apache_header(rel_path: str) -> bool:
    p = Path(rel_path)
    if p.name in HEADER_REQUIRED_NAMES:
        return True
    return rel_path.endswith(HEADER_REQUIRED_SUFFIXES)


def has_valid_apache_header(content: str) -> bool:
    head = "\n".join(content.splitlines()[:25])
    return (
        "Copyright 2026 Google LLC" in head
        and 'Licensed under the Apache License, Version 2.0 (the "License")' in head
        and "http://www.apache.org/licenses/LICENSE-2.0" in head
    )


def audit_repository() -> dict[str, object]:
    tracked = get_tracked_files()
    findings: list[dict[str, object]] = []

    if not (REPO_ROOT / "LICENSE").is_file():
        findings.append(
            {"file": "LICENSE", "rule": "missing_license", "detail": "Root LICENSE file missing."}
        )
    else:
        license_text = (REPO_ROOT / "LICENSE").read_text(encoding="utf-8")
        if "Apache License" not in license_text or "Version 2.0" not in license_text:
            findings.append(
                {
                    "file": "LICENSE",
                    "rule": "invalid_license",
                    "detail": "Root LICENSE must contain Apache License, Version 2.0.",
                }
            )

    readme_path = REPO_ROOT / "README.md"
    if not readme_path.is_file():
        findings.append(
            {"file": "README.md", "rule": "missing_readme", "detail": "Root README.md missing."}
        )
    else:
        readme_text = readme_path.read_text(encoding="utf-8")
        for phrase in REQUIRED_README_PHRASES:
            if phrase not in readme_text:
                findings.append(
                    {
                        "file": "README.md",
                        "rule": "missing_disclaimer_clause",
                        "detail": f"Missing required disclaimer text: {phrase}",
                    }
                )

    header_checked = 0
    header_passed = 0

    for rel_path in tracked:
        path = REPO_ROOT / rel_path
        if not path.exists():
            continue

        if path.name in FORBIDDEN_FILENAMES or rel_path.startswith("scape_docs"):
            findings.append(
                {
                    "file": rel_path,
                    "rule": "forbidden_tracked_file",
                    "detail": "File must remain git-ignored and never tracked.",
                }
            )
            continue

        if any(rel_path.endswith(sfx) for sfx in FORBIDDEN_SUFFIXES):
            findings.append(
                {
                    "file": rel_path,
                    "rule": "forbidden_binary_or_local_artifact",
                    "detail": "Binary, archive, or .local configuration artifact tracked in git.",
                }
            )
            continue

        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            findings.append(
                {
                    "file": rel_path,
                    "rule": "unexpected_binary_file",
                    "detail": "Non-UTF-8 binary file tracked in repository.",
                }
            )
            continue

        if requires_apache_header(rel_path):
            header_checked += 1
            if has_valid_apache_header(text):
                header_passed += 1
            else:
                findings.append(
                    {
                        "file": rel_path,
                        "rule": "missing_apache_header",
                        "detail": "Missing full 13-line Copyright 2026 Google LLC Apache-2.0 header.",
                    }
                )

        if rel_path != "scripts/verify_repo_compliance.py":
            for rule_name, pattern in FORBIDDEN_PATTERNS:
                for line_no, line in enumerate(text.splitlines(), start=1):
                    match = pattern.search(line)
                    if match:
                        findings.append(
                            {
                                "file": rel_path,
                                "line": line_no,
                                "rule": rule_name,
                                "detail": f"Matched forbidden pattern ({rule_name}): {match.group(0)[:40]}",
                            }
                        )

        if rel_path.startswith(DASH_CHECK_PREFIXES):
            for line_no, line in enumerate(text.splitlines(), start=1):
                if EM_OR_EN_DASH_RE.search(line):
                    findings.append(
                        {
                            "file": rel_path,
                            "line": line_no,
                            "rule": "typographic_dash_prohibited",
                            "detail": "Found prohibited em-dash or en-dash in customer-facing docs/UI.",
                        }
                    )

    return {
        "status": "PASS" if not findings else "FAIL",
        "tracked_files_scanned": len(tracked),
        "apache_headers_checked": header_checked,
        "apache_headers_passed": header_passed,
        "finding_count": len(findings),
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify Apache-2.0 headers, zero leaks, and Cymbal genericization compliance."
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON scorecard.")
    args = parser.parse_args()

    report = audit_repository()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(
            f"[{report['status']}] Compliance Gate | "
            f"Tracked Files: {report['tracked_files_scanned']} | "
            f"Apache Headers: {report['apache_headers_passed']}/{report['apache_headers_checked']} | "
            f"Findings: {report['finding_count']}"
        )
        for item in report["findings"][:25]:
            loc = f"{item['file']}:{item['line']}" if "line" in item else str(item["file"])
            print(f"  - [{item['rule']}] {loc} -> {item['detail']}")

    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
