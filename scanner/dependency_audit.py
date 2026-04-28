"""
MCPGuard — Dependency Audit Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Scans MCP server dependencies for known vulnerabilities, package age concerns,
typosquatting, and unpinned dependency versions.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional
from uuid import uuid4

import httpx


# ─── Finding Data Class ─────────────────────────────────────

@dataclass
class Finding:
    """A single security finding from the scanner."""
    id: str
    category: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    remediation: str = ""
    cwe_id: Optional[str] = None


# ─── NPM Audit ──────────────────────────────────────────────

def run_npm_audit(directory: str) -> list[Finding]:
    """
    Run `npm audit --json` in the given directory and parse results.

    Args:
        directory: Path to a directory containing package.json and node_modules.

    Returns:
        List of Finding objects for each vulnerability found.
    """
    findings: list[Finding] = []
    package_json = os.path.join(directory, "package.json")

    if not os.path.isfile(package_json):
        return findings

    try:
        # Install deps first if node_modules doesn't exist
        node_modules = os.path.join(directory, "node_modules")
        if not os.path.isdir(node_modules):
            subprocess.run(
                ["npm", "install", "--ignore-scripts", "--no-audit"],
                cwd=directory,
                capture_output=True,
                timeout=120,
            )

        result = subprocess.run(
            ["npm", "audit", "--json"],
            cwd=directory,
            capture_output=True,
            text=True,
            timeout=60,
        )

        if not result.stdout.strip():
            return findings

        data = json.loads(result.stdout)
        vulnerabilities = data.get("vulnerabilities", {})

        for pkg_name, vuln_info in vulnerabilities.items():
            severity_map = {
                "critical": "CRITICAL",
                "high": "HIGH",
                "moderate": "MEDIUM",
                "low": "LOW",
                "info": "INFO",
            }
            raw_sev = vuln_info.get("severity", "info")
            severity = severity_map.get(raw_sev, "INFO")

            via = vuln_info.get("via", [])
            title = f"Vulnerable dependency: {pkg_name}"
            description_parts = []
            cwe_ids = []
            url = ""

            for v in via:
                if isinstance(v, dict):
                    title = v.get("title", title)
                    if v.get("url"):
                        url = v["url"]
                    if v.get("cwe"):
                        cwe_ids.extend(v["cwe"])
                    description_parts.append(
                        f"{v.get('title', 'Unknown vulnerability')} "
                        f"(range: {v.get('range', 'unknown')})"
                    )

            findings.append(Finding(
                id=str(uuid4()),
                category="dependency-audit",
                severity=severity,
                title=title,
                description="; ".join(description_parts) if description_parts else f"Known vulnerability in {pkg_name}",
                file_path="package.json",
                line_number=None,
                remediation=f"Run `npm audit fix` or update {pkg_name} to a patched version. See: {url}" if url else f"Update {pkg_name} to a patched version.",
                cwe_id=cwe_ids[0] if cwe_ids else None,
            ))

    except subprocess.TimeoutExpired:
        findings.append(Finding(
            id=str(uuid4()),
            category="dependency-audit",
            severity="INFO",
            title="npm audit timed out",
            description="The npm audit command did not complete within 60 seconds.",
            remediation="Run `npm audit` manually to check for vulnerabilities.",
        ))
    except (json.JSONDecodeError, FileNotFoundError, OSError) as e:
        findings.append(Finding(
            id=str(uuid4()),
            category="dependency-audit",
            severity="INFO",
            title="npm audit could not run",
            description=f"Error running npm audit: {str(e)[:200]}",
            remediation="Ensure npm is installed and package.json is valid.",
        ))

    return findings


# ─── Pip Audit ───────────────────────────────────────────────

def run_pip_audit(directory: str) -> list[Finding]:
    """
    Run pip-audit on the given directory's requirements.txt.

    Args:
        directory: Path to a directory containing requirements.txt.

    Returns:
        List of Finding objects for each vulnerability found.
    """
    findings: list[Finding] = []
    req_file = os.path.join(directory, "requirements.txt")

    if not os.path.isfile(req_file):
        return findings

    try:
        result = subprocess.run(
            ["pip-audit", "--format", "json", "--requirement", req_file],
            cwd=directory,
            capture_output=True,
            text=True,
            timeout=120,
        )

        if not result.stdout.strip():
            return findings

        data = json.loads(result.stdout)
        dependencies = data if isinstance(data, list) else data.get("dependencies", [])

        for dep in dependencies:
            vulns = dep.get("vulns", [])
            for vuln in vulns:
                severity_raw = vuln.get("fix_versions", [])
                severity = "HIGH"  # pip-audit doesn't always provide severity

                findings.append(Finding(
                    id=str(uuid4()),
                    category="dependency-audit",
                    severity=severity,
                    title=f"Vulnerable Python package: {dep.get('name', 'unknown')}",
                    description=(
                        f"{vuln.get('id', 'Unknown CVE')}: {vuln.get('description', 'No description')[:200]}. "
                        f"Installed: {dep.get('version', 'unknown')}."
                    ),
                    file_path="requirements.txt",
                    remediation=(
                        f"Update {dep.get('name')} to one of: {', '.join(severity_raw)}"
                        if severity_raw
                        else f"Update {dep.get('name')} to the latest version."
                    ),
                    cwe_id=vuln.get("id"),
                ))

    except FileNotFoundError:
        findings.append(Finding(
            id=str(uuid4()),
            category="dependency-audit",
            severity="INFO",
            title="pip-audit not installed",
            description="pip-audit is not installed. Install it with: pip install pip-audit",
            remediation="Install pip-audit: `pip install pip-audit`",
        ))
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as e:
        findings.append(Finding(
            id=str(uuid4()),
            category="dependency-audit",
            severity="INFO",
            title="pip-audit could not run",
            description=f"Error: {str(e)[:200]}",
            remediation="Run `pip-audit -r requirements.txt` manually.",
        ))

    return findings


# ─── Package Age Check ───────────────────────────────────────

async def check_package_age(package_name: str, ecosystem: str) -> Optional[Finding]:
    """
    Check if a package was recently published (< 30 days) or had an ownership transfer.

    Args:
        package_name: The name of the package.
        ecosystem: Either 'npm' or 'pypi'.

    Returns:
        A Finding if suspicious, otherwise None.
    """
    from datetime import datetime, timedelta, timezone

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            if ecosystem == "npm":
                url = f"https://registry.npmjs.org/{package_name}"
                resp = await client.get(url)
                if resp.status_code != 200:
                    return None

                data = resp.json()
                time_data = data.get("time", {})

                # Check latest publish date
                versions = list(time_data.keys())
                versions = [v for v in versions if v not in ("created", "modified")]
                if versions:
                    latest_version = versions[-1]
                    latest_date_str = time_data.get(latest_version, "")
                    if latest_date_str:
                        latest_date = datetime.fromisoformat(latest_date_str.replace("Z", "+00:00"))
                        if datetime.now(timezone.utc) - latest_date < timedelta(days=30):
                            return Finding(
                                id=str(uuid4()),
                                category="dependency-audit",
                                severity="HIGH",
                                title=f"Recently published package: {package_name}",
                                description=(
                                    f"The package '{package_name}' was last published less than 30 days ago "
                                    f"({latest_date.strftime('%Y-%m-%d')}). Recently published or transferred "
                                    f"packages may pose a supply chain risk."
                                ),
                                file_path="package.json",
                                remediation="Verify the package maintainer identity and review the changelog before using.",
                                cwe_id="CWE-829",
                            )

                # Check for maintainer changes
                maintainers = data.get("maintainers", [])
                if len(maintainers) == 1:
                    created = time_data.get("created", "")
                    if created:
                        created_date = datetime.fromisoformat(created.replace("Z", "+00:00"))
                        if datetime.now(timezone.utc) - created_date < timedelta(days=60):
                            return Finding(
                                id=str(uuid4()),
                                category="dependency-audit",
                                severity="HIGH",
                                title=f"New single-maintainer package: {package_name}",
                                description=(
                                    f"'{package_name}' was created in the last 60 days with a single maintainer. "
                                    f"This pattern is common in supply chain attacks."
                                ),
                                file_path="package.json",
                                remediation="Review the package source code thoroughly before use.",
                                cwe_id="CWE-829",
                            )

            elif ecosystem == "pypi":
                url = f"https://pypi.org/pypi/{package_name}/json"
                resp = await client.get(url)
                if resp.status_code != 200:
                    return None

                data = resp.json()
                info = data.get("info", {})
                releases = data.get("releases", {})

                if releases:
                    latest_version = info.get("version", "")
                    release_files = releases.get(latest_version, [])
                    if release_files:
                        upload_time = release_files[0].get("upload_time_iso_8601", "")
                        if upload_time:
                            upload_date = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                            if datetime.now(timezone.utc) - upload_date < timedelta(days=30):
                                return Finding(
                                    id=str(uuid4()),
                                    category="dependency-audit",
                                    severity="HIGH",
                                    title=f"Recently published PyPI package: {package_name}",
                                    description=(
                                        f"'{package_name}' was published less than 30 days ago. "
                                        f"Review carefully for supply chain risks."
                                    ),
                                    file_path="requirements.txt",
                                    remediation="Verify the package author and review source before use.",
                                    cwe_id="CWE-829",
                                )

    except (httpx.HTTPError, KeyError, ValueError, TypeError):
        return Finding(
            id=str(uuid4()),
            category="dependency-audit",
            severity="INFO",
            title=f"Could not verify package age: {package_name}",
            description=f"Unable to reach the {ecosystem} registry to verify {package_name}.",
            remediation="Check the package manually on the registry website.",
        )

    return None


# ─── Typosquatting Detection ─────────────────────────────────

def check_typosquatting(package_name: str, known_packages: list[str]) -> Optional[Finding]:
    """
    Check if a package name is suspiciously similar to a known popular package.

    Uses Levenshtein distance to detect potential typosquatting attacks.

    Args:
        package_name: The package to check.
        known_packages: List of known legitimate popular packages.

    Returns:
        A CRITICAL Finding if typosquatting detected, else None.
    """
    try:
        from Levenshtein import distance as levenshtein_distance
    except ImportError:
        # Fallback: simple implementation
        def levenshtein_distance(s1: str, s2: str) -> int:
            if len(s1) < len(s2):
                return levenshtein_distance(s2, s1)
            if len(s2) == 0:
                return len(s1)
            prev_row = range(len(s2) + 1)
            for i, c1 in enumerate(s1):
                curr_row = [i + 1]
                for j, c2 in enumerate(s2):
                    insertions = prev_row[j + 1] + 1
                    deletions = curr_row[j] + 1
                    substitutions = prev_row[j] + (c1 != c2)
                    curr_row.append(min(insertions, deletions, substitutions))
                prev_row = curr_row
            return prev_row[-1]

    for known in known_packages:
        if package_name == known:
            continue

        dist = levenshtein_distance(package_name.lower(), known.lower())
        if dist <= 2 and dist > 0:
            return Finding(
                id=str(uuid4()),
                category="dependency-audit",
                severity="CRITICAL",
                title=f"Possible typosquatting: '{package_name}' similar to '{known}'",
                description=(
                    f"The package '{package_name}' has a name very similar to the popular package "
                    f"'{known}' (Levenshtein distance: {dist}). This is a common supply chain attack "
                    f"vector where attackers publish packages with names similar to popular ones."
                ),
                file_path="package.json",
                remediation=f"Verify you intended to install '{package_name}' and not '{known}'. Check the npm/PyPI page for the correct package.",
                cwe_id="CWE-829",
            )

    return None


# ─── Unpinned Dependencies ──────────────────────────────────

def check_unpinned_dependencies(directory: str) -> list[Finding]:
    """
    Check for unpinned dependency versions in package.json or requirements.txt.

    Unpinned deps (using ^, ~, *, >=) can lead to unexpected version upgrades
    that may introduce vulnerabilities.

    Args:
        directory: Path to the project directory.

    Returns:
        List of Finding objects for each unpinned dependency.
    """
    findings: list[Finding] = []
    range_pattern = re.compile(r'[\^~*><=]')

    # Check package.json
    pkg_json_path = os.path.join(directory, "package.json")
    if os.path.isfile(pkg_json_path):
        try:
            with open(pkg_json_path, "r", encoding="utf-8") as f:
                pkg = json.load(f)

            for dep_type in ("dependencies", "devDependencies", "peerDependencies"):
                deps = pkg.get(dep_type, {})
                for name, version in deps.items():
                    if isinstance(version, str) and range_pattern.search(version):
                        findings.append(Finding(
                            id=str(uuid4()),
                            category="dependency-audit",
                            severity="LOW",
                            title=f"Unpinned dependency: {name}@{version}",
                            description=(
                                f"The dependency '{name}' uses a version range '{version}' instead "
                                f"of an exact pin. This allows automatic minor/patch upgrades that "
                                f"could introduce vulnerabilities."
                            ),
                            file_path="package.json",
                            remediation=f"Pin to an exact version: `npm install {name}@<exact-version> --save-exact`",
                            cwe_id="CWE-1104",
                        ))
        except (json.JSONDecodeError, OSError):
            pass

    # Check requirements.txt
    req_path = os.path.join(directory, "requirements.txt")
    if os.path.isfile(req_path):
        try:
            with open(req_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            for i, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue

                # Check for range specifiers
                if ">=" in line or "~=" in line or "<" in line or "!=" in line:
                    pkg_name = re.split(r'[><=!~]', line)[0].strip()
                    findings.append(Finding(
                        id=str(uuid4()),
                        category="dependency-audit",
                        severity="LOW",
                        title=f"Unpinned Python dependency: {line}",
                        description=(
                            f"Line {i}: '{line}' uses a version range instead of an exact pin."
                        ),
                        file_path="requirements.txt",
                        line_number=i,
                        remediation=f"Pin to exact version: `{pkg_name}==<exact-version>`",
                        cwe_id="CWE-1104",
                    ))
                elif "==" not in line and re.match(r'^[a-zA-Z0-9_-]', line):
                    # No version specifier at all
                    findings.append(Finding(
                        id=str(uuid4()),
                        category="dependency-audit",
                        severity="LOW",
                        title=f"Unversioned Python dependency: {line}",
                        description=(
                            f"Line {i}: '{line}' has no version specifier. Any version will be installed."
                        ),
                        file_path="requirements.txt",
                        line_number=i,
                        remediation=f"Add an exact version: `{line}==<version>`",
                        cwe_id="CWE-1104",
                    ))
        except OSError:
            pass

    return findings


# ─── Well-Known Package Lists for Typosquatting ──────────────

POPULAR_NPM_PACKAGES = [
    "express", "react", "lodash", "axios", "chalk", "commander", "next",
    "typescript", "webpack", "babel", "eslint", "prettier", "jest",
    "mocha", "chai", "mongoose", "sequelize", "prisma", "socket.io",
    "fastify", "koa", "hapi", "dotenv", "cors", "helmet", "morgan",
    "passport", "jsonwebtoken", "bcrypt", "uuid", "moment", "dayjs",
    "zod", "yup", "joi", "ajv", "fs-extra", "glob", "rimraf",
    "@modelcontextprotocol/sdk", "@anthropic-ai/sdk",
]

POPULAR_PYPI_PACKAGES = [
    "requests", "flask", "django", "fastapi", "numpy", "pandas",
    "scikit-learn", "tensorflow", "torch", "celery", "redis",
    "sqlalchemy", "pydantic", "httpx", "aiohttp", "boto3",
    "pillow", "matplotlib", "beautifulsoup4", "scrapy",
    "cryptography", "paramiko", "fabric", "ansible",
    "pytest", "black", "ruff", "mypy", "uvicorn",
]


# ─── Main Entry Point ───────────────────────────────────────

async def run_full_dependency_audit(directory: str) -> list[Finding]:
    """
    Run a complete dependency audit on the given directory.

    This runs all dependency checks: npm audit, pip audit, package age,
    typosquatting, and unpinned dependencies.

    Args:
        directory: Path to the MCP server directory.

    Returns:
        Combined list of all dependency findings.
    """
    findings: list[Finding] = []

    # Run npm and pip audits
    findings.extend(run_npm_audit(directory))
    findings.extend(run_pip_audit(directory))

    # Check unpinned dependencies
    findings.extend(check_unpinned_dependencies(directory))

    # Check typosquatting for npm packages
    pkg_json_path = os.path.join(directory, "package.json")
    if os.path.isfile(pkg_json_path):
        try:
            with open(pkg_json_path, "r", encoding="utf-8") as f:
                pkg = json.load(f)
            all_deps = list(pkg.get("dependencies", {}).keys()) + list(pkg.get("devDependencies", {}).keys())
            for dep in all_deps:
                result = check_typosquatting(dep, POPULAR_NPM_PACKAGES)
                if result:
                    findings.append(result)

                # Check package age
                age_result = await check_package_age(dep, "npm")
                if age_result:
                    findings.append(age_result)
        except (json.JSONDecodeError, OSError):
            pass

    # Check typosquatting for Python packages
    req_path = os.path.join(directory, "requirements.txt")
    if os.path.isfile(req_path):
        try:
            with open(req_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and not line.startswith("-"):
                        pkg_name = re.split(r'[><=!~\[]', line)[0].strip()
                        if pkg_name:
                            result = check_typosquatting(pkg_name, POPULAR_PYPI_PACKAGES)
                            if result:
                                findings.append(result)

                            age_result = await check_package_age(pkg_name, "pypi")
                            if age_result:
                                findings.append(age_result)
        except OSError:
            pass

    return findings


def main():
    """CLI entry point for testing the dependency audit module."""
    import argparse
    parser = argparse.ArgumentParser(description="MCPGuard Dependency Audit")
    parser.add_argument("directory", help="Path to the MCP server directory to audit")
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(f"Error: '{args.directory}' is not a valid directory")
        sys.exit(1)

    findings = asyncio.run(run_full_dependency_audit(args.directory))

    print(f"\n{'=' * 60}")
    print(f"  Dependency Audit Results: {len(findings)} finding(s)")
    print(f"{'=' * 60}\n")

    for f in findings:
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "ℹ️"}.get(f.severity, "❓")
        print(f"  {icon} [{f.severity}] {f.title}")
        print(f"     {f.description[:120]}")
        if f.remediation:
            print(f"     Fix: {f.remediation[:120]}")
        print()


if __name__ == "__main__":
    main()
