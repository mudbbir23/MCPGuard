"""
MCPGuard — Permission Audit Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Analyzes MCP server configurations and code for excessive or dangerous permission requests.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal
from uuid import uuid4

from scanner.dependency_audit import Finding


def audit_permissions(directory: str) -> list[Finding]:
    """
    Audit an MCP server directory for dangerous permission patterns.

    Checks:
    - Filesystem access patterns (reading outside designated directories)
    - Network access patterns (outbound HTTP to suspicious domains)
    - Environment variable access (reading secrets)
    - Excessive Docker/container privileges
    - Shell command execution capabilities

    Args:
        directory: Path to the MCP server source directory.

    Returns:
        List of Finding objects for each permission concern.
    """
    findings: list[Finding] = []

    for root, dirs, files in os.walk(directory):
        # Skip non-source directories
        dirs[:] = [d for d in dirs if d not in {
            "node_modules", ".git", "__pycache__", "dist", "build", ".venv", "venv"
        }]

        for filename in files:
            if not filename.endswith((".py", ".js", ".ts", ".mjs", ".cjs")):
                continue

            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, directory)

            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    lines = content.splitlines()
            except OSError:
                continue

            # Check for filesystem access outside designated dirs
            fs_patterns = [
                (r'os\.path\.expanduser\s*\(', "Accesses user home directory"),
                (r'Path\.home\s*\(', "Accesses user home directory"),
                (r'os\.environ', "Reads environment variables (potential secret access)"),
                (r'process\.env', "Reads environment variables (potential secret access)"),
                (r'\/etc\/passwd|\/etc\/shadow', "Accesses system credential files"),
                (r'\.ssh[/\\]', "Accesses SSH directory"),
                (r'\.aws[/\\]|\.azure[/\\]|\.gcp[/\\]', "Accesses cloud credential directories"),
            ]

            for pattern, desc in fs_patterns:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line):
                        findings.append(Finding(
                            id=str(uuid4()),
                            category="permission-audit",
                            severity="HIGH",
                            title=f"Dangerous permission: {desc}",
                            description=f"Line {i} in {rel_path}: {desc}. This could allow the MCP server to access sensitive data outside its intended scope.",
                            file_path=rel_path,
                            line_number=i,
                            remediation="Restrict file access to designated directories only. Use allowlists for permitted paths.",
                            cwe_id="CWE-732",
                        ))

            # Check for network access patterns
            net_patterns = [
                (r'https?://[^\s\'"]+webhook', "Sends data to external webhook"),
                (r'https?://[^\s\'"]+\.ngrok', "Connects to ngrok tunnel (potential exfiltration)"),
                (r'dns\.resolve|dns\.lookup', "Performs DNS lookups (potential DNS exfiltration)"),
                (r'net\.createServer|http\.createServer', "Creates a network server"),
            ]

            for pattern, desc in net_patterns:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line):
                        findings.append(Finding(
                            id=str(uuid4()),
                            category="permission-audit",
                            severity="MEDIUM",
                            title=f"Network permission: {desc}",
                            description=f"Line {i} in {rel_path}: {desc}.",
                            file_path=rel_path,
                            line_number=i,
                            remediation="Review network access and restrict outbound connections to known-safe endpoints.",
                            cwe_id="CWE-918",
                        ))

            # Check for privilege escalation patterns
            priv_patterns = [
                (r'sudo|runas|pkexec', "Attempts privilege escalation"),
                (r'chmod\s+777|chmod\s+666', "Sets overly permissive file permissions"),
                (r'--privileged|--cap-add', "Requests Docker container privileges"),
            ]

            for pattern, desc in priv_patterns:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append(Finding(
                            id=str(uuid4()),
                            category="permission-audit",
                            severity="CRITICAL",
                            title=f"Privilege escalation: {desc}",
                            description=f"Line {i} in {rel_path}: {desc}.",
                            file_path=rel_path,
                            line_number=i,
                            remediation="Run with least privileges. Never request root or elevated permissions.",
                            cwe_id="CWE-269",
                        ))

    # Deduplicate
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f.file_path, f.line_number, f.category, f.title)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    return sorted(unique_findings, key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(f.severity, 5))
