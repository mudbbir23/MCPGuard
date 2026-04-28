"""
MCPGuard — Static Code Analysis Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
AST-based analysis for Python and regex-based scanning for JavaScript/TypeScript
to detect security vulnerabilities in MCP server source code.
"""

from __future__ import annotations

import ast
import os
import re
from pathlib import Path
from typing import Optional
from uuid import uuid4

from scanner.dependency_audit import Finding


# ─── Hardcoded Secret Patterns ───────────────────────────────

SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token"),
    (r'gho_[a-zA-Z0-9]{36}', "GitHub OAuth Token"),
    (r'github_pat_[a-zA-Z0-9_]{22,}', "GitHub Fine-Grained PAT"),
    (r'sk-[a-zA-Z0-9]{20,}', "OpenAI/Anthropic API Key"),
    (r'sk-ant-api[a-zA-Z0-9-]{20,}', "Anthropic API Key"),
    (r'key-[a-zA-Z0-9]{20,}', "Generic API Key"),
    (r'glpat-[a-zA-Z0-9\-_]{20,}', "GitLab PAT"),
    (r'xox[bps]-[a-zA-Z0-9\-]{10,}', "Slack Token"),
    (r'sk_live_[a-zA-Z0-9]{20,}', "Stripe Live Key"),
    (r'rk_live_[a-zA-Z0-9]{20,}', "Stripe Restricted Key"),
    (r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', "SendGrid API Key"),
    (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', "Private Key"),
    (r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}', "JWT Token"),
]

# Directories to skip
SKIP_DIRS = {"node_modules", ".git", "__pycache__", "dist", "build", ".venv", "venv", ".next", ".cache"}


# ─── Python AST Security Visitor ─────────────────────────────

class PythonSecurityVisitor(ast.NodeVisitor):
    """
    AST visitor that detects security vulnerabilities in Python source code.

    Detects:
    - exec()/eval() calls
    - Shell injection via subprocess/os.system
    - Path traversal via open() with variables
    - Unsafe deserialization (pickle/marshal)
    - Hardcoded credentials
    - Missing authentication on route handlers
    """

    def __init__(self, filepath: str, source_lines: list[str]):
        self.filepath = filepath
        self.source_lines = source_lines
        self.findings: list[Finding] = []
        self._imports: set[str] = set()
        self._has_auth_decorator = False

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._imports.add(alias.name)
            # Check for unsafe deserialization modules
            if alias.name in ("pickle", "marshal", "shelve", "cPickle"):
                self.findings.append(Finding(
                    id=str(uuid4()),
                    category="static-analysis",
                    severity="HIGH",
                    title=f"Unsafe deserialization: import {alias.name}",
                    description=(
                        f"Importing '{alias.name}' enables deserialization of arbitrary objects, "
                        f"which can lead to remote code execution if untrusted data is deserialized."
                    ),
                    file_path=self.filepath,
                    line_number=node.lineno,
                    remediation="Use JSON or other safe serialization formats instead of pickle/marshal.",
                    cwe_id="CWE-502",
                ))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self._imports.add(node.module)
            if node.module in ("pickle", "marshal", "shelve", "cPickle"):
                self.findings.append(Finding(
                    id=str(uuid4()),
                    category="static-analysis",
                    severity="HIGH",
                    title=f"Unsafe deserialization: from {node.module} import ...",
                    description=(
                        f"Importing from '{node.module}' enables unsafe deserialization."
                    ),
                    file_path=self.filepath,
                    line_number=node.lineno,
                    remediation="Use JSON or other safe serialization formats.",
                    cwe_id="CWE-502",
                ))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func_name = self._get_func_name(node.func)

        # exec() / eval() detection
        if func_name in ("exec", "eval"):
            self.findings.append(Finding(
                id=str(uuid4()),
                category="static-analysis",
                severity="CRITICAL",
                title=f"Dangerous function: {func_name}()",
                description=(
                    f"The use of {func_name}() allows execution of arbitrary code. "
                    f"If user input can reach this call, it enables remote code execution."
                ),
                file_path=self.filepath,
                line_number=node.lineno,
                remediation=f"Remove {func_name}(). Use ast.literal_eval() for safe evaluation of literals.",
                cwe_id="CWE-95",
            ))

        # subprocess / os.system shell injection
        if func_name in ("subprocess.run", "subprocess.call", "subprocess.Popen",
                         "subprocess.check_output", "subprocess.check_call", "os.system", "os.popen"):
            if node.args:
                first_arg = node.args[0]
                if self._is_string_formatting(first_arg):
                    self.findings.append(Finding(
                        id=str(uuid4()),
                        category="static-analysis",
                        severity="CRITICAL",
                        title=f"Shell injection via {func_name}()",
                        description=(
                            f"Using string formatting in {func_name}() arguments can lead to "
                            f"shell command injection if the formatted values come from user input."
                        ),
                        file_path=self.filepath,
                        line_number=node.lineno,
                        remediation="Use a list of arguments instead of string formatting. Never use shell=True with user input.",
                        cwe_id="CWE-78",
                    ))

            # Check for shell=True
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append(Finding(
                        id=str(uuid4()),
                        category="static-analysis",
                        severity="HIGH",
                        title=f"shell=True in {func_name}()",
                        description=(
                            f"Using shell=True with {func_name}() allows shell interpretation "
                            f"of the command, enabling command injection attacks."
                        ),
                        file_path=self.filepath,
                        line_number=node.lineno,
                        remediation="Remove shell=True. Pass command as a list of arguments instead.",
                        cwe_id="CWE-78",
                    ))

        # open() path traversal
        if func_name in ("open", "builtins.open"):
            if node.args:
                path_arg = node.args[0]
                if isinstance(path_arg, ast.Name):
                    # Path comes from a variable — potential traversal
                    self.findings.append(Finding(
                        id=str(uuid4()),
                        category="static-analysis",
                        severity="HIGH",
                        title="Potential path traversal in open()",
                        description=(
                            f"The file path passed to open() comes from a variable, which could "
                            f"be user-controlled. Without path validation, an attacker could "
                            f"read arbitrary files using ../ traversal."
                        ),
                        file_path=self.filepath,
                        line_number=node.lineno,
                        remediation="Validate and normalize the path using os.path.abspath() or Path.resolve(). Check the result is within the expected directory.",
                        cwe_id="CWE-22",
                    ))

        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        """Check string constants for hardcoded secrets."""
        if isinstance(node.value, str) and len(node.value) > 8:
            for pattern, secret_type in SECRET_PATTERNS:
                if re.search(pattern, node.value):
                    # Avoid false positives from test/example strings
                    line_content = ""
                    if node.lineno and node.lineno <= len(self.source_lines):
                        line_content = self.source_lines[node.lineno - 1].lower()
                    if any(skip in line_content for skip in ("example", "test", "placeholder", "xxx", "your-")):
                        continue

                    self.findings.append(Finding(
                        id=str(uuid4()),
                        category="static-analysis",
                        severity="CRITICAL",
                        title=f"Hardcoded credential: {secret_type}",
                        description=(
                            f"A {secret_type} was found hardcoded in the source code. "
                            f"Hardcoded credentials can be extracted from source code and used for unauthorized access."
                        ),
                        file_path=self.filepath,
                        line_number=node.lineno,
                        remediation="Move this credential to an environment variable. Never commit secrets to source code.",
                        cwe_id="CWE-798",
                    ))
                    break  # One finding per string
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Check for missing authentication on route handlers."""
        is_route = False
        for decorator in node.decorator_list:
            decorator_name = self._get_func_name(decorator) if isinstance(decorator, ast.Call) else self._get_attr_name(decorator)
            if decorator_name and any(route in str(decorator_name) for route in (".get", ".post", ".put", ".delete", ".patch", ".route")):
                is_route = True
            if decorator_name and "auth" in str(decorator_name).lower():
                self._has_auth_decorator = True

        if is_route and not self._has_auth_decorator:
            # Check if any parameter has "Depends" with "auth" in name
            has_auth_dep = False
            for arg in node.args.args:
                if arg.annotation:
                    ann_str = ast.dump(arg.annotation)
                    if "auth" in ann_str.lower() or "current_user" in ann_str.lower():
                        has_auth_dep = True
            for default in node.args.defaults:
                if isinstance(default, ast.Call):
                    fn = self._get_func_name(default.func) if hasattr(default, 'func') else ""
                    if "depends" in str(fn).lower() or "auth" in str(fn).lower():
                        has_auth_dep = True

            if not has_auth_dep:
                self.findings.append(Finding(
                    id=str(uuid4()),
                    category="static-analysis",
                    severity="MEDIUM",
                    title=f"Potentially unauthenticated route: {node.name}()",
                    description=(
                        f"The route handler '{node.name}' does not appear to have authentication. "
                        f"Ensure this is intentional if the endpoint should be public."
                    ),
                    file_path=self.filepath,
                    line_number=node.lineno,
                    remediation="Add authentication via a Depends() parameter or auth decorator.",
                    cwe_id="CWE-306",
                ))

        self._has_auth_decorator = False
        self.generic_visit(node)

    def _get_func_name(self, node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            value = self._get_func_name(node.value)
            return f"{value}.{node.attr}" if value else node.attr
        elif isinstance(node, ast.Call):
            return self._get_func_name(node.func)
        return ""

    def _get_attr_name(self, node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            value = self._get_attr_name(node.value)
            return f"{value}.{node.attr}" if value else node.attr
        return ""

    def _is_string_formatting(self, node: ast.expr) -> bool:
        """Check if a node involves string formatting (f-strings, .format(), %)."""
        if isinstance(node, ast.JoinedStr):  # f-string
            return True
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            return True
        return False


# ─── JavaScript/TypeScript Scanner ───────────────────────────

def scan_js_file(filepath: str) -> list[Finding]:
    """
    Scan a JavaScript/TypeScript file for security issues using regex patterns.

    Detects:
    - exec/execSync/spawn with string concatenation
    - eval()
    - Path traversal in fs operations
    - Hardcoded credentials
    - require('child_process') with user input

    Args:
        filepath: Path to the JS/TS file.

    Returns:
        List of Finding objects.
    """
    findings: list[Finding] = []

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            lines = content.splitlines()
    except OSError:
        return findings

    rel_path = filepath

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        # Skip comments
        if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
            continue

        # exec/execSync/spawn with string concatenation
        if re.search(r'(exec|execSync|execFileSync)\s*\(', stripped):
            if re.search(r'(exec|execSync|execFileSync)\s*\([^)]*(\+|`\$\{)', stripped):
                findings.append(Finding(
                    id=str(uuid4()),
                    category="static-analysis",
                    severity="CRITICAL",
                    title="Shell injection: exec/execSync with string concatenation",
                    description=f"Command execution with string interpolation detected. User input could be injected into shell commands.",
                    file_path=rel_path,
                    line_number=i,
                    remediation="Use execFile() or spawn() with an array of arguments instead of string concatenation.",
                    cwe_id="CWE-78",
                ))

        # spawn with string concatenation
        if re.search(r'spawn\s*\(', stripped) and re.search(r'spawn\s*\([^)]*(\+|`\$\{)', stripped):
            findings.append(Finding(
                id=str(uuid4()),
                category="static-analysis",
                severity="CRITICAL",
                title="Shell injection: spawn with string concatenation",
                description="Process spawn with string interpolation in arguments.",
                file_path=rel_path,
                line_number=i,
                remediation="Pass arguments as an array to spawn(), never concatenate strings.",
                cwe_id="CWE-78",
            ))

        # eval()
        if re.search(r'\beval\s*\(', stripped) and not stripped.startswith("//"):
            findings.append(Finding(
                id=str(uuid4()),
                category="static-analysis",
                severity="CRITICAL",
                title="Dangerous function: eval()",
                description="eval() allows execution of arbitrary JavaScript code, enabling code injection attacks.",
                file_path=rel_path,
                line_number=i,
                remediation="Remove eval(). Use JSON.parse() for data or Function constructor for sandboxed evaluation.",
                cwe_id="CWE-95",
            ))

        # fs operations with variables
        fs_funcs = r'(readFile|readFileSync|writeFile|writeFileSync|readdir|readdirSync|unlink|unlinkSync|rmdir|rmdirSync)'
        if re.search(rf'fs\.{fs_funcs}\s*\(', stripped):
            # Check if path argument is a variable (not a string literal)
            match = re.search(rf'fs\.{fs_funcs}\s*\(\s*([^\'"][^,)]*)', stripped)
            if match:
                path_arg = match.group(2).strip()
                if path_arg and not path_arg.startswith(("'", '"', '`', '__dirname', 'path.join(__dirname')):
                    findings.append(Finding(
                        id=str(uuid4()),
                        category="static-analysis",
                        severity="HIGH",
                        title=f"Path traversal in fs.{match.group(1)}()",
                        description=f"File system operation uses a variable as path, which could allow directory traversal attacks.",
                        file_path=rel_path,
                        line_number=i,
                        remediation="Validate and sanitize the path. Use path.resolve() and verify the result is within the allowed directory.",
                        cwe_id="CWE-22",
                    ))

        # Hardcoded credentials
        for pattern, secret_type in SECRET_PATTERNS:
            if re.search(pattern, stripped):
                # Skip obvious test/example patterns
                if any(skip in stripped.lower() for skip in ("example", "test", "placeholder", "xxx", "your-", "todo")):
                    continue
                findings.append(Finding(
                    id=str(uuid4()),
                    category="static-analysis",
                    severity="CRITICAL",
                    title=f"Hardcoded credential: {secret_type}",
                    description=f"A {secret_type} was found hardcoded in source code.",
                    file_path=rel_path,
                    line_number=i,
                    remediation="Move this credential to an environment variable.",
                    cwe_id="CWE-798",
                ))
                break  # One per line

        # require('child_process')
        if re.search(r"require\s*\(\s*['\"]child_process['\"]\s*\)", stripped):
            findings.append(Finding(
                id=str(uuid4()),
                category="static-analysis",
                severity="HIGH",
                title="child_process module imported",
                description="The child_process module enables command execution. Ensure commands are not constructed from user input.",
                file_path=rel_path,
                line_number=i,
                remediation="Avoid child_process if possible. If needed, use execFile() with a fixed command and array arguments.",
                cwe_id="CWE-78",
            ))

    return findings


# ─── Directory Scanner ───────────────────────────────────────

def scan_directory(directory: str) -> list[Finding]:
    """
    Recursively scan a directory for security vulnerabilities.

    Walks all .py, .js, .ts files (skipping node_modules, .git, etc.),
    runs the appropriate scanner on each file, deduplicates findings,
    and returns them sorted by severity (CRITICAL first).

    Args:
        directory: Path to the MCP server directory.

    Returns:
        Combined, deduplicated list of findings sorted by severity.
    """
    findings: list[Finding] = []

    for root, dirs, files in os.walk(directory):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for filename in files:
            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, directory)

            if filename.endswith(".py"):
                # Python AST analysis
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        source = f.read()
                        source_lines = source.splitlines()

                    tree = ast.parse(source, filename=filepath)
                    visitor = PythonSecurityVisitor(rel_path, source_lines)
                    visitor.visit(tree)
                    findings.extend(visitor.findings)
                except SyntaxError:
                    # Can't parse — skip
                    pass
                except Exception:
                    pass

            elif filename.endswith((".js", ".ts", ".mjs", ".cjs")):
                # JavaScript/TypeScript regex scanning
                js_findings = scan_js_file(filepath)
                # Update file paths to be relative
                for f in js_findings:
                    f.file_path = rel_path
                findings.extend(js_findings)

    # Deduplicate by (file_path, line_number, category)
    seen: set[tuple] = set()
    unique_findings: list[Finding] = []
    for f in findings:
        key = (f.file_path, f.line_number, f.category, f.title)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    unique_findings.sort(key=lambda f: severity_order.get(f.severity, 5))

    return unique_findings


# ─── Finding Explainer ───────────────────────────────────────

def explain_finding(finding: Finding) -> str:
    """
    Generate a one-sentence plain-English explanation of a finding.

    Suitable for showing to non-security-expert developers.

    Args:
        finding: The Finding to explain.

    Returns:
        A brief human-readable explanation.
    """
    explanations = {
        "CWE-78": f"This code could let an attacker run system commands on your server by injecting malicious input.",
        "CWE-95": f"This code executes arbitrary code, which means an attacker could run anything they want on your machine.",
        "CWE-22": f"This code reads files based on a variable, which an attacker could exploit to read sensitive files like /etc/passwd.",
        "CWE-502": f"This code deserializes data in a way that could let an attacker execute code by sending crafted data.",
        "CWE-798": f"There's a password or API key hardcoded in the source code — anyone who sees this code gets access.",
        "CWE-306": f"This API endpoint doesn't check if the user is logged in, so anyone could access it.",
        "CWE-829": f"This dependency might be malicious — it's either very new, has a suspicious name, or recently changed ownership.",
        "CWE-1104": f"Dependencies aren't locked to specific versions, so a malicious update could be installed automatically.",
    }

    if finding.cwe_id and finding.cwe_id in explanations:
        return explanations[finding.cwe_id]

    # Fallback generic explanation
    return f"{finding.title}: {finding.description[:100]}"


# ─── Main Entry Point ───────────────────────────────────────

def main():
    """CLI entry point for testing the static analysis module."""
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="MCPGuard Static Analysis")
    parser.add_argument("directory", help="Path to scan")
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(f"Error: '{args.directory}' is not a valid directory")
        sys.exit(1)

    findings = scan_directory(args.directory)

    print(f"\n{'=' * 60}")
    print(f"  Static Analysis Results: {len(findings)} finding(s)")
    print(f"{'=' * 60}\n")

    for f in findings:
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "ℹ️"}.get(f.severity, "❓")
        print(f"  {icon} [{f.severity}] {f.title}")
        if f.file_path:
            loc = f.file_path
            if f.line_number:
                loc += f":{f.line_number}"
            print(f"     File: {loc}")
        print(f"     {explain_finding(f)}")
        print()


if __name__ == "__main__":
    main()
