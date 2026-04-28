# MCPGuard GitHub Action

Automated security scanning for Model Context Protocol (MCP) servers in your CI/CD pipeline.

## Usage

Add this step to your GitHub Actions workflow (e.g., `.github/workflows/security.yml`):

```yaml
name: MCP Security Scan

on:
  pull_request:
    branches: [ main ]
  push:
    branches: [ main ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run MCPGuard Security Scanner
        uses: mudbbir23/MCPGuard/action@main
        with:
          # Optional: Fail the build if CRITICAL or HIGH vulnerabilities are found (default: true)
          fail-on-critical: 'true'
```

## What it does

This action automatically sends your repository URL to the MCPGuard API to perform a comprehensive security audit:
1. **Tool Poisoning Detection:** Analyzes MCP tool definitions for prompt injections and malicious instructions.
2. **Dependency Audit:** Checks for known vulnerabilities, typosquatting, and outdated packages.
3. **Static Code Analysis:** Scans your Python or JavaScript/TypeScript AST for dangerous patterns like shell injection, path traversal, and hardcoded secrets.
4. **Permissions Audit:** Evaluates the overall scope of permissions your server requests.

If any CRITICAL or HIGH issues are detected and `fail-on-critical` is set to `true`, the workflow will fail, preventing vulnerable MCP servers from being merged or deployed.
