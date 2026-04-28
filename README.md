# MCPGuard 🛡️

[![MCP Security](https://img.shields.io/badge/MCP-Security-blue.svg)](https://modelcontextprotocol.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**MCPGuard** is a comprehensive, production-ready security scanning platform for the Model Context Protocol (MCP) ecosystem. 

As AI agents gain the ability to interact with local and remote systems via MCP servers, the attack surface expands exponentially. MCPGuard analyzes tool definitions, dependencies, and source code to detect vulnerabilities before you connect a server to your agent.

## Features

- **Tool Poisoning Detection:** Analyzes MCP tool definitions (using regex heuristics and optional Claude AI analysis) to detect hidden instructions designed to manipulate LLMs.
- **Dependency Auditing:** Checks for typosquatting, outdated packages, and known vulnerabilities via `npm audit` and `pip-audit`.
- **Static Code Analysis:** AST-based scanning for Python and regex-based scanning for JS/TS to catch shell injection, path traversal, and hardcoded secrets.
- **Permissions Audit:** Evaluates the overall scope of permissions your server requests.
- **Public Registry:** A community-driven database tracking security scores and advisories for public MCP servers.
- **Developer Tooling:** Includes a Next.js web dashboard, a FastAPI scanning engine, a TypeScript CLI, and a GitHub Action.

## Project Architecture

```text
mcpguard/
├── frontend/          # Next.js 15 UI with Tailwind & shadcn/ui
├── backend/           # FastAPI app handling API endpoints & Celery tasks
├── scanner/           # Core Python security scanning engine
├── cli/               # TypeScript CLI tool
└── action/            # GitHub Action integration
```

## Quick Start (Local Development)

### Prerequisites
- Node.js (v20+)
- Python (v3.10+)
- Docker & Docker Compose

### Running the Platform

1. **Clone the repository:**
   ```bash
   git clone https://github.com/mudbbir23/MCPGuard.git
   cd MCPGuard
   ```

2. **Configure Environment:**
   ```bash
   cp .env.example .env
   # Edit .env and add your API keys (Anthropic, Clerk, Supabase, etc.)
   ```

3. **Start the Infrastructure:**
   ```bash
   # Starts Postgres, Redis, Celery Worker, FastAPI backend, and Next.js frontend
   docker-compose up --build
   ```

4. **Access the Application:**
   - Frontend: [http://localhost:3000](http://localhost:3000)
   - API Docs: [http://localhost:8000/docs](http://localhost:8000/docs)

## Using the CLI

```bash
cd cli
npm install
npx tsx src/index.ts scan https://github.com/modelcontextprotocol/server-filesystem
```

## GitHub Action

Add MCPGuard to your CI/CD pipeline to block vulnerable MCP servers from being deployed:

```yaml
steps:
  - uses: actions/checkout@v4
  - name: Run MCPGuard
    uses: mudbbir23/MCPGuard/action@main
    with:
      fail-on-critical: 'true'
```

## License

This project is licensed under the MIT License.
