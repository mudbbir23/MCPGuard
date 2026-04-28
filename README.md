# MCPGuard 🛡️

[![MCP Security](https://img.shields.io/badge/MCP-Security-blue.svg)](https://modelcontextprotocol.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**MCPGuard** is a comprehensive, production-ready security scanning platform for the Model Context Protocol (MCP) ecosystem. 

As AI agents gain the ability to interact with local and remote systems via MCP servers, the attack surface expands exponentially. MCPGuard analyzes tool definitions, dependencies, and source code to detect vulnerabilities before you connect a server to your agent.

---

## 🌟 Features

- **Tool Poisoning Detection:** Analyzes MCP tool definitions (using regex heuristics and optional Claude AI analysis) to detect hidden instructions designed to manipulate LLMs.
- **Dependency Auditing:** Checks for typosquatting, outdated packages, and known vulnerabilities via `npm audit` and `pip-audit`.
- **Static Code Analysis:** AST-based scanning for Python and regex-based scanning for JS/TS to catch shell injection, path traversal, and hardcoded secrets.
- **Permissions Audit:** Evaluates the overall scope of permissions your server requests.
- **Public Registry:** A community-driven database tracking security scores and advisories for public MCP servers.
- **Developer Tooling:** Includes a Next.js web dashboard, a FastAPI scanning engine, a TypeScript CLI, and a GitHub Action.

---

## 🏗️ Project Architecture

```text
mcpguard/
├── frontend/          # Next.js 15 UI with Tailwind & shadcn/ui
├── backend/           # FastAPI app handling API endpoints & Celery tasks
├── scanner/           # Core Python security scanning engine
├── cli/               # TypeScript CLI tool
└── action/            # GitHub Action integration
```

---

## 🔑 Required APIs & Dependencies

Before running or deploying the platform, you need to set up the following free external services. Copy `.env.example` to `.env` in the root folder and fill in the values:

1. **Supabase (PostgreSQL Database)**
   - **Why?** Stores user accounts, scan history, and the public registry.
   - **Setup:** Create a free project at [Supabase](https://supabase.com).
   - **Env Vars needed:**
     - `SUPABASE_URL`
     - `SUPABASE_KEY` (The public/anon key)
     - `DATABASE_URL` (Found under Project Settings -> Database -> Connection string)
   - **Initialization:** Run the SQL script found in `backend/database/schema.sql` inside the Supabase SQL Editor to create your tables.

2. **Clerk (Authentication)**
   - **Why?** Manages secure user signups, logins, and session JWTs.
   - **Setup:** Create a free project at [Clerk](https://clerk.com).
   - **Env Vars needed:**
     - `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY`
     - `CLERK_SECRET_KEY`
     - `CLERK_JWKS_URL` (Usually `https://[your-clerk-frontend-api]/.well-known/jwks.json`)

3. **Anthropic (AI Analysis - *Optional but Recommended*)**
   - **Why?** Powers the advanced LLM-based tool poisoning detection. If omitted, the platform falls back to regex-based heuristic scanning without crashing.
   - **Setup:** Get an API key from [Anthropic Console](https://console.anthropic.com).
   - **Env Vars needed:**
     - `ANTHROPIC_API_KEY`

---

## 💻 How to Run Locally (Testing & Development)

The easiest way to run the entire platform locally is using Docker.

### Prerequisites
- Docker & Docker Compose installed on your machine.

### Steps
1. **Clone the repository:**
   ```bash
   git clone https://github.com/mudbbir23/MCPGuard.git
   cd MCPGuard
   ```

2. **Configure Environment:**
   Ensure your `.env` file is filled out as described above.

3. **Start the Infrastructure:**
   ```bash
   # Starts Postgres, Redis, Celery Worker, FastAPI backend, and Next.js frontend
   docker-compose up --build
   ```

4. **Access the Application:**
   - **Frontend UI:** [http://localhost:3000](http://localhost:3000)
   - **Backend API Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)

To stop the servers, press `Ctrl + C` in the terminal, or run `docker-compose down`.

---

## 🚀 How to Deploy to Production

When you are ready to put this on the live internet, we recommend a split deployment strategy (Vercel for Frontend, Render/Railway for Backend).

### 1. Deploy the Backend (FastAPI + Celery)
Standard serverless platforms (like Vercel) don't support long-running background tasks. You should use a platform like [Render](https://render.com/) or [Railway](https://railway.app/).

1. Connect your GitHub repository.
2. Create a **Web Service** pointing to the `backend` directory.
   - Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
3. Create a **Background Worker** pointing to the `backend` directory.
   - Start command: `celery -A tasks.scan_tasks worker --loglevel=info`
4. Create a **Redis instance** (both platforms offer simple Redis plugins/services).
5. Add all your backend environment variables (`DATABASE_URL`, `CELERY_BROKER_URL` pointing to your Redis instance, `ANTHROPIC_API_KEY`, etc.).

### 2. Deploy the Frontend (Next.js)
1. Go to [Vercel](https://vercel.com/) and import your GitHub repository.
2. Set the **Root Directory** to `frontend`.
3. Add your frontend environment variables:
   - `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY`
   - `NEXT_PUBLIC_API_URL` (Set this to the URL of the Backend Web Service you just deployed above, e.g., `https://mcpguard-api.onrender.com`).
4. Click **Deploy**.

---

## 🛠️ Developer Tooling

### Using the CLI

You can run scans directly from your terminal using the built-in TypeScript CLI.

```bash
cd cli
npm install
npx tsx src/index.ts scan https://github.com/modelcontextprotocol/server-filesystem
```

*Options:*
- `--api-url <url>`: Override the default API URL to point to your local or deployed backend.

### GitHub Action

Add MCPGuard to your CI/CD pipeline to block vulnerable MCP servers from being deployed or merged:

```yaml
steps:
  - uses: actions/checkout@v4
  - name: Run MCPGuard
    uses: mudbbir23/MCPGuard/action@main
    with:
      # Automatically fails the build if CRITICAL or HIGH vulnerabilities are found
      fail-on-critical: 'true'
      # Point to your deployed API
      api-url: 'https://mcpguard-api.onrender.com' 
```

---

## License

This project is licensed under the MIT License.
