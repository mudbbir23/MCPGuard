/**
 * MCPGuard API Client
 * Typed API client with retry logic for the FastAPI backend.
 */

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

// ─── Types ──────────────────────────────────────────────────

export type TargetType = "github" | "npm" | "local";
export type ScanStatus = "pending" | "running" | "complete" | "failed";
export type SeverityScore = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SAFE";
export type ServerCategory = "filesystem" | "communication" | "development" | "database" | "other";

export interface ScanStartResponse {
  scan_id: string;
  status: ScanStatus;
  estimated_seconds: number;
}

export interface Finding {
  id: string;
  category: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  title: string;
  description: string;
  file_path: string | null;
  line_number: number | null;
  remediation: string;
  cwe_id: string | null;
}

export interface ScanResult {
  version: string;
  generated_at: string;
  target: { url: string; type: string };
  overall_score: SeverityScore;
  severity_counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  total_findings: number;
  scan_duration_ms: number | null;
  categories: Record<string, { count: number; findings: Finding[] }>;
}

export interface ScanResponse {
  id: string;
  created_at: string;
  user_id: string | null;
  target_url: string;
  target_type: TargetType;
  status: ScanStatus;
  overall_score: SeverityScore | null;
  result_json: ScanResult | null;
  scan_duration_ms: number | null;
  error_message: string | null;
  progress: string | null;
}

export interface RegistryServer {
  id: string;
  name: string;
  description: string;
  github_url: string;
  npm_package: string | null;
  language: string;
  category: ServerCategory;
  latest_score: SeverityScore | null;
  latest_scan_id: string | null;
  scan_count: number;
  created_at: string;
  updated_at: string;
}

// ─── Fetch Wrapper with Retry ───────────────────────────────

async function fetchWithRetry(
  url: string,
  options: RequestInit = {},
  retries = 3,
  backoff = 1000,
): Promise<Response> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, {
        ...options,
        headers: {
          "Content-Type": "application/json",
          ...options.headers,
        },
      });
      if (res.ok || res.status < 500) return res;
      if (attempt < retries) {
        await new Promise((r) => setTimeout(r, backoff * Math.pow(2, attempt)));
      }
    } catch (err) {
      if (attempt === retries) throw err;
      await new Promise((r) => setTimeout(r, backoff * Math.pow(2, attempt)));
    }
  }
  throw new Error("Max retries exceeded");
}

// ─── API Functions ──────────────────────────────────────────

export async function startScan(
  targetUrl: string,
  targetType: TargetType,
): Promise<ScanStartResponse> {
  const res = await fetchWithRetry(`${API_URL}/scans`, {
    method: "POST",
    body: JSON.stringify({ target_url: targetUrl, target_type: targetType }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err?.error?.message || "Failed to start scan");
  }
  return res.json();
}

export async function getScan(scanId: string): Promise<ScanResponse> {
  const res = await fetchWithRetry(`${API_URL}/scans/${scanId}`);
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err?.error?.message || "Failed to get scan");
  }
  return res.json();
}

export async function listScans(
  page = 1,
  limit = 20,
): Promise<{ scans: ScanResponse[]; total: number }> {
  const res = await fetchWithRetry(
    `${API_URL}/scans?page=${page}&limit=${limit}`,
  );
  if (!res.ok) throw new Error("Failed to list scans");
  return res.json();
}

export async function listRegistryServers(params: {
  page?: number;
  limit?: number;
  category?: string;
  search?: string;
  sort?: string;
} = {}): Promise<{ servers: RegistryServer[]; total: number }> {
  const searchParams = new URLSearchParams();
  if (params.page) searchParams.set("page", String(params.page));
  if (params.limit) searchParams.set("limit", String(params.limit));
  if (params.category) searchParams.set("category", params.category);
  if (params.search) searchParams.set("search", params.search);
  if (params.sort) searchParams.set("sort", params.sort);

  const res = await fetchWithRetry(
    `${API_URL}/registry?${searchParams.toString()}`,
  );
  if (!res.ok) throw new Error("Failed to list servers");
  return res.json();
}

export async function getRegistryServer(
  serverId: string,
): Promise<RegistryServer> {
  const res = await fetchWithRetry(`${API_URL}/registry/${serverId}`);
  if (!res.ok) throw new Error("Server not found");
  return res.json();
}

export async function submitServer(body: {
  github_url: string;
  npm_package?: string;
  category?: string;
  email?: string;
}): Promise<ScanStartResponse> {
  const res = await fetchWithRetry(`${API_URL}/registry/submit`, {
    method: "POST",
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err?.error?.message || "Failed to submit server");
  }
  return res.json();
}
