"use client";

import { useState } from "react";
import { Search, GitBranch, Package, ArrowRight, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { startScan, type TargetType } from "@/lib/api";

interface ScanInputProps {
  onScanStarted: (scanId: string) => void;
}

export function ScanInput({ onScanStarted }: ScanInputProps) {
  const [target, setTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const detectedType = detectTargetType(target);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!target.trim() || !detectedType) return;

    setLoading(true);
    setError("");

    try {
      const result = await startScan(target.trim(), detectedType);
      onScanStarted(result.scan_id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start scan");
    } finally {
      setLoading(false);
    }
  }

  function handleExample(url: string) {
    setTarget(url);
    setError("");
  }

  return (
    <div className="w-full max-w-2xl mx-auto">
      <form onSubmit={handleSubmit} className="relative">
        <div className="relative group">
          <div className="absolute -inset-0.5 bg-gradient-to-r from-red-500/20 via-orange-500/20 to-yellow-500/20 rounded-xl blur opacity-60 group-hover:opacity-100 transition duration-500" />
          <div className="relative flex items-center gap-2 bg-[#111111] border border-white/10 rounded-xl p-2">
            <div className="flex items-center pl-3">
              <Search className="w-5 h-5 text-white/40" />
            </div>
            <Input
              value={target}
              onChange={(e) => {
                setTarget(e.target.value);
                setError("");
              }}
              placeholder="Enter GitHub URL or npm package name..."
              className="flex-1 bg-transparent border-0 text-white placeholder:text-white/30 focus-visible:ring-0 focus-visible:ring-offset-0 text-base h-12"
            />
            <Button
              type="submit"
              disabled={loading || !detectedType}
              className="h-10 px-6 bg-white text-black font-semibold hover:bg-white/90 rounded-lg transition-all disabled:opacity-30"
            >
              {loading ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <>
                  Scan <ArrowRight className="w-4 h-4 ml-1" />
                </>
              )}
            </Button>
          </div>
        </div>
      </form>

      {/* Detection badge */}
      <div className="flex items-center justify-between mt-3 px-1">
        <div className="flex items-center gap-2">
          {target.trim() && detectedType && (
            <Badge
              variant="outline"
              className="text-xs border-white/10 text-white/60"
            >
              {detectedType === "github" ? (
                <>
                  <GitBranch className="w-3 h-3 mr-1" /> GitHub repo detected
                </>
              ) : (
                <>
                  <Package className="w-3 h-3 mr-1" /> npm package detected
                </>
              )}
            </Badge>
          )}
          {target.trim() && !detectedType && (
            <span className="text-xs text-red-400">
              Invalid URL format. Enter a GitHub URL or npm package name.
            </span>
          )}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="mt-3 px-4 py-2 bg-red-500/10 border border-red-500/20 rounded-lg">
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      {/* Examples */}
      <div className="mt-4 flex flex-wrap items-center gap-2 px-1">
        <span className="text-xs text-white/30">Try an example:</span>
        <button
          type="button"
          onClick={() =>
            handleExample("https://github.com/modelcontextprotocol/servers")
          }
          className="text-xs text-white/50 hover:text-white/80 underline underline-offset-2 transition-colors"
        >
          @modelcontextprotocol/servers
        </button>
        <span className="text-white/20">·</span>
        <button
          type="button"
          onClick={() =>
            handleExample("@modelcontextprotocol/server-filesystem")
          }
          className="text-xs text-white/50 hover:text-white/80 underline underline-offset-2 transition-colors"
        >
          @modelcontextprotocol/server-filesystem
        </button>
      </div>
    </div>
  );
}

function detectTargetType(input: string): TargetType | null {
  const trimmed = input.trim();
  if (!trimmed) return null;

  if (/^https?:\/\/github\.com\/[\w\-\.]+\/[\w\-\.]+\/?$/.test(trimmed)) {
    return "github";
  }
  if (/^@?[\w\-\.]+\/[\w\-\.]+$/.test(trimmed) && !trimmed.startsWith("http")) {
    return "npm";
  }
  if (/^[\w\-\.]+$/.test(trimmed) && !trimmed.startsWith("http")) {
    return "npm";
  }
  return null;
}
