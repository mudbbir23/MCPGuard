"use client";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { FindingCard } from "@/components/FindingCard";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Download,
  Share2,
  Clock,
} from "lucide-react";
import type { ScanResponse } from "@/lib/api";

interface ScanReportProps {
  scan: ScanResponse;
}

const SCORE_CONFIG = {
  CRITICAL: {
    icon: ShieldAlert,
    color: "text-red-500",
    bg: "bg-red-500/10",
    border: "border-red-500/30",
    label: "CRITICAL",
    grade: "F",
  },
  HIGH: {
    icon: ShieldAlert,
    color: "text-orange-500",
    bg: "bg-orange-500/10",
    border: "border-orange-500/30",
    label: "HIGH RISK",
    grade: "D",
  },
  MEDIUM: {
    icon: Shield,
    color: "text-yellow-500",
    bg: "bg-yellow-500/10",
    border: "border-yellow-500/30",
    label: "MEDIUM",
    grade: "C",
  },
  LOW: {
    icon: Shield,
    color: "text-blue-500",
    bg: "bg-blue-500/10",
    border: "border-blue-500/30",
    label: "LOW RISK",
    grade: "B",
  },
  SAFE: {
    icon: ShieldCheck,
    color: "text-green-500",
    bg: "bg-green-500/10",
    border: "border-green-500/30",
    label: "SAFE",
    grade: "A",
  },
};

export function ScanReport({ scan }: ScanReportProps) {
  const result = scan.result_json;
  if (!result) return null;

  const score = scan.overall_score || "SAFE";
  const config = SCORE_CONFIG[score] || SCORE_CONFIG.SAFE;
  const ScoreIcon = config.icon;
  const counts = result.severity_counts;

  function handleDownload() {
    const blob = new Blob([JSON.stringify(result, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `mcpguard-report-${scan.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function handleShare() {
    const url = `${window.location.origin}/scan/${scan.id}`;
    navigator.clipboard.writeText(url);
  }

  // Collect all findings
  const allFindings = Object.values(result.categories || {}).flatMap(
    (cat) => cat.findings || [],
  );

  return (
    <div className="w-full max-w-3xl mx-auto">
      {/* Score Header */}
      <div
        className={`${config.bg} border ${config.border} rounded-xl p-6 mb-6`}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div
              className={`w-16 h-16 rounded-xl ${config.bg} flex items-center justify-center`}
            >
              <span className={`text-3xl font-bold font-mono ${config.color}`}>
                {config.grade}
              </span>
            </div>
            <div>
              <div className="flex items-center gap-2 mb-1">
                <ScoreIcon className={`w-5 h-5 ${config.color}`} />
                <span className={`text-lg font-bold ${config.color}`}>
                  {config.label}
                </span>
              </div>
              <p className="text-sm text-white/50">{scan.target_url}</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={handleShare}
              className="border-white/10 text-white/60 hover:text-white bg-transparent"
            >
              <Share2 className="w-3.5 h-3.5 mr-1.5" /> Share
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleDownload}
              className="border-white/10 text-white/60 hover:text-white bg-transparent"
            >
              <Download className="w-3.5 h-3.5 mr-1.5" /> Download
            </Button>
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-5 gap-3 mt-5">
          {[
            {
              label: "Critical",
              count: counts.critical,
              color: "text-red-400",
            },
            { label: "High", count: counts.high, color: "text-orange-400" },
            { label: "Medium", count: counts.medium, color: "text-yellow-400" },
            { label: "Low", count: counts.low, color: "text-blue-400" },
            { label: "Info", count: counts.info, color: "text-gray-400" },
          ].map((stat) => (
            <div
              key={stat.label}
              className="text-center bg-black/20 rounded-lg py-2"
            >
              <p className={`text-xl font-bold font-mono ${stat.color}`}>
                {stat.count}
              </p>
              <p className="text-xs text-white/40">{stat.label}</p>
            </div>
          ))}
        </div>

        {/* Scan duration */}
        {scan.scan_duration_ms && (
          <div className="flex items-center gap-1 mt-3 text-xs text-white/30">
            <Clock className="w-3 h-3" />
            <span>
              Scanned in {(scan.scan_duration_ms / 1000).toFixed(1)}s
            </span>
          </div>
        )}
      </div>

      {/* Findings */}
      {allFindings.length > 0 ? (
        <div className="space-y-2">
          <h3 className="text-sm font-semibold text-white/60 uppercase tracking-wider mb-3">
            Findings ({allFindings.length})
          </h3>
          {allFindings.map((finding) => (
            <FindingCard
              key={finding.id}
              finding={finding}
              githubUrl={
                scan.target_type === "github" ? scan.target_url : undefined
              }
            />
          ))}
        </div>
      ) : (
        <div className="text-center py-12 text-white/30">
          <ShieldCheck className="w-12 h-12 mx-auto mb-3 text-green-500/50" />
          <p className="text-lg">No security issues found</p>
          <p className="text-sm mt-1">This MCP server looks clean!</p>
        </div>
      )}
    </div>
  );
}
