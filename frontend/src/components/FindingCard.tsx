"use client";

import { Badge } from "@/components/ui/badge";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { ChevronDown, FileCode, ExternalLink } from "lucide-react";

interface FindingData {
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

interface FindingCardProps {
  finding: FindingData;
  githubUrl?: string;
}

const SEVERITY_CONFIG = {
  CRITICAL: {
    color: "bg-red-500/10 text-red-400 border-red-500/20",
    dot: "bg-red-500",
    badge: "border-red-500/30 text-red-400",
  },
  HIGH: {
    color: "bg-orange-500/10 text-orange-400 border-orange-500/20",
    dot: "bg-orange-500",
    badge: "border-orange-500/30 text-orange-400",
  },
  MEDIUM: {
    color: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
    dot: "bg-yellow-500",
    badge: "border-yellow-500/30 text-yellow-400",
  },
  LOW: {
    color: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    dot: "bg-blue-500",
    badge: "border-blue-500/30 text-blue-400",
  },
  INFO: {
    color: "bg-gray-500/10 text-gray-400 border-gray-500/20",
    dot: "bg-gray-500",
    badge: "border-gray-500/30 text-gray-400",
  },
};

export function FindingCard({ finding, githubUrl }: FindingCardProps) {
  const config = SEVERITY_CONFIG[finding.severity] || SEVERITY_CONFIG.INFO;

  const fileLink =
    githubUrl && finding.file_path
      ? `${githubUrl}/blob/main/${finding.file_path}${finding.line_number ? `#L${finding.line_number}` : ""}`
      : null;

  return (
    <Collapsible>
      <CollapsibleTrigger className="w-full group">
        <div
          className={`flex items-start gap-3 p-4 rounded-lg border transition-all hover:bg-white/[0.02] ${config.color}`}
        >
          <div className={`w-2 h-2 rounded-full mt-2 ${config.dot}`} />
          <div className="flex-1 text-left">
            <div className="flex items-center gap-2 mb-1">
              <Badge
                variant="outline"
                className={`text-[10px] font-mono ${config.badge}`}
              >
                {finding.severity}
              </Badge>
              {finding.cwe_id && (
                <a
                  href={`https://cwe.mitre.org/data/definitions/${finding.cwe_id.replace("CWE-", "")}.html`}
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={(e) => e.stopPropagation()}
                  className="text-[10px] font-mono text-white/30 hover:text-white/60 transition-colors"
                >
                  {finding.cwe_id} ↗
                </a>
              )}
            </div>
            <p className="text-sm font-medium text-white/90">
              {finding.title}
            </p>
            {finding.file_path && (
              <div className="flex items-center gap-1 mt-1">
                <FileCode className="w-3 h-3 text-white/30" />
                {fileLink ? (
                  <a
                    href={fileLink}
                    target="_blank"
                    rel="noopener noreferrer"
                    onClick={(e) => e.stopPropagation()}
                    className="text-xs font-mono text-white/40 hover:text-blue-400 transition-colors"
                  >
                    {finding.file_path}
                    {finding.line_number ? `:${finding.line_number}` : ""}
                    <ExternalLink className="w-2.5 h-2.5 inline ml-1" />
                  </a>
                ) : (
                  <span className="text-xs font-mono text-white/40">
                    {finding.file_path}
                    {finding.line_number ? `:${finding.line_number}` : ""}
                  </span>
                )}
              </div>
            )}
          </div>
          <ChevronDown className="w-4 h-4 text-white/30 group-data-[state=open]:rotate-180 transition-transform mt-1" />
        </div>
      </CollapsibleTrigger>

      <CollapsibleContent>
        <div className="ml-5 pl-4 border-l border-white/5 py-3 space-y-3">
          <p className="text-sm text-white/60 leading-relaxed">
            {finding.description}
          </p>
          {finding.remediation && (
            <div className="bg-green-500/5 border border-green-500/10 rounded-lg p-3">
              <p className="text-xs font-semibold text-green-400 mb-1">
                💡 Remediation
              </p>
              <p className="text-sm text-green-300/80">
                {finding.remediation}
              </p>
            </div>
          )}
        </div>
      </CollapsibleContent>
    </Collapsible>
  );
}
