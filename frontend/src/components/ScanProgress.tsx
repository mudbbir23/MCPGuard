"use client";

import { useEffect, useState } from "react";
import { Shield, Loader2 } from "lucide-react";
import { Progress } from "@/components/ui/progress";

interface ScanProgressProps {
  progress: string | null;
  status: "pending" | "running";
}

const SCAN_LAYERS = [
  { name: "Preparing scan environment", duration: 3 },
  { name: "Running dependency audit", duration: 10 },
  { name: "Running static analysis", duration: 12 },
  { name: "Analyzing tool descriptions", duration: 15 },
  { name: "Auditing permissions", duration: 8 },
  { name: "Building report", duration: 2 },
];

export function ScanProgress({ progress, status }: ScanProgressProps) {
  const [elapsed, setElapsed] = useState(0);
  const [progressValue, setProgressValue] = useState(0);

  const totalDuration = SCAN_LAYERS.reduce((sum, l) => sum + l.duration, 0);
  const currentLayer =
    progress || (status === "pending" ? "Queued..." : "Initializing...");

  useEffect(() => {
    const interval = setInterval(() => {
      setElapsed((prev) => prev + 1);
      setProgressValue((prev) => Math.min(prev + 100 / totalDuration, 95));
    }, 1000);
    return () => clearInterval(interval);
  }, [totalDuration]);

  const remaining = Math.max(0, totalDuration - elapsed);

  return (
    <div className="w-full max-w-2xl mx-auto">
      <div className="bg-[#111111] border border-white/10 rounded-xl p-8">
        {/* Animated shield icon */}
        <div className="flex justify-center mb-6">
          <div className="relative">
            <div className="absolute inset-0 bg-blue-500/20 rounded-full blur-xl animate-pulse" />
            <div className="relative w-16 h-16 bg-[#1a1a1a] rounded-full flex items-center justify-center border border-white/10">
              <Shield className="w-8 h-8 text-blue-400 animate-pulse" />
            </div>
          </div>
        </div>

        {/* Current layer */}
        <p className="text-center text-white font-medium mb-2">
          {currentLayer}
        </p>

        {/* Progress bar */}
        <div className="mb-4">
          <Progress
            value={progressValue}
            className="h-2 bg-white/5 [&>div]:bg-gradient-to-r [&>div]:from-blue-500 [&>div]:to-cyan-400"
          />
        </div>

        {/* Time info */}
        <div className="flex justify-between text-xs text-white/40">
          <span>Elapsed: {elapsed}s</span>
          <span>
            {remaining > 0 ? `~${remaining}s remaining` : "Finalizing..."}
          </span>
        </div>

        {/* Scan layers checklist */}
        <div className="mt-6 space-y-2">
          {SCAN_LAYERS.map((layer, i) => {
            const layerProgress = progress?.toLowerCase() || "";
            const layerName = layer.name.toLowerCase();
            const isActive = layerProgress.includes(
              layerName.split(" ").slice(0, 2).join(" "),
            );
            const isDone =
              SCAN_LAYERS.findIndex((l) =>
                layerProgress.includes(
                  l.name.toLowerCase().split(" ").slice(0, 2).join(" "),
                ),
              ) > i;

            return (
              <div
                key={i}
                className={`flex items-center gap-3 text-sm transition-all duration-300 ${
                  isDone
                    ? "text-green-400"
                    : isActive
                      ? "text-white"
                      : "text-white/20"
                }`}
              >
                <div
                  className={`w-5 h-5 rounded-full flex items-center justify-center text-xs border ${
                    isDone
                      ? "bg-green-500/20 border-green-500/50 text-green-400"
                      : isActive
                        ? "bg-blue-500/20 border-blue-500/50 text-blue-400"
                        : "border-white/10"
                  }`}
                >
                  {isDone ? (
                    "✓"
                  ) : isActive ? (
                    <Loader2 className="w-3 h-3 animate-spin" />
                  ) : (
                    i + 1
                  )}
                </div>
                <span className={isActive ? "font-medium" : ""}>
                  {layer.name}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
