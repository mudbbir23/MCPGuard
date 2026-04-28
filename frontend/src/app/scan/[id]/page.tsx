"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { ArrowLeft, AlertCircle } from "lucide-react";
import Link from "next/link";

import { getScan, type ScanResponse } from "@/lib/api";
import { ScanProgress } from "@/components/ScanProgress";
import { ScanReport } from "@/components/ScanReport";
import { Button } from "@/components/ui/button";

export default function ScanPage() {
  const params = useParams();
  const router = useRouter();
  const scanId = params.id as string;

  const [scan, setScan] = useState<ScanResponse | null>(null);
  const [error, setError] = useState<string>("");

  useEffect(() => {
    if (!scanId) return;

    let mounted = true;
    let pollInterval: NodeJS.Timeout;

    async function fetchScan() {
      try {
        const data = await getScan(scanId);
        if (mounted) {
          setScan(data);
          
          // Stop polling if complete or failed
          if (data.status === "complete" || data.status === "failed") {
            clearInterval(pollInterval);
          }
        }
      } catch (err) {
        if (mounted) {
          setError(err instanceof Error ? err.message : "Failed to fetch scan");
          clearInterval(pollInterval);
        }
      }
    }

    // Initial fetch
    fetchScan();

    // Poll every 2 seconds
    pollInterval = setInterval(fetchScan, 2000);

    return () => {
      mounted = false;
      clearInterval(pollInterval);
    };
  }, [scanId]);

  if (error) {
    return (
      <main className="flex-1 container mx-auto px-4 py-12 max-w-3xl">
        <Button variant="ghost" onClick={() => router.back()} className="mb-8">
          <ArrowLeft className="w-4 h-4 mr-2" /> Back
        </Button>
        <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-6 text-center">
          <AlertCircle className="w-8 h-8 text-red-500 mx-auto mb-3" />
          <h2 className="text-lg font-semibold text-red-400 mb-1">Error Loading Scan</h2>
          <p className="text-red-300/80">{error}</p>
        </div>
      </main>
    );
  }

  if (!scan) {
    return (
      <main className="flex-1 container mx-auto px-4 py-12 max-w-3xl flex justify-center">
        <div className="animate-pulse flex flex-col items-center gap-4">
          <div className="w-12 h-12 rounded-full border-2 border-white/20 border-t-white animate-spin" />
          <p className="text-white/50">Loading scan details...</p>
        </div>
      </main>
    );
  }

  return (
    <main className="flex-1 container mx-auto px-4 py-12 max-w-4xl">
      <div className="mb-8">
        <Link 
          href="/"
          className="inline-flex items-center text-sm font-medium text-white/50 hover:text-white transition-colors"
        >
          <ArrowLeft className="w-4 h-4 mr-1" /> New Scan
        </Link>
      </div>

      {(scan.status === "pending" || scan.status === "running") && (
        <div className="py-12">
          <ScanProgress progress={scan.progress} status={scan.status} />
        </div>
      )}

      {scan.status === "complete" && (
        <ScanReport scan={scan} />
      )}

      {scan.status === "failed" && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-8 text-center max-w-2xl mx-auto">
          <AlertCircle className="w-12 h-12 text-red-500 mx-auto mb-4" />
          <h2 className="text-xl font-bold text-red-400 mb-2">Scan Failed</h2>
          <p className="text-red-300/80 mb-6">{scan.error_message || "An unknown error occurred during the scan."}</p>
          <Button onClick={() => window.location.reload()} variant="outline" className="border-white/10">
            Try Again
          </Button>
        </div>
      )}
    </main>
  );
}
