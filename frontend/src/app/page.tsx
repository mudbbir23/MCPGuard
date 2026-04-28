"use client";

import { useRouter } from "next/navigation";
import { ScanInput } from "@/components/ScanInput";
import { Shield, Zap, Lock, Terminal } from "lucide-react";

export default function Home() {
  const router = useRouter();

  function handleScanStarted(scanId: string) {
    router.push(`/scan/${scanId}`);
  }

  return (
    <main className="flex-1 flex flex-col items-center pt-24 pb-16 px-4">
      {/* Hero Section */}
      <div className="text-center max-w-3xl mx-auto mb-16 relative">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-64 h-64 bg-blue-500/20 blur-[100px] rounded-full pointer-events-none" />
        
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/5 border border-white/10 text-sm text-white/80 mb-6">
          <Shield className="w-4 h-4 text-blue-400" />
          Securing the Model Context Protocol ecosystem
        </div>
        
        <h1 className="text-5xl sm:text-6xl font-extrabold tracking-tight mb-6 bg-gradient-to-br from-white to-white/50 bg-clip-text text-transparent">
          Scan your MCP servers for vulnerabilities
        </h1>
        
        <p className="text-lg text-white/60 mb-10 max-w-2xl mx-auto">
          Detect tool poisoning, vulnerable dependencies, excessive permissions, and hidden unicode payloads before you give AI access to your system.
        </p>

        <ScanInput onScanStarted={handleScanStarted} />
      </div>

      {/* Features */}
      <div className="grid sm:grid-cols-3 gap-6 max-w-5xl mx-auto mt-12">
        {[
          {
            icon: Shield,
            title: "Tool Poisoning Detection",
            description: "Identifies hidden instructions and semantic manipulation in tool descriptions that could trick an LLM.",
          },
          {
            icon: Lock,
            title: "Dependency & AST Audit",
            description: "Checks for typosquatting, old packages, and analyzes Python/JS ASTs for dangerous patterns like shell injection.",
          },
          {
            icon: Zap,
            title: "Instant Public Registry",
            description: "Browse the community registry to find safe, highly-rated MCP servers or submit your own for automated review.",
          },
        ].map((feature, i) => (
          <div key={i} className="p-6 rounded-2xl bg-white/[0.02] border border-white/5 hover:bg-white/[0.04] transition-colors">
            <div className="w-10 h-10 rounded-lg bg-white/5 flex items-center justify-center mb-4 border border-white/10">
              <feature.icon className="w-5 h-5 text-blue-400" />
            </div>
            <h3 className="text-lg font-semibold mb-2">{feature.title}</h3>
            <p className="text-sm text-white/50 leading-relaxed">
              {feature.description}
            </p>
          </div>
        ))}
      </div>

      {/* CLI CTA */}
      <div className="mt-24 max-w-2xl mx-auto w-full text-center">
        <h3 className="text-xl font-bold mb-4">Run locally with our CLI</h3>
        <div className="bg-black border border-white/10 rounded-xl p-4 flex items-center justify-between group">
          <div className="flex items-center gap-3 text-white/70 font-mono text-sm">
            <Terminal className="w-4 h-4 text-white/40" />
            <span>npx mcpguard scan ./my-server</span>
          </div>
          <button 
            onClick={() => navigator.clipboard.writeText("npx mcpguard scan ./my-server")}
            className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-xs font-medium transition-colors"
          >
            Copy
          </button>
        </div>
      </div>
    </main>
  );
}
