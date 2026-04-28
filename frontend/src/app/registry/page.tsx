"use client";

import { useEffect, useState } from "react";
import { Plus, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { RegistryTable } from "@/components/RegistryTable";
import { listRegistryServers, type RegistryServer } from "@/lib/api";

export default function RegistryPage() {
  const [servers, setServers] = useState<RegistryServer[]>([]);
  const [loading, setLoading] = useState(true);
  
  // Filters
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState<string>("all");
  const [sort, setSort] = useState("updated_at");

  useEffect(() => {
    async function load() {
      setLoading(true);
      try {
        const data = await listRegistryServers({
          search: search || undefined,
          category: category !== "all" ? category : undefined,
          sort,
        });
        setServers(data.servers);
      } catch (err) {
        console.error("Failed to load registry servers:", err);
      } finally {
        setLoading(false);
      }
    }
    
    // Add small debounce for search
    const timer = setTimeout(load, 300);
    return () => clearTimeout(timer);
  }, [search, category, sort]);

  return (
    <main className="flex-1 container mx-auto px-4 py-12 max-w-5xl">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8">
        <div>
          <h1 className="text-3xl font-bold tracking-tight mb-2 flex items-center gap-3">
            <ShieldCheck className="w-8 h-8 text-blue-400" />
            MCP Security Registry
          </h1>
          <p className="text-white/50">
            Browse verified community MCP servers and their security scores.
          </p>
        </div>
        
        <Button className="bg-white text-black hover:bg-white/90 font-medium">
          <Plus className="w-4 h-4 mr-2" />
          Submit Server
        </Button>
      </div>

      <div className={loading ? "opacity-50 pointer-events-none transition-opacity" : "transition-opacity"}>
        <RegistryTable 
          servers={servers} 
          onSearch={setSearch}
          onCategoryFilter={setCategory}
          onSort={setSort}
        />
      </div>
    </main>
  );
}
