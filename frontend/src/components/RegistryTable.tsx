"use client";

import { useState } from "react";
import { formatDistanceToNow } from "date-fns";
import { 
  ShieldAlert, 
  Shield, 
  ShieldCheck, 
  Search, 
  ExternalLink,
  ChevronDown
} from "lucide-react";

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { RegistryServer, ServerCategory } from "@/lib/api";

interface RegistryTableProps {
  servers: RegistryServer[];
  onSearch: (q: string) => void;
  onCategoryFilter: (c: string) => void;
  onSort: (s: string) => void;
}

const SCORE_CONFIG = {
  CRITICAL: { icon: ShieldAlert, color: "text-red-500", badge: "border-red-500/30 text-red-400 bg-red-500/10" },
  HIGH: { icon: ShieldAlert, color: "text-orange-500", badge: "border-orange-500/30 text-orange-400 bg-orange-500/10" },
  MEDIUM: { icon: Shield, color: "text-yellow-500", badge: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" },
  LOW: { icon: Shield, color: "text-blue-500", badge: "border-blue-500/30 text-blue-400 bg-blue-500/10" },
  SAFE: { icon: ShieldCheck, color: "text-green-500", badge: "border-green-500/30 text-green-400 bg-green-500/10" },
};

export function RegistryTable({ servers, onSearch, onCategoryFilter, onSort }: RegistryTableProps) {
  const [searchTerm, setSearchTerm] = useState("");

  function handleSearchSubmit(e: React.FormEvent) {
    e.preventDefault();
    onSearch(searchTerm);
  }

  return (
    <div className="w-full">
      {/* Filters */}
      <div className="flex flex-col sm:flex-row items-center gap-4 mb-6">
        <form onSubmit={handleSearchSubmit} className="relative flex-1 w-full">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-white/40" />
          <Input 
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search servers..." 
            className="pl-9 bg-[#111] border-white/10 w-full"
          />
        </form>
        
        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Select onValueChange={onCategoryFilter} defaultValue="all">
            <SelectTrigger className="w-[150px] bg-[#111] border-white/10">
              <SelectValue placeholder="Category" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Categories</SelectItem>
              <SelectItem value="filesystem">Filesystem</SelectItem>
              <SelectItem value="communication">Communication</SelectItem>
              <SelectItem value="development">Development</SelectItem>
              <SelectItem value="database">Database</SelectItem>
              <SelectItem value="other">Other</SelectItem>
            </SelectContent>
          </Select>

          <Select onValueChange={onSort} defaultValue="updated_at">
            <SelectTrigger className="w-[150px] bg-[#111] border-white/10">
              <SelectValue placeholder="Sort by" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="updated_at">Recently Updated</SelectItem>
              <SelectItem value="latest_score">Security Score</SelectItem>
              <SelectItem value="name">Name</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      {/* Table */}
      <div className="rounded-xl border border-white/10 bg-[#111] overflow-hidden">
        <Table>
          <TableHeader className="bg-white/[0.02]">
            <TableRow className="border-white/10 hover:bg-transparent">
              <TableHead className="text-white/60 font-medium">Server</TableHead>
              <TableHead className="text-white/60 font-medium">Category</TableHead>
              <TableHead className="text-white/60 font-medium">Security Score</TableHead>
              <TableHead className="text-white/60 font-medium">Last Scanned</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {servers.length === 0 ? (
              <TableRow className="border-white/10">
                <TableCell colSpan={4} className="h-32 text-center text-white/40">
                  No servers found matching your criteria.
                </TableCell>
              </TableRow>
            ) : (
              servers.map((server) => {
                const config = SCORE_CONFIG[server.latest_score || "SAFE"] || SCORE_CONFIG.SAFE;
                const Icon = config.icon;

                return (
                  <TableRow key={server.id} className="border-white/10 hover:bg-white/[0.02] group">
                    <TableCell>
                      <div className="font-medium text-white/90">{server.name}</div>
                      <a 
                        href={server.github_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs font-mono text-white/40 hover:text-blue-400 flex items-center mt-1"
                      >
                        {server.github_url.replace("https://github.com/", "")}
                        <ExternalLink className="w-3 h-3 ml-1 opacity-0 group-hover:opacity-100 transition-opacity" />
                      </a>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-xs bg-white/5 border-white/10 text-white/60 capitalize">
                        {server.category}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {server.latest_score ? (
                        <Badge variant="outline" className={`text-xs flex items-center w-fit gap-1.5 ${config.badge}`}>
                          <Icon className="w-3.5 h-3.5" />
                          {server.latest_score}
                        </Badge>
                      ) : (
                        <span className="text-xs text-white/30">Unscanned</span>
                      )}
                    </TableCell>
                    <TableCell className="text-sm text-white/50">
                      {server.updated_at ? formatDistanceToNow(new Date(server.updated_at), { addSuffix: true }) : "Never"}
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
