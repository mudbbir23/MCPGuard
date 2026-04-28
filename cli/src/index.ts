#!/usr/bin/env node

import { Command } from "commander";
import { scanCommand } from "./commands/scan.js";
import { registryCommand } from "./commands/registry.js";

const program = new Command();

program
  .name("mcpguard")
  .description("Security scanner for Model Context Protocol (MCP) servers")
  .version("0.1.0");

program
  .command("scan")
  .description("Scan an MCP server for security vulnerabilities")
  .argument("<target>", "GitHub URL or npm package name")
  .option("-w, --wait", "Wait for the scan to complete and show results", true)
  .option("--api-url <url>", "Custom API URL", process.env.MCPGUARD_API_URL || "http://localhost:8000")
  .action(scanCommand);

program
  .command("registry")
  .description("Search the public MCP Security Registry")
  .argument("[query]", "Search query")
  .option("--api-url <url>", "Custom API URL", process.env.MCPGUARD_API_URL || "http://localhost:8000")
  .action(registryCommand);

program.parse();
