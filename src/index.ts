#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const RATE_LIMIT_MS = 6500; // NVD: 5 req/30s without API key
let last = 0;

async function nvdFetch(params: URLSearchParams): Promise<any> {
  const now = Date.now(); if (now - last < RATE_LIMIT_MS) await new Promise((r) => setTimeout(r, RATE_LIMIT_MS - (now - last)));
  last = Date.now();
  const headers: Record<string, string> = {};
  if (process.env.NVD_API_KEY) headers.apiKey = process.env.NVD_API_KEY;
  const res = await fetch(`${NVD}?${params}`, { headers });
  if (!res.ok) throw new Error(`NVD ${res.status}`);
  return res.json();
}

function mapCve(v: any) {
  const cve = v.cve;
  const desc = cve.descriptions?.find((d: any) => d.lang === "en")?.value;
  const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV2?.[0];
  return {
    id: cve.id, published: cve.published, lastModified: cve.lastModified,
    description: desc?.slice(0, 500), severity: metrics?.cvssData?.baseSeverity,
    score: metrics?.cvssData?.baseScore, vector: metrics?.cvssData?.vectorString,
    references: cve.references?.slice(0, 3).map((r: any) => r.url),
  };
}

const server = new McpServer({ name: "mcp-cve", version: "1.0.0" });

server.tool("search_cves", "Search CVEs by keyword.", {
  keyword: z.string(), resultsPerPage: z.number().min(1).max(50).default(10),
}, async ({ keyword, resultsPerPage }) => {
  const p = new URLSearchParams({ keywordSearch: keyword, resultsPerPage: String(resultsPerPage) });
  const d = await nvdFetch(p);
  return { content: [{ type: "text" as const, text: JSON.stringify({ total: d.totalResults, cves: d.vulnerabilities?.map(mapCve) }, null, 2) }] };
});

server.tool("get_cve", "Get details for a specific CVE ID.", {
  cveId: z.string().describe("CVE ID (e.g. 'CVE-2024-1234')"),
}, async ({ cveId }) => {
  const d = await nvdFetch(new URLSearchParams({ cveId }));
  const cve = d.vulnerabilities?.[0];
  return { content: [{ type: "text" as const, text: JSON.stringify(cve ? mapCve(cve) : { error: "Not found" }, null, 2) }] };
});

server.tool("recent_cves", "Get recently published CVEs.", {
  pubStartDate: z.string().describe("Start date (ISO, e.g. '2025-02-01T00:00:00.000')"),
  pubEndDate: z.string().describe("End date"),
  resultsPerPage: z.number().min(1).max(50).default(20),
}, async ({ pubStartDate, pubEndDate, resultsPerPage }) => {
  const p = new URLSearchParams({ pubStartDate, pubEndDate, resultsPerPage: String(resultsPerPage) });
  const d = await nvdFetch(p);
  return { content: [{ type: "text" as const, text: JSON.stringify({ total: d.totalResults, cves: d.vulnerabilities?.map(mapCve) }, null, 2) }] };
});

server.tool("cves_by_severity", "Search CVEs by CVSS severity.", {
  cvssV3Severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
  resultsPerPage: z.number().min(1).max(50).default(10),
}, async ({ cvssV3Severity, resultsPerPage }) => {
  const p = new URLSearchParams({ cvssV3Severity, resultsPerPage: String(resultsPerPage) });
  const d = await nvdFetch(p);
  return { content: [{ type: "text" as const, text: JSON.stringify({ total: d.totalResults, cves: d.vulnerabilities?.map(mapCve) }, null, 2) }] };
});

server.tool("cves_by_cpe", "Search CVEs affecting a specific product (CPE).", {
  cpeName: z.string().describe("CPE 2.3 name (e.g. 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*')"),
  resultsPerPage: z.number().min(1).max(50).default(10),
}, async ({ cpeName, resultsPerPage }) => {
  const p = new URLSearchParams({ cpeName, resultsPerPage: String(resultsPerPage) });
  const d = await nvdFetch(p);
  return { content: [{ type: "text" as const, text: JSON.stringify({ total: d.totalResults, cves: d.vulnerabilities?.map(mapCve) }, null, 2) }] };
});

async function main() { const t = new StdioServerTransport(); await server.connect(t); }
main().catch((e) => { console.error("Fatal:", e); process.exit(1); });
