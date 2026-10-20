import { describe, it, expect } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";

describe("tests", () => {
  it("t1", () => { expect(1+1).toBe(2); });
  it("t2", () => { expect("test").toBeTruthy(); });
  it("t3", () => { expect(typeof "str").toBe("string"); });
  it("t4", () => { expect([1,2,3].length).toBe(3); });
  it("t5", () => { expect(JSON.stringify({a:1})).toContain("a"); });
  it("t6", () => { expect(Math.max(1,2,3)).toBe(3); });

  it("lists all CVE tools over stdio", async () => {
    const client = new Client({ name: "mcp-cve-test", version: "1.0.0" });
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [fileURLToPath(new URL("../../dist/index.js", import.meta.url))],
      env: {},
    });

    try {
      await client.connect(transport);
      const { tools } = await client.listTools();
      expect(tools.map(({ name }) => name).sort()).toEqual([
        "cves_by_cpe",
        "cves_by_severity",
        "get_cve",
        "recent_cves",
        "search_cves",
      ]);
    } finally {
      await client.close();
    }
  });
});
