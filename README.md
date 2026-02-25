# mcp-cve

Search the NVD for CVEs by keyword, severity, date range, or affected product.

## Tools

| Tool | Description |
|------|-------------|
| `search_cves` | Search CVEs by keyword. |
| `get_cve` | Get details for a specific CVE ID. |
| `recent_cves` | Get recently published CVEs. |
| `cves_by_severity` | Search CVEs by CVSS severity. |
| `cves_by_cpe` | Search CVEs affecting a specific product (CPE). |

## Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `NVD_API_KEY` | Yes | NVD API key (optional, increases rate limit) |

## Installation

```bash
git clone https://github.com/PetrefiedThunder/mcp-cve.git
cd mcp-cve
npm install
npm run build
```

## Usage with Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cve": {
      "command": "node",
      "args": ["/path/to/mcp-cve/dist/index.js"],
      "env": {
        "NVD_API_KEY": "your-nvd-api-key"
      }
    }
  }
}
```

## Usage with npx

```bash
npx mcp-cve
```

## License

MIT
