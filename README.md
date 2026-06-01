# MCP Threat Intelligence

MCP Threat Intelligence is a stateless Cloudflare Workers Model Context Protocol server that gives an investigator's AI agent reusable tools for enriching and correlating indicators across VirusTotal, urlscan.io, and Censys. The point is not a single lookup; it is to let the agent gather evidence, pivot from domains to IPs and infrastructure fingerprints, and return a normalized investigation summary with a verdict, confidence, and evidence chain.

## Why an MCP server instead of querying these APIs directly

An MCP server lets the AI agent orchestrate multi-source correlation autonomously instead of forcing every investigator or prompt to know three vendor APIs. It is reusable across investigators and agents, and it centralizes authentication, rate-limit handling, optional caching, and audit logging so source API keys and quota policies stay in one controlled Worker.

## Architecture

This Worker uses Cloudflare's current stateless `createMcpHandler` approach from the `agents/mcp` SDK. A fresh `McpServer` is created per request, which matches the current Cloudflare guidance for stateless Streamable HTTP MCP servers.

Tools exposed at `/mcp`:

- `virustotal_lookup(indicator)`: auto-detects domain, IP, URL, or file hash; returns reputation, vendor detections, categories, and domain resolutions.
- `urlscan_lookup(url_or_domain)`: searches existing scans; returns verdict, title, final URL, screenshot link, contacted IPs, and contacted domains.
- `censys_lookup(ip_or_domain)`: returns host ports/services, TLS certificate details, JARM, ASN, and geolocation using the current Censys Platform API.
- `investigate_indicator(indicator)`: orchestrates the sources, pivots domain resolutions into Censys host enrichment, runs JARM/certificate sibling pivots, checks hosted content in urlscan, and returns one normalized correlated summary.

Every source result normalizes to:

```json
{
  "indicator": "example.com",
  "indicator_type": "domain",
  "source": "virustotal",
  "verdict": "unknown",
  "score": null,
  "key_findings": [],
  "raw_ref": {}
}
```

The Worker accepts common defanged indicators like `evil[.]com`, `hxxps://evil[.]com`, and `1[.]2[.]3[.]4`. If a source API key is missing, that source returns a structured `skipped` result instead of failing the whole tool call.

## Setup

```powershell
npm install
```

For local development, copy the example env file and fill only the keys you want to test:

```powershell
Copy-Item .dev.vars.example .dev.vars
```

Do not commit `.dev.vars`; it is ignored.

## Secrets

Set secrets in Cloudflare with Wrangler:

```powershell
npx wrangler secret put VT_API_KEY
npx wrangler secret put URLSCAN_API_KEY
npx wrangler secret put CENSYS_API_TOKEN
npx wrangler secret put CENSYS_ORG_ID
npx wrangler secret put MCP_SHARED_SECRET
```

Censys currently documents the Platform API under `https://api.platform.censys.io/v3/` with bearer-token authentication. If your account still has older API ID/secret credentials, create a current Censys Platform personal access token and use it as `CENSYS_API_TOKEN`.

Optional cache:

1. Create a Workers KV namespace.
2. Uncomment the `kv_namespaces` binding in `wrangler.jsonc`.
3. Set `ENABLE_CACHE=true` and optionally `CACHE_TTL_SECONDS`.

## Local Dev

```powershell
npx wrangler dev
```

The MCP endpoint will be:

```text
http://localhost:8787/mcp
```

If `MCP_SHARED_SECRET` is set, clients must send:

```text
Authorization: Bearer <MCP_SHARED_SECRET>
```

## Deploy

```powershell
npx wrangler deploy
```

After deploy, the endpoint is:

```text
https://mcp-threat-intelligence.<your-subdomain>.workers.dev/mcp
```

## Connect

### MCP Inspector

```powershell
npx @modelcontextprotocol/inspector
```

Use the remote Streamable HTTP URL:

```text
https://mcp-threat-intelligence.<your-subdomain>.workers.dev/mcp
```

Add an `Authorization` header if `MCP_SHARED_SECRET` is set.

### Cloudflare AI Playground

Open the Cloudflare AI Playground, add a remote MCP server, and use:

```text
https://mcp-threat-intelligence.<your-subdomain>.workers.dev/mcp
```

Set the bearer token header if the shared secret is enabled.

### Claude Desktop via mcp-remote

Edit `%APPDATA%\Claude\claude_desktop_config.json` on Windows:

```json
{
  "mcpServers": {
    "threat-intel": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://mcp-threat-intelligence.<your-subdomain>.workers.dev/mcp",
        "--header",
        "Authorization:${AUTH_HEADER}"
      ],
      "env": {
        "AUTH_HEADER": "Bearer <MCP_SHARED_SECRET>"
      }
    }
  }
}
```

Restart Claude Desktop after editing the config.

## Sample Investigation Transcript

Investigator:

```text
Investigate hxxps://login-example[.]com and look for related infrastructure.
```

Agent calls:

```text
investigate_indicator({"indicator":"hxxps://login-example[.]com"})
```

Representative response:

```text
login-example.com assessed as suspicious with medium confidence using virustotal, urlscan, censys.

Evidence chain:
1. Input refanged to https://login-example.com/ and classified as url.
2. VirusTotal found suspicious vendor detections and recent resolutions to 203.0.113.44.
3. urlscan found a login-themed page title, final URL, screenshot, and contacted domains.
4. Censys enriched 203.0.113.44 with ports 80 and 443, a TLS certificate, JARM fingerprint, ASN, and geolocation.
5. Censys JARM and certificate pivots surfaced sibling IPs 203.0.113.45 and 203.0.113.46.

Next pivot:
Run censys_lookup on each sibling IP, then compare certificates, JARM, page title, and ASN for campaign clustering.
```

## Security Notes

- This demo is not authless by default when `MCP_SHARED_SECRET` is configured. Keep it enabled to avoid creating an open proxy to paid API quotas.
- Secrets must be set with Wrangler or Cloudflare dashboard secrets. Never commit real API keys.
- Each external query emits a structured audit log line with source, indicator, timestamp, status, and HTTP status where available.
- API errors and rate limits are returned as structured JSON so the agent can explain partial results and continue with other sources.
- For production, replace the shared bearer token with OAuth using `@cloudflare/workers-oauth-provider`, Cloudflare Access, or another OAuth 2.1 provider.

## Roadmap

- OAuth and per-user tool permissions.
- MISP and STIX/TAXII export.
- More sources such as AbuseIPDB, Shodan, GreyNoise, and MISP.
- Durable workflow support for long-running investigations.
- Richer correlation scoring and analyst-tunable verdict policy.

## GitHub and Cloudflare Git Integration

Initialize and push:

```powershell
git init
git branch -M main
git add .
git commit -m "Initial MCP threat intelligence worker"
git remote add origin https://github.com/TheDudesRepo/MCP-Threat-Intelligence.git
git push -u origin main
```

Then in Cloudflare:

1. Workers & Pages -> Create -> Import a repository.
2. Select `TheDudesRepo/MCP-Threat-Intelligence`.
3. Set the production branch to `main`.
4. Use `npm install` as the install command.
5. Use `npm run deploy` or `npx wrangler deploy` as the deploy command, depending on the Git integration UI.
6. Add the Worker secrets listed above before enabling production deploys.

