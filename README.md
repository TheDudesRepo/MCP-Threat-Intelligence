# MCP Threat Intelligence

MCP Threat Intelligence is a stateless Cloudflare Workers Model Context Protocol server that gives an investigator's AI agent reusable tools for enriching and correlating indicators across VirusTotal, urlscan.io, and Censys. The point is not a single lookup; it is to let the agent gather evidence, pivot from domains to IPs and infrastructure fingerprints, and return a normalized investigation summary with a verdict, confidence, and evidence chain.

## Why an MCP server instead of querying these APIs directly

An MCP server lets the AI agent orchestrate multi-source correlation autonomously instead of forcing every investigator or prompt to know three vendor APIs. It is reusable across investigators and agents, and it centralizes authentication, rate-limit handling, optional caching, and audit logging so source API keys and quota policies stay in one controlled Worker.

## Architecture

This Worker uses Cloudflare's current stateless `createMcpHandler` approach from the `agents/mcp` SDK. A fresh `McpServer` is created per request, which matches the current Cloudflare guidance for stateless Streamable HTTP MCP servers.

Tools exposed at `/mcp`:

- `virustotal_lookup(indicator)`: auto-detects domain, IP, URL, or file hash; returns reputation, vendor detections, categories, and domain resolutions.
- `urlscan_lookup(url_or_domain)`: searches existing scans; returns verdict, title, final URL, screenshot link, contacted IPs, and contacted domains.
- `cloudflare_urlscan_lookup(url_or_domain, submit_scan?)`: searches Cloudflare Radar URL Scanner reports and optionally submits a new unlisted scan; returns verdict, final URL, primary IP/ASN, contacted IPs/domains, categories, hashes, and report link.
- `censys_lookup(ip_or_domain)`: returns host ports/services, TLS certificate details, JARM, ASN, and geolocation using the current Censys Platform API. Free Censys accounts can use direct IP host lookups; domain search requires paid/organization API access.
- `investigate_indicator(indicator)`: orchestrates the sources, pivots VirusTotal and Cloudflare Radar IP evidence into Censys direct IP host enrichment when possible, runs paid/org Censys sibling pivots when enabled, checks hosted content in urlscan/Radar, and returns one normalized correlated summary.

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
npx wrangler secret put CLOUDFLARE_ACCOUNT_ID
npx wrangler secret put CLOUDFLARE_URL_SCANNER_TOKEN
npx wrangler secret put CENSYS_API_TOKEN
npx wrangler secret put MCP_SHARED_SECRET
```

CLOUDFLARE_URL_SCANNER_TOKEN should be a Cloudflare API token with Account > URL Scanner permission. The account ID is not a password, but keep it in Cloudflare secrets instead of `wrangler.jsonc` so the public repo does not disclose account metadata.

Cloudflare Radar URL Scanner uses `Unlisted` visibility by default in this Worker when submitting a new scan. Do not set it to `Public` unless you intentionally want submitted URLs to appear in recent scans and search results. To override it:

```powershell
npx wrangler secret put CLOUDFLARE_URL_SCAN_VISIBILITY
```

Use `Unlisted` or `Public` as the value.

Censys currently documents the Platform API under `https://api.platform.censys.io/v3/` with bearer-token authentication. If your account still has older API ID/secret credentials, create a current Censys Platform personal access token and use it as `CENSYS_API_TOKEN`.

For free Censys accounts, do not set `CENSYS_ORG_ID`; the Worker omits `organization_id` by default. In this mode, Censys works for direct IP host lookups and for investigations where VirusTotal provides resolved IPs to pivot into Censys. Censys domain search and sibling-infrastructure pivots use the Platform search API and require paid/organization API access.

If you have a paid/enterprise Censys account that requires an organization ID, set both:

```powershell
npx wrangler secret put CENSYS_ORG_ID
npx wrangler secret put CENSYS_USE_ORG_ID
```

Use `true` as the value for `CENSYS_USE_ORG_ID`.

If you previously set `CENSYS_ORG_ID` for a free account, remove it to keep the Cloudflare secret list clean:

```powershell
npx wrangler secret delete CENSYS_ORG_ID
```

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

Clients must send:

```text
Authorization: Bearer <MCP_SHARED_SECRET>
```

## Deploy

```powershell
npx wrangler deploy
```

After deploy, the endpoint is:

```text
https://mcp-threat-intel.<your-subdomain>.workers.dev/mcp
```

## Connect

### MCP Inspector

```powershell
npx @modelcontextprotocol/inspector
```

Use the remote Streamable HTTP URL:

```text
https://mcp-threat-intel.<your-subdomain>.workers.dev/mcp
```

Add the `Authorization` header with your `MCP_SHARED_SECRET` value.

### Cloudflare AI Playground

Open the Cloudflare AI Playground, add a remote MCP server, and use:

```text
https://mcp-threat-intel.<your-subdomain>.workers.dev/mcp
```

Set the bearer token header with your `MCP_SHARED_SECRET` value.

### Cloudflare Radar MCP Server

Cloudflare also runs an official Radar MCP server:

```text
https://radar.mcp.cloudflare.com/mcp
```

Use it directly when you want general Radar trends, insights, and URL scan utilities in a client. This Worker integrates the underlying URL Scanner API directly so its results can be normalized and correlated with VirusTotal, urlscan.io, and Censys in `investigate_indicator`.

### Claude Desktop via mcp-remote

Edit the Claude Desktop config file for your OS:

- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

Use the same JSON on each OS:

```json
{
  "mcpServers": {
    "threat-intel": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://mcp-threat-intel.<your-subdomain>.workers.dev/mcp",
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

Keep `Authorization:${AUTH_HEADER}` exactly as shown. Put your real shared secret in `AUTH_HEADER` with the `Bearer ` prefix. Restart Claude Desktop after editing the config.

### Claude Code

Claude Code can connect directly to remote HTTP MCP servers:

```bash
claude mcp add --transport http --scope user threat-intel \
  https://mcp-threat-intel.<your-subdomain>.workers.dev/mcp \
  --header "Authorization: Bearer <MCP_SHARED_SECRET>"
```

Verify it:

```bash
claude mcp list
```

Inside Claude Code, run:

```text
/mcp
```

If you prefer a project-scoped config instead of a user-scoped server, omit `--scope user` from the add command while you are in that project.

### Codex CLI

Codex reads MCP server config from `~/.codex/config.toml` for user-wide setup, or `.codex/config.toml` for a trusted project-scoped setup. Use `bearer_token_env_var`; Codex adds the `Authorization: Bearer ...` header for you.

Add this to `~/.codex/config.toml`:

```toml
[mcp_servers.threat-intel]
url = "https://mcp-threat-intel.<your-subdomain>.workers.dev/mcp"
bearer_token_env_var = "MCP_SHARED_SECRET"
```

Then set the environment variable before starting Codex.

macOS/Linux:

```bash
export MCP_SHARED_SECRET="<MCP_SHARED_SECRET>"
codex
```

Windows PowerShell:

```powershell
$env:MCP_SHARED_SECRET = "<MCP_SHARED_SECRET>"
codex
```

Verify it inside Codex:

```text
/mcp
```

For Codex, the environment variable is just the raw shared secret. Do not include `Bearer ` when using `bearer_token_env_var`.

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
4. Cloudflare Radar confirmed the final URL, primary IP, contacted domains, categories, and malicious verdict metadata.
5. Censys enriched 203.0.113.44 with ports 80 and 443, a TLS certificate, JARM fingerprint, ASN, and geolocation.
6. Censys JARM and certificate pivots surfaced sibling IPs 203.0.113.45 and 203.0.113.46.

Next pivot:
Run censys_lookup on each sibling IP, then compare certificates, JARM, page title, and ASN for campaign clustering.
```

## Security Notes

- `MCP_SHARED_SECRET` is required. If it is missing, `/mcp` fails closed so the Worker does not become an open proxy to paid API quotas.
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
