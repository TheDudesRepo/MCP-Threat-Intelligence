import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createMcpHandler } from "agents/mcp";
import { z } from "zod";
import { investigateIndicator } from "./investigate";
import { lookupCloudflareUrlScan } from "./sources/cloudflare";
import { lookupCensys } from "./sources/censys";
import { lookupUrlscan } from "./sources/urlscan";
import { lookupVirusTotal } from "./sources/virustotal";

const MCP_ROUTE = "/mcp";

function createServer(env: Env): McpServer {
  const server = new McpServer({
    name: "MCP Threat Intelligence",
    version: "0.1.0",
  });

  server.tool(
    "virustotal_lookup",
    "Auto-detect a domain, IP, URL, or file hash and return VirusTotal reputation, vendor detections, categories, and domain resolutions when applicable.",
    {
      indicator: z
        .string()
        .min(1)
        .describe("A domain, IP address, URL, file hash, or defanged indicator."),
    },
    async ({ indicator }) => jsonToolResult(await lookupVirusTotal(env, indicator)),
  );

  server.tool(
    "urlscan_lookup",
    "Search existing urlscan.io scans for a URL, domain, or IP and return verdict, page title, final URL, screenshot link, contacted IPs, and contacted domains.",
    {
      url_or_domain: z
        .string()
        .min(1)
        .describe("A URL, domain, IP, or defanged URL/domain to search in urlscan.io."),
    },
    async ({ url_or_domain }) =>
      jsonToolResult(await lookupUrlscan(env, url_or_domain)),
  );

  server.tool(
    "cloudflare_urlscan_lookup",
    "Search existing Cloudflare Radar URL Scanner reports for a URL, domain, or IP. Optionally submit a new unlisted scan when no report is found. Returns verdict, final URL, primary IP/ASN, contacted IPs/domains, categories, hashes, and a Radar report link.",
    {
      url_or_domain: z
        .string()
        .min(1)
        .describe("A URL, domain, IP, or defanged URL/domain to search in Cloudflare Radar URL Scanner."),
      submit_scan: z
        .boolean()
        .optional()
        .describe("Submit a new unlisted Cloudflare URL scan if no existing scan report is found. Defaults to false."),
    },
    async ({ url_or_domain, submit_scan }) =>
      jsonToolResult(
        await lookupCloudflareUrlScan(env, url_or_domain, {
          submitScan: submit_scan === true,
        }),
      ),
  );

  server.tool(
    "censys_lookup",
    "Enrich an IP address with Censys Platform host context including open ports, services, TLS certificate details, JARM, ASN, and geolocation. Domain search requires paid/organization Censys API access; free accounts can use direct IP host lookup.",
    {
      ip_or_domain: z
        .string()
        .min(1)
        .describe("An IP address, domain, URL hostname, or defanged host indicator."),
    },
    async ({ ip_or_domain }) => jsonToolResult(await lookupCensys(env, ip_or_domain)),
  );

  server.tool(
    "investigate_indicator",
    "Correlate VirusTotal, urlscan.io, and Censys evidence for an indicator. Use this when the investigator needs a normalized verdict, confidence, pivots, and an evidence chain rather than a single-source lookup.",
    {
      indicator: z
        .string()
        .min(1)
        .describe("A domain, IP, URL, file hash, or defanged indicator to investigate."),
    },
    async ({ indicator }) =>
      jsonToolResult(await investigateIndicator(env, indicator)),
  );

  return server;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const url = new URL(request.url);

    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/health")) {
      return Response.json({
        name: "mcp-threat-intelligence",
        status: "ok",
        mcp_endpoint: MCP_ROUTE,
      });
    }

    const server = createServer(env);
    const handler = createMcpHandler(server, {
      route: MCP_ROUTE,
      corsOptions: {
        origin: "*",
        methods: "GET, POST, OPTIONS",
        headers:
          "Content-Type, Authorization, Mcp-Session-Id, MCP-Protocol-Version, Last-Event-ID",
        exposeHeaders: "Mcp-Session-Id, MCP-Protocol-Version",
      },
    });

    if (isMcpRoute(url.pathname) && request.method !== "OPTIONS") {
      const authFailure = authorizeRequest(request, env);
      if (authFailure) {
        return authFailure;
      }
    }

    return handler(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;

function authorizeRequest(request: Request, env: Env): Response | null {
  if (!env.MCP_SHARED_SECRET) {
    return Response.json(
      {
        error: "mcp_shared_secret_required",
        message:
          "MCP_SHARED_SECRET is not configured; refusing to expose MCP tools.",
      },
      {
        status: 503,
      },
    );
  }

  const expected = `Bearer ${env.MCP_SHARED_SECRET}`;
  const actual = request.headers.get("authorization");
  if (actual === expected) {
    return null;
  }

  return Response.json(
    {
      error: "unauthorized",
      message: "Missing or invalid bearer token for MCP endpoint.",
    },
    {
      status: 401,
      headers: {
        "www-authenticate": 'Bearer realm="mcp-threat-intel"',
      },
    },
  );
}

function isMcpRoute(pathname: string): boolean {
  return pathname === MCP_ROUTE || pathname.startsWith(`${MCP_ROUTE}/`);
}

function jsonToolResult(value: unknown) {
  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(value, null, 2),
      },
    ],
  };
}
