interface Env {
  VT_API_KEY?: string;
  URLSCAN_API_KEY?: string;
  CENSYS_API_ID?: string;
  CENSYS_API_TOKEN?: string;
  CENSYS_PLATFORM_TOKEN?: string;
  CENSYS_API_SECRET?: string;
  CENSYS_ORG_ID?: string;
  MCP_SHARED_SECRET?: string;
  ENABLE_CACHE?: string;
  CACHE_TTL_SECONDS?: string;
  TI_CACHE?: KVNamespace;
}
