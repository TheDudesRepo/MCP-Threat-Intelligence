export type IndicatorType = "domain" | "ip" | "url" | "file_hash" | "unknown";

export type SourceName =
  | "virustotal"
  | "urlscan"
  | "censys"
  | "cloudflare_radar"
  | "correlation";

export type Verdict =
  | "malicious"
  | "suspicious"
  | "clean"
  | "unknown"
  | "skipped"
  | "error";

export interface ParsedIndicator {
  original: string;
  normalized: string;
  indicator_type: IndicatorType;
  hostname?: string | undefined;
}

export interface SourceError {
  source: SourceName;
  status?: number | undefined;
  code: string;
  message: string;
  retry_after_seconds?: number | undefined;
  response_excerpt?: string | undefined;
}

export interface NormalizedSourceResult {
  indicator: string;
  indicator_type: IndicatorType;
  source: SourceName;
  verdict: Verdict;
  score: number | null;
  key_findings: string[];
  raw_ref: Record<string, unknown> | null;
  status: "ok" | "skipped" | "error";
  error?: SourceError | undefined;
  details?: Record<string, unknown> | undefined;
}

export interface CensysServiceSummary {
  port?: number | undefined;
  protocol?: string | undefined;
  transport_protocol?: string | undefined;
  service_name?: string | undefined;
  observed_at?: string | undefined;
}

export interface CensysHostSummary {
  ip?: string | undefined;
  open_ports: number[];
  services: CensysServiceSummary[];
  tls_certificates: Array<Record<string, unknown>>;
  jarm_fingerprints: string[];
  certificate_fingerprints: string[];
  asn?: number | undefined;
  as_name?: string | undefined;
  geolocation?: Record<string, unknown> | undefined;
  labels: string[];
  threats: string[];
}

export interface InvestigationResult {
  indicator: string;
  indicator_type: IndicatorType;
  refanged_indicator: string;
  verdict: Verdict;
  confidence: "low" | "medium" | "high";
  summary: string;
  normalized_sources: NormalizedSourceResult[];
  evidence_chain: string[];
  pivots: Array<Record<string, unknown>>;
  skipped_sources: string[];
}
