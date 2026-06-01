import type { SourceName } from "../types";

interface AuditEvent {
  source: SourceName;
  indicator: string;
  status: "ok" | "error" | "retry" | "skipped";
  status_code?: number;
  cache_hit?: boolean;
  detail?: string;
}

export function auditExternalQuery(event: AuditEvent): void {
  console.log(
    JSON.stringify({
      event: "threat_intel_external_query",
      timestamp: new Date().toISOString(),
      source: event.source,
      indicator: event.indicator,
      status: event.status,
      status_code: event.status_code,
      cache_hit: event.cache_hit ?? false,
      detail: event.detail,
    }),
  );
}

