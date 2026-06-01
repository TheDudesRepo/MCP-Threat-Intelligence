import type {
  IndicatorType,
  NormalizedSourceResult,
  SourceError,
  SourceName,
  Verdict,
} from "../types";

export function skippedResult(
  source: SourceName,
  indicator: string,
  indicatorType: IndicatorType,
  reason: string,
): NormalizedSourceResult {
  return {
    indicator,
    indicator_type: indicatorType,
    source,
    verdict: "skipped",
    score: null,
    key_findings: [reason],
    raw_ref: null,
    status: "skipped",
  };
}

export function errorResult(
  source: SourceName,
  indicator: string,
  indicatorType: IndicatorType,
  error: SourceError,
): NormalizedSourceResult {
  return {
    indicator,
    indicator_type: indicatorType,
    source,
    verdict: "error",
    score: null,
    key_findings: [error.message],
    raw_ref: null,
    status: "error",
    error,
  };
}

export function makeSourceResult(input: {
  source: SourceName;
  indicator: string;
  indicatorType: IndicatorType;
  verdict: Verdict;
  score: number | null;
  keyFindings: string[];
  rawRef: Record<string, unknown> | null;
  details?: Record<string, unknown>;
}): NormalizedSourceResult {
  return {
    indicator: input.indicator,
    indicator_type: input.indicatorType,
    source: input.source,
    verdict: input.verdict,
    score: input.score,
    key_findings: input.keyFindings.length
      ? input.keyFindings
      : ["No notable findings returned."],
    raw_ref: input.rawRef,
    status: "ok",
    ...(input.details ? { details: input.details } : {}),
  };
}

export function verdictFromStats(stats: Record<string, unknown> | undefined): {
  verdict: Verdict;
  score: number | null;
} {
  if (!stats) {
    return { verdict: "unknown", score: null };
  }

  const malicious = toNumber(stats.malicious);
  const suspicious = toNumber(stats.suspicious);
  const harmless = toNumber(stats.harmless);
  const undetected = toNumber(stats.undetected);
  const timeout = toNumber(stats.timeout);
  const total = malicious + suspicious + harmless + undetected + timeout;
  const score = total
    ? Math.min(100, Math.round(((malicious * 2 + suspicious) / total) * 100))
    : null;

  if (malicious > 0) {
    return { verdict: "malicious", score };
  }

  if (suspicious > 0) {
    return { verdict: "suspicious", score };
  }

  if (harmless > 0) {
    return { verdict: "clean", score };
  }

  return { verdict: "unknown", score };
}

function toNumber(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

