import { parseIndicator } from "./lib/indicators";
import { makeSourceResult } from "./lib/results";
import { lookupCloudflareUrlScan } from "./sources/cloudflare";
import {
  findCensysSiblings,
  getCensysHostSummary,
  lookupCensys,
} from "./sources/censys";
import { lookupUrlscan } from "./sources/urlscan";
import { lookupVirusTotal } from "./sources/virustotal";
import type {
  InvestigationResult,
  NormalizedSourceResult,
  Verdict,
} from "./types";

export async function investigateIndicator(
  env: Env,
  input: string,
): Promise<InvestigationResult> {
  const parsed = parseIndicator(input);
  const normalizedSources: NormalizedSourceResult[] = [];
  const evidenceChain: string[] = [
    `Input refanged to ${parsed.normalized} and classified as ${parsed.indicator_type}.`,
  ];
  const pivots: Array<Record<string, unknown>> = [];

  const vt = await lookupVirusTotal(env, parsed.normalized);
  normalizedSources.push(vt);
  evidenceChain.push(summarizeSource(vt));

  const urlscanEligible =
    parsed.indicator_type === "domain" || parsed.indicator_type === "url";
  if (urlscanEligible) {
    const urlscan = await lookupUrlscan(env, parsed.normalized);
    normalizedSources.push(urlscan);
    evidenceChain.push(summarizeSource(urlscan));

    const cloudflare = await lookupCloudflareUrlScan(env, parsed.normalized);
    normalizedSources.push(cloudflare);
    evidenceChain.push(summarizeSource(cloudflare));
  }

  const pivotIps = collectPivotIps(
    parsed.normalized,
    parsed.indicator_type,
    normalizedSources,
  );
  if (pivotIps.length > 0) {
    evidenceChain.push(
      `Pivoting to Censys host enrichment for ${pivotIps.slice(0, 3).join(", ")}.`,
    );
  }

  for (const ip of pivotIps.slice(0, 2)) {
    const censys = await lookupCensys(env, ip);
    normalizedSources.push(censys);
    evidenceChain.push(summarizeSource(censys));

    const hostSummary = getCensysHostSummary(censys);
    if (hostSummary) {
      const siblingPivots = await findCensysSiblings(
        env,
        hostSummary,
        parsed.normalized,
      );
      pivots.push(...siblingPivots);
      for (const pivot of siblingPivots) {
        const related = Array.isArray(pivot.related_ips)
          ? pivot.related_ips.join(", ")
          : "";
        evidenceChain.push(
          `Censys ${pivot.pivot_type} pivot found related IPs: ${
            related || "none in first page"
          }.`,
        );
      }
    }
  }

  if (pivotIps.length === 0 && parsed.hostname) {
    const censys = await lookupCensys(env, parsed.hostname);
    normalizedSources.push(censys);
    evidenceChain.push(summarizeSource(censys));

    const hostSummary = getCensysHostSummary(censys);
    if (hostSummary) {
      const siblingPivots = await findCensysSiblings(
        env,
        hostSummary,
        parsed.normalized,
      );
      pivots.push(...siblingPivots);
    }
  }

  const decision = decideVerdict(normalizedSources);
  const summary = buildInvestigationSummary(
    parsed.normalized,
    decision.verdict,
    decision.confidence,
    normalizedSources,
    pivots,
  );
  const correlation = makeSourceResult({
    source: "correlation",
    indicator: parsed.normalized,
    indicatorType: parsed.indicator_type,
    verdict: decision.verdict,
    score: decision.score,
    keyFindings: [summary],
    rawRef: null,
    details: {
      confidence: decision.confidence,
      evidence_count: evidenceChain.length,
      pivot_count: pivots.length,
    },
  });
  normalizedSources.push(correlation);

  return {
    indicator: input,
    indicator_type: parsed.indicator_type,
    refanged_indicator: parsed.normalized,
    verdict: decision.verdict,
    confidence: decision.confidence,
    summary,
    normalized_sources: normalizedSources,
    evidence_chain: evidenceChain,
    pivots,
    skipped_sources: normalizedSources
      .filter((source) => source.status === "skipped")
      .map((source) => source.source),
  };
}

function collectPivotIps(
  normalized: string,
  type: string,
  sources: NormalizedSourceResult[],
): string[] {
  const ips = new Set<string>();
  if (type === "ip") {
    ips.add(normalized);
  }

  for (const source of sources) {
    const resolutions = source.details?.resolutions;
    if (Array.isArray(resolutions)) {
      for (const resolution of resolutions) {
        if (isRecord(resolution) && typeof resolution.ip_address === "string") {
          ips.add(resolution.ip_address);
        }
      }
    }

    const primaryIp = source.details?.primary_ip;
    if (typeof primaryIp === "string") {
      ips.add(primaryIp);
    }

    const contactedIps = source.details?.contacted_ips;
    if (Array.isArray(contactedIps)) {
      for (const ip of contactedIps) {
        if (typeof ip === "string") {
          ips.add(ip);
        }
      }
    }
  }

  return [...ips];
}

function decideVerdict(sources: NormalizedSourceResult[]): {
  verdict: Verdict;
  confidence: "low" | "medium" | "high";
  score: number | null;
} {
  const okSources = sources.filter((source) => source.status === "ok");
  const malicious = okSources.filter((source) => source.verdict === "malicious");
  const suspicious = okSources.filter(
    (source) => source.verdict === "suspicious",
  );

  if (malicious.length >= 2 || (malicious.length === 1 && suspicious.length > 0)) {
    return { verdict: "malicious", confidence: "high", score: 90 };
  }

  if (malicious.length === 1) {
    return { verdict: "malicious", confidence: "medium", score: 75 };
  }

  if (suspicious.length >= 2) {
    return { verdict: "suspicious", confidence: "high", score: 70 };
  }

  if (suspicious.length === 1) {
    return { verdict: "suspicious", confidence: "medium", score: 55 };
  }

  const clean = okSources.filter((source) => source.verdict === "clean");
  if (clean.length > 0 && okSources.length >= 2) {
    return { verdict: "clean", confidence: "medium", score: 5 };
  }

  return {
    verdict: "unknown",
    confidence: okSources.length > 0 ? "low" : "low",
    score: null,
  };
}

function buildInvestigationSummary(
  indicator: string,
  verdict: Verdict,
  confidence: "low" | "medium" | "high",
  sources: NormalizedSourceResult[],
  pivots: Array<Record<string, unknown>>,
): string {
  const activeSources = sources
    .filter((source) => source.status === "ok")
    .map((source) => source.source)
    .filter((source) => source !== "correlation");
  const skipped = sources
    .filter((source) => source.status === "skipped")
    .map((source) => source.source);
  const pivotText =
    pivots.length > 0
      ? ` Censys pivots produced ${pivots.length} sibling-infrastructure lead(s).`
      : "";
  const skippedText =
    skipped.length > 0 ? ` Skipped sources: ${skipped.join(", ")}.` : "";

  return `${indicator} assessed as ${verdict} with ${confidence} confidence using ${
    activeSources.length > 0 ? activeSources.join(", ") : "no external source"
  }.${pivotText}${skippedText}`;
}

function summarizeSource(source: NormalizedSourceResult): string {
  return `${source.source} returned ${source.verdict} (${source.status}): ${source.key_findings[0]}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
