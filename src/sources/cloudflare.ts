import { cacheKey, getCached, putCached } from "../lib/cache";
import { fetchJson } from "../lib/http";
import { isIp, parseIndicator } from "../lib/indicators";
import { errorResult, makeSourceResult, skippedResult } from "../lib/results";
import type {
  IndicatorType,
  NormalizedSourceResult,
  SourceError,
  Verdict,
} from "../types";

const CLOUDFLARE_API_BASE_URL = "https://api.cloudflare.com/client/v4";

interface CloudflareApiEnvelope<T> {
  success?: boolean;
  errors?: Array<Record<string, unknown>>;
  messages?: Array<Record<string, unknown>>;
  result?: T;
}

interface CloudflareSearchPayload {
  results?: CloudflareSearchResult[];
}

interface CloudflareSearchResult {
  _id?: string;
  task?: Record<string, unknown>;
  page?: Record<string, unknown>;
  stats?: Record<string, unknown>;
  verdicts?: Record<string, unknown>;
  result?: string;
}

interface CloudflareSubmitPayload {
  uuid?: string;
  api?: string;
  visibility?: string;
  url?: string;
  message?: string;
}

export async function lookupCloudflareUrlScan(
  env: Env,
  input: string,
  options: { submitScan?: boolean } = {},
): Promise<NormalizedSourceResult> {
  const parsed = parseIndicator(input);
  const lookupValue = parsed.hostname ?? parsed.normalized;
  const accountId = env.CLOUDFLARE_ACCOUNT_ID?.trim();
  const token = getCloudflareUrlScannerToken(env);

  if (!accountId || !token) {
    return skippedResult(
      "cloudflare_radar",
      lookupValue,
      parsed.indicator_type,
      "Cloudflare URL Scanner account ID or API token is not configured; skipped.",
    );
  }

  if (
    parsed.indicator_type !== "domain" &&
    parsed.indicator_type !== "url" &&
    parsed.indicator_type !== "ip"
  ) {
    return errorResult(
      "cloudflare_radar",
      lookupValue,
      parsed.indicator_type,
      {
        source: "cloudflare_radar",
        code: "invalid_indicator",
        message:
          "Cloudflare URL Scanner lookup requires a URL, domain, or IP address.",
      },
    );
  }

  const key = cacheKey(
    "cloudflare_radar",
    `${parsed.indicator_type}:${lookupValue}:submit=${options.submitScan === true}`,
  );
  const cached = await getCached<NormalizedSourceResult>(env, key);
  if (cached) {
    return cached;
  }

  const search = await searchCloudflareScans(env, parsed.normalized, lookupValue);
  if (!search.ok) {
    return errorResult(
      "cloudflare_radar",
      lookupValue,
      parsed.indicator_type,
      search.error,
    );
  }

  const topResult = search.results[0];
  const scanId =
    topResult?._id ??
    stringValue(topResult?.task?.uuid) ??
    extractScanIdFromResultUrl(topResult?.result);

  if (scanId) {
    const report = await getCloudflareScanReport(env, scanId, lookupValue);
    if (report.ok) {
      const result = normalizeCloudflareReport(
        parsed.normalized,
        parsed.indicator_type,
        report.data,
        scanId,
        search.searchUrl,
      );
      await putCached(env, key, result);
      return result;
    }
  }

  if (options.submitScan) {
    const submitted = await submitCloudflareScan(env, toScanUrl(parsed));
    if (!submitted.ok) {
      return errorResult(
        "cloudflare_radar",
        lookupValue,
        parsed.indicator_type,
        submitted.error,
      );
    }

    const result = normalizeSubmittedScan(
      parsed.normalized,
      parsed.indicator_type,
      submitted.data,
    );
    await putCached(env, key, result);
    return result;
  }

  const result = makeSourceResult({
    source: "cloudflare_radar",
    indicator: lookupValue,
    indicatorType: parsed.indicator_type,
    verdict: "unknown",
    score: null,
    keyFindings: [
      `Found ${search.results.length} existing Cloudflare Radar URL Scanner result(s).`,
    ],
    rawRef: {
      search_url: search.searchUrl,
    },
    details: {
      total_results: search.results.length,
      latest_scan_id: scanId ?? null,
      latest_result_url: topResult?.result ?? null,
      search_results: search.results.slice(0, 5),
    },
  });
  await putCached(env, key, result);
  return result;
}

async function searchCloudflareScans(
  env: Env,
  normalized: string,
  lookupValue: string,
): Promise<
  | { ok: true; results: CloudflareSearchResult[]; searchUrl: string }
  | { ok: false; error: SourceError }
> {
  const accountId = env.CLOUDFLARE_ACCOUNT_ID?.trim() ?? "";
  const query = buildCloudflareSearchQuery(normalized, lookupValue);
  const searchUrl = `${CLOUDFLARE_API_BASE_URL}/accounts/${encodeURIComponent(
    accountId,
  )}/urlscanner/v2/search?${new URLSearchParams({
    q: query,
    size: "5",
  }).toString()}`;
  const response = await fetchJson<
    CloudflareApiEnvelope<CloudflareSearchPayload> | CloudflareSearchPayload
  >(searchUrl, {
    source: "cloudflare_radar",
    indicator: lookupValue,
    headers: cloudflareHeaders(env),
  });

  if (!response.ok) {
    return { ok: false, error: response.error };
  }

  const payload = unwrapCloudflareResult<CloudflareSearchPayload>(response.data);
  return {
    ok: true,
    results: payload.results ?? [],
    searchUrl,
  };
}

async function getCloudflareScanReport(
  env: Env,
  scanId: string,
  indicator: string,
): Promise<
  | { ok: true; data: Record<string, unknown> }
  | { ok: false; error: SourceError }
> {
  const accountId = env.CLOUDFLARE_ACCOUNT_ID?.trim() ?? "";
  const endpoint = `${CLOUDFLARE_API_BASE_URL}/accounts/${encodeURIComponent(
    accountId,
  )}/urlscanner/v2/result/${encodeURIComponent(scanId)}`;
  const response = await fetchJson<
    CloudflareApiEnvelope<Record<string, unknown>> | Record<string, unknown>
  >(endpoint, {
    source: "cloudflare_radar",
    indicator,
    headers: cloudflareHeaders(env),
  });

  if (!response.ok) {
    return { ok: false, error: response.error };
  }

  return {
    ok: true,
    data: unwrapCloudflareResult<Record<string, unknown>>(response.data),
  };
}

async function submitCloudflareScan(
  env: Env,
  url: string,
): Promise<
  | { ok: true; data: CloudflareSubmitPayload }
  | { ok: false; error: SourceError }
> {
  const accountId = env.CLOUDFLARE_ACCOUNT_ID?.trim() ?? "";
  const endpoint = `${CLOUDFLARE_API_BASE_URL}/accounts/${encodeURIComponent(
    accountId,
  )}/urlscanner/v2/scan`;
  const response = await fetchJson<
    CloudflareApiEnvelope<CloudflareSubmitPayload> | CloudflareSubmitPayload
  >(endpoint, {
    source: "cloudflare_radar",
    indicator: url,
    method: "POST",
    headers: {
      ...cloudflareHeaders(env),
      "content-type": "application/json",
    },
    body: JSON.stringify({
      url,
      visibility: env.CLOUDFLARE_URL_SCAN_VISIBILITY ?? "Unlisted",
    }),
  });

  if (!response.ok) {
    return { ok: false, error: response.error };
  }

  return {
    ok: true,
    data: unwrapCloudflareResult<CloudflareSubmitPayload>(response.data),
  };
}

function normalizeCloudflareReport(
  indicator: string,
  indicatorType: IndicatorType,
  report: Record<string, unknown>,
  scanId: string,
  searchUrl: string,
): NormalizedSourceResult {
  const task = asRecord(report.task);
  const page = asRecord(report.page);
  const lists = asRecord(report.lists);
  const meta = asRecord(report.meta);
  const processors = asRecord(meta?.processors);
  const verdicts = asRecord(report.verdicts);
  const overallVerdict = asRecord(verdicts?.overall);
  const contactedIps = stringArray(lists?.ips).slice(0, 50);
  const contactedDomains = stringArray(lists?.domains).slice(0, 50);
  const contactedAsns = stringArray(lists?.asns).slice(0, 50);
  const finalUrl = stringValue(page?.url);
  const primaryIp = stringValue(page?.ip);
  const primaryAsn = stringValue(page?.asn);
  const malicious = overallVerdict?.malicious === true;
  const score = numberValue(overallVerdict?.score);
  const verdict = verdictFromCloudflare(malicious, score);
  const categories = extractCloudflareCategories(processors);
  const phishing = processors?.phishing;
  const radarRank = processors?.radarRank;

  const findings: string[] = [];
  findings.push(
    `Cloudflare Radar scan status: ${
      stringValue(task?.status) ?? stringValue(task?.success) ?? "unknown"
    }.`,
  );
  if (malicious) {
    findings.push("Cloudflare verdict marked the URL as malicious.");
  }
  if (finalUrl) {
    findings.push(`Final URL: ${finalUrl}.`);
  }
  if (primaryIp || primaryAsn) {
    findings.push(
      `Primary response: ${[primaryIp, primaryAsn].filter(Boolean).join(" / ")}.`,
    );
  }
  if (contactedIps.length > 0 || contactedDomains.length > 0) {
    findings.push(
      `Contacted ${contactedIps.length} IP(s) and ${contactedDomains.length} domain(s).`,
    );
  }
  if (categories.length > 0) {
    findings.push(`Cloudflare categories: ${categories.slice(0, 8).join(", ")}.`);
  }

  return makeSourceResult({
    source: "cloudflare_radar",
    indicator,
    indicatorType,
    verdict,
    score,
    keyFindings: findings,
    rawRef: {
      scan_id: scanId,
      search_url: searchUrl,
      report_url: `https://radar.cloudflare.com/scan/${scanId}`,
    },
    details: {
      scan_id: scanId,
      submitted_url: task?.url ?? null,
      final_url: finalUrl,
      primary_ip: primaryIp ?? null,
      primary_asn: primaryAsn ?? null,
      country: page?.country ?? null,
      server: page?.server ?? null,
      contacted_ips: contactedIps,
      contacted_domains: contactedDomains,
      contacted_asns: contactedAsns,
      hashes: lists?.hashes ?? null,
      certificates: lists?.certificates ?? null,
      categories,
      phishing: phishing ?? null,
      radar_rank: radarRank ?? null,
      verdicts: verdicts ?? null,
      report_url: `https://radar.cloudflare.com/scan/${scanId}`,
    },
  });
}

function normalizeSubmittedScan(
  indicator: string,
  indicatorType: IndicatorType,
  submission: CloudflareSubmitPayload,
): NormalizedSourceResult {
  const scanId = submission.uuid;
  const reportUrl = scanId ? `https://radar.cloudflare.com/scan/${scanId}` : null;

  return makeSourceResult({
    source: "cloudflare_radar",
    indicator,
    indicatorType,
    verdict: "unknown",
    score: null,
    keyFindings: [
      `Submitted Cloudflare Radar URL scan${
        scanId ? ` ${scanId}` : ""
      }; report may need polling before it is available.`,
    ],
    rawRef: {
      scan_id: scanId ?? null,
      api_url: submission.api ?? null,
      report_url: reportUrl,
      visibility: submission.visibility ?? null,
    },
    details: {
      scan_id: scanId ?? null,
      submitted_url: submission.url ?? null,
      visibility: submission.visibility ?? null,
      report_url: reportUrl,
      message: submission.message ?? null,
    },
  });
}

function buildCloudflareSearchQuery(normalized: string, lookupValue: string): string {
  if (normalized.startsWith("http://") || normalized.startsWith("https://")) {
    const quoted = quoteForSearch(normalized);
    return `task.url:${quoted} OR page.url:${quoted}`;
  }

  if (isIp(lookupValue)) {
    return `page.ip:${quoteForSearch(lookupValue)} OR ip:${quoteForSearch(
      lookupValue,
    )}`;
  }

  return `page.domain:${quoteForSearch(lookupValue)}`;
}

function toScanUrl(parsed: ReturnType<typeof parseIndicator>): string {
  if (parsed.normalized.startsWith("http://") || parsed.normalized.startsWith("https://")) {
    return parsed.normalized;
  }

  return `https://${parsed.hostname ?? parsed.normalized}`;
}

function cloudflareHeaders(env: Env): HeadersInit {
  return {
    authorization: toBearer(getCloudflareUrlScannerToken(env) ?? ""),
    accept: "application/json",
  };
}

function getCloudflareUrlScannerToken(env: Env): string | undefined {
  return env.CLOUDFLARE_URL_SCANNER_TOKEN ?? env.CLOUDFLARE_API_TOKEN;
}

function toBearer(token: string): string {
  return token.toLowerCase().startsWith("bearer ") ? token : `Bearer ${token}`;
}

function unwrapCloudflareResult<T>(data: CloudflareApiEnvelope<T> | T): T {
  if (isRecord(data) && "result" in data && data.result) {
    return data.result as T;
  }

  return data as T;
}

function verdictFromCloudflare(
  malicious: boolean,
  score: number | null,
): Verdict {
  if (malicious || (score !== null && score >= 50)) {
    return "malicious";
  }

  if (score !== null && score > 0) {
    return "suspicious";
  }

  return "unknown";
}

function extractCloudflareCategories(
  processors: Record<string, unknown> | undefined,
): string[] {
  const domainCategories = processors?.domainCategories;
  if (Array.isArray(domainCategories)) {
    return domainCategories
      .map((category) =>
        typeof category === "string" ? category : JSON.stringify(category),
      )
      .slice(0, 20);
  }

  if (isRecord(domainCategories)) {
    return Object.values(domainCategories)
      .flatMap((value) => (Array.isArray(value) ? value : [value]))
      .filter((value): value is string => typeof value === "string")
      .slice(0, 20);
  }

  return [];
}

function quoteForSearch(value: string): string {
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

function extractScanIdFromResultUrl(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }

  const match = /\/scan\/([^/?#]+)/.exec(value) ?? /\/result\/([^/?#]+)/.exec(value);
  return match?.[1];
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter((item): item is string => typeof item === "string");
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function numberValue(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return isRecord(value) ? value : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
