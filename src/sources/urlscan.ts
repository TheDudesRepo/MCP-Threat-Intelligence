import { cacheKey, getCached, putCached } from "../lib/cache";
import { fetchJson } from "../lib/http";
import { isIp, parseIndicator } from "../lib/indicators";
import { errorResult, makeSourceResult, skippedResult } from "../lib/results";
import type { NormalizedSourceResult, Verdict } from "../types";

const URLSCAN_BASE_URL = "https://urlscan.io/api/v1";

interface UrlscanSearchResponse {
  total?: number;
  results?: UrlscanSearchResult[];
}

interface UrlscanSearchResult {
  _id?: string;
  task?: Record<string, unknown>;
  page?: Record<string, unknown>;
  stats?: Record<string, unknown>;
  verdicts?: Record<string, unknown>;
  result?: string;
}

interface UrlscanResultResponse {
  page?: Record<string, unknown>;
  task?: Record<string, unknown>;
  stats?: Record<string, unknown>;
  verdicts?: Record<string, unknown>;
  lists?: {
    ips?: string[];
    domains?: string[];
    urls?: string[];
  };
}

export async function lookupUrlscan(
  env: Env,
  input: string,
): Promise<NormalizedSourceResult> {
  const parsed = parseIndicator(input);
  const lookupValue = parsed.hostname ?? parsed.normalized;

  if (!env.URLSCAN_API_KEY) {
    return skippedResult(
      "urlscan",
      lookupValue,
      parsed.indicator_type,
      "urlscan.io API key is not configured; skipped.",
    );
  }

  if (
    parsed.indicator_type !== "domain" &&
    parsed.indicator_type !== "url" &&
    !isIp(lookupValue)
  ) {
    return errorResult("urlscan", lookupValue, parsed.indicator_type, {
      source: "urlscan",
      code: "invalid_indicator",
      message: "urlscan lookup requires a URL, domain, or IP address.",
    });
  }

  const key = cacheKey("urlscan", `${parsed.indicator_type}:${lookupValue}`);
  const cached = await getCached<NormalizedSourceResult>(env, key);
  if (cached) {
    return cached;
  }

  const query = buildUrlscanQuery(parsed.normalized, lookupValue);
  const searchUrl = `${URLSCAN_BASE_URL}/search/?${new URLSearchParams({
    q: query,
    size: "5",
  }).toString()}`;
  const searchResponse = await fetchJson<UrlscanSearchResponse>(searchUrl, {
    source: "urlscan",
    indicator: lookupValue,
    headers: {
      "API-Key": env.URLSCAN_API_KEY,
      accept: "application/json",
    },
  });

  if (!searchResponse.ok) {
    return errorResult(
      "urlscan",
      lookupValue,
      parsed.indicator_type,
      searchResponse.error,
    );
  }

  const results = searchResponse.data.results ?? [];
  const topResult = results[0];
  const resultId = topResult?._id;
  const resultData = resultId
    ? await fetchUrlscanResult(env, lookupValue, resultId)
    : null;
  const verdictInfo = extractVerdict(topResult, resultData);
  const screenshotUrl = resultId
    ? `https://urlscan.io/screenshots/${resultId}.png`
    : null;
  const contactedIps = resultData?.lists?.ips?.slice(0, 25) ?? [];
  const contactedDomains = resultData?.lists?.domains?.slice(0, 25) ?? [];
  const finalUrl = stringValue(resultData?.page?.url ?? topResult?.page?.url);
  const title = stringValue(resultData?.page?.title ?? topResult?.page?.title);

  const findings: string[] = [];
  findings.push(`Found ${results.length} existing urlscan result(s).`);
  if (title) {
    findings.push(`Latest page title: ${title}.`);
  }
  if (finalUrl) {
    findings.push(`Latest final URL: ${finalUrl}.`);
  }
  if (contactedIps.length > 0) {
    findings.push(`Contacted IPs include: ${contactedIps.slice(0, 8).join(", ")}.`);
  }
  if (contactedDomains.length > 0) {
    findings.push(
      `Contacted domains include: ${contactedDomains.slice(0, 8).join(", ")}.`,
    );
  }

  const result = makeSourceResult({
    source: "urlscan",
    indicator: lookupValue,
    indicatorType: parsed.indicator_type,
    verdict: verdictInfo.verdict,
    score: verdictInfo.score,
    keyFindings: findings,
    rawRef: {
      search_url: searchUrl,
      result_url: resultId ? `https://urlscan.io/result/${resultId}/` : null,
      api_url: resultId ? `${URLSCAN_BASE_URL}/result/${resultId}/` : null,
      screenshot_url: screenshotUrl,
    },
    details: {
      total: searchResponse.data.total ?? results.length,
      page_title: title,
      final_url: finalUrl,
      screenshot_url: screenshotUrl,
      contacted_ips: contactedIps,
      contacted_domains: contactedDomains,
      latest_scan_id: resultId ?? null,
      stats: resultData?.stats ?? topResult?.stats ?? null,
      verdicts: resultData?.verdicts ?? topResult?.verdicts ?? null,
    },
  });

  await putCached(env, key, result);
  return result;
}

async function fetchUrlscanResult(
  env: Env,
  indicator: string,
  id: string,
): Promise<UrlscanResultResponse | null> {
  const endpoint = `${URLSCAN_BASE_URL}/result/${encodeURIComponent(id)}/`;
  const response = await fetchJson<UrlscanResultResponse>(endpoint, {
    source: "urlscan",
    indicator,
    headers: {
      "API-Key": env.URLSCAN_API_KEY ?? "",
      accept: "application/json",
    },
  });

  if (!response.ok) {
    return null;
  }

  return response.data;
}

function buildUrlscanQuery(normalized: string, lookupValue: string): string {
  if (normalized.startsWith("http://") || normalized.startsWith("https://")) {
    const quoted = quoteForUrlscan(normalized);
    return `page.url:${quoted} OR task.url:${quoted}`;
  }

  if (isIp(lookupValue)) {
    return `ip:${lookupValue}`;
  }

  return `domain:${lookupValue}`;
}

function extractVerdict(
  searchResult: UrlscanSearchResult | undefined,
  resultData: UrlscanResultResponse | null,
): { verdict: Verdict; score: number | null } {
  const verdicts = resultData?.verdicts ?? searchResult?.verdicts;
  const overall = asRecord(verdicts?.overall);
  const urlscan = asRecord(verdicts?.urlscan);
  const source = overall ?? urlscan;
  const score = toNumber(source?.score);
  const malicious = source?.malicious === true;

  if (malicious || (score !== null && score >= 50)) {
    return { verdict: "malicious", score };
  }

  if (score !== null && score > 0) {
    return { verdict: "suspicious", score };
  }

  if (source?.malicious === false || searchResult) {
    return { verdict: "clean", score };
  }

  return { verdict: "unknown", score: null };
}

function quoteForUrlscan(value: string): string {
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function toNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object"
    ? (value as Record<string, unknown>)
    : undefined;
}

