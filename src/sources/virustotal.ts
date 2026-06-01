import { cacheKey, getCached, putCached } from "../lib/cache";
import { fetchJson } from "../lib/http";
import { parseIndicator } from "../lib/indicators";
import { errorResult, makeSourceResult, skippedResult, verdictFromStats } from "../lib/results";
import type { IndicatorType, NormalizedSourceResult } from "../types";

const VT_BASE_URL = "https://www.virustotal.com/api/v3";

interface VirusTotalObjectResponse {
  data?: {
    id?: string;
    type?: string;
    links?: {
      self?: string;
    };
    attributes?: Record<string, unknown>;
  };
}

interface VirusTotalCollectionResponse {
  data?: Array<{
    id?: string;
    type?: string;
    attributes?: Record<string, unknown>;
    links?: {
      self?: string;
    };
  }>;
  meta?: Record<string, unknown>;
  links?: Record<string, unknown>;
}

export async function lookupVirusTotal(
  env: Env,
  input: string,
): Promise<NormalizedSourceResult> {
  const parsed = parseIndicator(input);

  if (!env.VT_API_KEY) {
    return skippedResult(
      "virustotal",
      parsed.normalized,
      parsed.indicator_type,
      "VirusTotal API key is not configured; skipped.",
    );
  }

  if (parsed.indicator_type === "unknown") {
    return errorResult("virustotal", parsed.normalized, "unknown", {
      source: "virustotal",
      code: "invalid_indicator",
      message: "VirusTotal lookup requires a domain, IP, URL, or file hash.",
    });
  }

  const key = cacheKey(
    "virustotal",
    `${parsed.indicator_type}:${parsed.normalized}`,
  );
  const cached = await getCached<NormalizedSourceResult>(env, key);
  if (cached) {
    return cached;
  }

  const endpoint = buildVirusTotalEndpoint(
    parsed.indicator_type,
    parsed.normalized,
  );
  const response = await fetchJson<VirusTotalObjectResponse>(endpoint, {
    source: "virustotal",
    indicator: parsed.normalized,
    headers: {
      "x-apikey": env.VT_API_KEY,
      accept: "application/json",
    },
  });

  if (!response.ok) {
    return errorResult(
      "virustotal",
      parsed.normalized,
      parsed.indicator_type,
      response.error,
    );
  }

  const attributes = response.data.data?.attributes ?? {};
  const resolutions =
    parsed.indicator_type === "domain"
      ? await fetchDomainResolutions(env, parsed.normalized)
      : [];
  const stats = asRecord(attributes.last_analysis_stats);
  const { verdict, score } = verdictFromStats(stats);
  const vendorDetections = extractVendorDetections(
    asRecord(attributes.last_analysis_results),
  );
  const categories = asStringRecord(attributes.categories);
  const keyFindings = buildVirusTotalFindings(
    attributes,
    vendorDetections,
    categories,
    resolutions,
  );

  const result = makeSourceResult({
    source: "virustotal",
    indicator: parsed.normalized,
    indicatorType: parsed.indicator_type,
    verdict,
    score,
    keyFindings,
    rawRef: {
      endpoint,
      id: response.data.data?.id,
      self: response.data.data?.links?.self,
    },
    details: {
      reputation: attributes.reputation ?? null,
      last_analysis_stats: stats ?? null,
      vendor_detections: vendorDetections,
      categories,
      resolutions,
      asn: attributes.asn ?? null,
      as_owner: attributes.as_owner ?? null,
      country: attributes.country ?? null,
      jarm: attributes.jarm ?? null,
    },
  });

  await putCached(env, key, result);
  return result;
}

function buildVirusTotalEndpoint(type: IndicatorType, value: string): string {
  switch (type) {
    case "domain":
      return `${VT_BASE_URL}/domains/${encodeURIComponent(value)}`;
    case "ip":
      return `${VT_BASE_URL}/ip_addresses/${encodeURIComponent(value)}`;
    case "url":
      return `${VT_BASE_URL}/urls/${encodeURIComponent(base64Url(value))}`;
    case "file_hash":
      return `${VT_BASE_URL}/files/${encodeURIComponent(value)}`;
    default:
      throw new Error(`Unsupported VirusTotal indicator type: ${type}`);
  }
}

async function fetchDomainResolutions(
  env: Env,
  domain: string,
): Promise<Array<Record<string, unknown>>> {
  const endpoint = `${VT_BASE_URL}/domains/${encodeURIComponent(
    domain,
  )}/resolutions?limit=10`;
  const response = await fetchJson<VirusTotalCollectionResponse>(endpoint, {
    source: "virustotal",
    indicator: domain,
    headers: {
      "x-apikey": env.VT_API_KEY ?? "",
      accept: "application/json",
    },
  });

  if (!response.ok) {
    return [];
  }

  return (response.data.data ?? []).map((item) => ({
    ip_address: item.attributes?.ip_address,
    host_name: item.attributes?.host_name,
    date: item.attributes?.date,
    resolver: item.attributes?.resolver,
  }));
}

function extractVendorDetections(
  results: Record<string, unknown> | undefined,
): Array<Record<string, unknown>> {
  if (!results) {
    return [];
  }

  return Object.entries(results)
    .flatMap(([vendor, raw]) => {
      const result = asRecord(raw);
      const category = String(result?.category ?? "");
      if (category !== "malicious" && category !== "suspicious") {
        return [];
      }

      return [
        {
          vendor,
          category,
          result: result?.result ?? null,
          method: result?.method ?? null,
        },
      ];
    })
    .slice(0, 12);
}

function buildVirusTotalFindings(
  attributes: Record<string, unknown>,
  vendorDetections: Array<Record<string, unknown>>,
  categories: Record<string, string>,
  resolutions: Array<Record<string, unknown>>,
): string[] {
  const findings: string[] = [];
  const stats = asRecord(attributes.last_analysis_stats);
  if (stats) {
    findings.push(
      `Analysis stats: malicious=${stats.malicious ?? 0}, suspicious=${
        stats.suspicious ?? 0
      }, harmless=${stats.harmless ?? 0}.`,
    );
  }

  if (typeof attributes.reputation === "number") {
    findings.push(`Community reputation score: ${attributes.reputation}.`);
  }

  if (vendorDetections.length > 0) {
    findings.push(
      `Flagged by ${vendorDetections.length} vendor(s): ${vendorDetections
        .slice(0, 5)
        .map((detection) => detection.vendor)
        .join(", ")}.`,
    );
  }

  const categoryValues = Array.from(new Set(Object.values(categories))).slice(
    0,
    5,
  );
  if (categoryValues.length > 0) {
    findings.push(`Categories: ${categoryValues.join(", ")}.`);
  }

  const resolvedIps = Array.from(
    new Set(
      resolutions
        .map((resolution) => resolution.ip_address)
        .filter((ip): ip is string => typeof ip === "string"),
    ),
  );
  if (resolvedIps.length > 0) {
    findings.push(`Recent domain resolutions: ${resolvedIps.join(", ")}.`);
  }

  return findings;
}

function base64Url(input: string): string {
  const bytes = new TextEncoder().encode(input);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/g, "");
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object"
    ? (value as Record<string, unknown>)
    : undefined;
}

function asStringRecord(value: unknown): Record<string, string> {
  const record = asRecord(value);
  if (!record) {
    return {};
  }

  return Object.fromEntries(
    Object.entries(record).filter(
      (entry): entry is [string, string] => typeof entry[1] === "string",
    ),
  );
}

