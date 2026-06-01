import { cacheKey, getCached, putCached } from "../lib/cache";
import { fetchJson } from "../lib/http";
import { parseIndicator } from "../lib/indicators";
import { errorResult, makeSourceResult, skippedResult } from "../lib/results";
import type {
  CensysHostSummary,
  CensysServiceSummary,
  IndicatorType,
  NormalizedSourceResult,
  SourceError,
  Verdict,
} from "../types";

const CENSYS_BASE_URL = "https://api.platform.censys.io/v3/global";

interface CensysSearchResponse {
  result?: {
    hits?: unknown[];
    total?: number;
  };
}

type CensysSearchResult =
  | {
      ok: true;
      query: string;
      total: number | null;
      ips: string[];
      raw_hits: unknown[];
    }
  | {
      ok: false;
      error: SourceError;
    };

export async function lookupCensys(
  env: Env,
  input: string,
): Promise<NormalizedSourceResult> {
  const parsed = parseIndicator(input);
  const lookupValue = parsed.hostname ?? parsed.normalized;
  const token = getCensysToken(env);

  if (!token) {
    return skippedResult(
      "censys",
      lookupValue,
      parsed.indicator_type,
      "Censys Platform API token is not configured; skipped.",
    );
  }

  if (
    parsed.indicator_type !== "ip" &&
    parsed.indicator_type !== "domain" &&
    parsed.indicator_type !== "url"
  ) {
    return errorResult("censys", lookupValue, parsed.indicator_type, {
      source: "censys",
      code: "invalid_indicator",
      message: "Censys lookup requires an IP address, domain, or URL hostname.",
    });
  }

  const indicatorType =
    parsed.indicator_type === "url" ? "domain" : parsed.indicator_type;
  const key = cacheKey("censys", `${indicatorType}:${lookupValue}`);
  const cached = await getCached<NormalizedSourceResult>(env, key);
  if (cached) {
    return cached;
  }

  const result =
    indicatorType === "ip"
      ? await lookupCensysHost(env, lookupValue, lookupValue, "ip")
      : await lookupCensysDomain(env, lookupValue);

  await putCached(env, key, result);
  return result;
}

export async function findCensysSiblings(
  env: Env,
  host: CensysHostSummary,
  rootIndicator: string,
): Promise<Array<Record<string, unknown>>> {
  const token = getCensysToken(env);
  if (!token) {
    return [];
  }

  const pivots: Array<Record<string, unknown>> = [];
  const hostIp = host.ip;
  const jarm = host.jarm_fingerprints[0];
  const cert = host.certificate_fingerprints[0];

  if (jarm) {
    const query = `host.services.jarm.fingerprint: "${jarm}"`;
    const search = await searchCensysHosts(env, query, 5, rootIndicator);
    if (search.ok) {
      pivots.push({
        pivot_type: "jarm",
        pivot_value: jarm,
        query,
        related_ips: excludeSelf(search.ips, hostIp),
        total: search.total,
      });
    }
  }

  if (cert) {
    const query = `host.services.tls.certificates.leaf_data.fingerprint_sha256: "${cert}"`;
    const search = await searchCensysHosts(env, query, 5, rootIndicator);
    if (search.ok) {
      pivots.push({
        pivot_type: "certificate_sha256",
        pivot_value: cert,
        query,
        related_ips: excludeSelf(search.ips, hostIp),
        total: search.total,
      });
    }
  }

  return pivots;
}

export function getCensysHostSummary(
  result: NormalizedSourceResult,
): CensysHostSummary | null {
  const summary = result.details?.host_summary;
  return isRecord(summary) ? (summary as unknown as CensysHostSummary) : null;
}

async function lookupCensysDomain(
  env: Env,
  domain: string,
): Promise<NormalizedSourceResult> {
  const query = `host.names: "${domain}"`;
  const search = await searchCensysHosts(env, query, 5, domain);

  if (!search.ok) {
    return errorResult("censys", domain, "domain", search.error);
  }

  const firstIp = search.ips[0];
  if (!firstIp) {
    return makeSourceResult({
      source: "censys",
      indicator: domain,
      indicatorType: "domain",
      verdict: "unknown",
      score: null,
      keyFindings: [
        "Censys search completed but did not return a host IP for this domain.",
      ],
      rawRef: {
        endpoint: `${CENSYS_BASE_URL}/search/query`,
        query,
      },
      details: {
        search_total: search.total,
        search_hits: search.raw_hits.slice(0, 5),
      },
    });
  }

  return lookupCensysHost(env, firstIp, domain, "domain", {
    domain_search_query: query,
    domain_search_total: search.total,
    matched_ips: search.ips,
  });
}

async function lookupCensysHost(
  env: Env,
  ip: string,
  displayIndicator: string,
  indicatorType: IndicatorType,
  extraDetails: Record<string, unknown> = {},
): Promise<NormalizedSourceResult> {
  const endpoint = addOrgId(
    env,
    `${CENSYS_BASE_URL}/asset/host/${encodeURIComponent(ip)}`,
  );
  const token = getCensysToken(env);
  const response = await fetchJson<Record<string, unknown>>(endpoint, {
    source: "censys",
    indicator: displayIndicator,
    headers: {
      authorization: toBearer(token ?? ""),
      accept: "application/json",
    },
  });

  if (!response.ok) {
    return errorResult("censys", displayIndicator, indicatorType, response.error);
  }

  const resource = extractResource(response.data);
  const summary = summarizeHost(resource);
  const { verdict, score } = verdictFromCensys(summary);
  const findings = buildCensysFindings(summary);

  return makeSourceResult({
    source: "censys",
    indicator: displayIndicator,
    indicatorType,
    verdict,
    score,
    keyFindings: findings,
    rawRef: {
      endpoint,
      host_ip: summary.ip ?? ip,
    },
    details: {
      ...extraDetails,
      host_summary: summary,
    },
  });
}

async function searchCensysHosts(
  env: Env,
  query: string,
  pageSize: number,
  auditIndicator: string,
): Promise<CensysSearchResult> {
  const endpoint = addOrgId(env, `${CENSYS_BASE_URL}/search/query`);
  const token = getCensysToken(env);
  const response = await fetchJson<CensysSearchResponse>(endpoint, {
    source: "censys",
    indicator: auditIndicator,
    method: "POST",
    headers: {
      authorization: toBearer(token ?? ""),
      accept: "application/json",
      "content-type": "application/json",
    },
    body: JSON.stringify({
      query,
      page_size: pageSize,
      fields: [
        "host.ip",
        "host.names",
        "host.services.port",
        "host.services.protocol",
        "host.services.transport_protocol",
      ],
    }),
  });

  if (!response.ok) {
    return {
      ok: false,
      error: response.error,
    };
  }

  const hits = response.data.result?.hits ?? [];
  return {
    ok: true,
    query,
    total:
      typeof response.data.result?.total === "number"
        ? response.data.result.total
        : null,
    ips: collectIps(hits),
    raw_hits: hits,
  };
}

function summarizeHost(resource: Record<string, unknown>): CensysHostSummary {
  const services = getServices(resource);
  const serviceSummaries = services.map(summarizeService);
  const openPorts = uniqueNumbers(
    serviceSummaries
      .map((service) => service.port)
      .filter((port): port is number => typeof port === "number"),
  );
  const tlsCertificates = services
    .map(extractTlsCertificate)
    .filter((cert): cert is Record<string, unknown> => cert !== null);
  const jarmFingerprints = collectStringsByKey(
    resource,
    (key, value) => key.includes("jarm") && /^[a-f0-9]{62}$/i.test(value),
  ).slice(0, 10);
  const certificateFingerprints = collectStringsByKey(
    resource,
    (key, value) =>
      key.includes("fingerprint") &&
      /^[a-f0-9]{64}$/i.test(value),
  ).slice(0, 10);
  const autonomousSystem = isRecord(resource.autonomous_system)
    ? resource.autonomous_system
    : undefined;
  const location = isRecord(resource.location) ? resource.location : undefined;

  return {
    ip: stringValue(resource.ip),
    open_ports: openPorts,
    services: serviceSummaries,
    tls_certificates: tlsCertificates,
    jarm_fingerprints: jarmFingerprints,
    certificate_fingerprints: certificateFingerprints,
    asn: numberValue(autonomousSystem?.asn),
    as_name:
      stringValue(autonomousSystem?.name) ??
      stringValue(autonomousSystem?.description),
    geolocation: location,
    labels: collectLabelLike(resource, "label"),
    threats: collectLabelLike(resource, "threat"),
  };
}

function buildCensysFindings(summary: CensysHostSummary): string[] {
  const findings: string[] = [];

  if (summary.open_ports.length > 0) {
    findings.push(
      `Observed open ports: ${summary.open_ports.slice(0, 20).join(", ")}.`,
    );
  }

  const namedServices = summary.services
    .slice(0, 8)
    .map((service) => {
      const proto =
        service.service_name ?? service.protocol ?? service.transport_protocol;
      return `${service.port ?? "unknown"}/${proto ?? "unknown"}`;
    });
  if (namedServices.length > 0) {
    findings.push(`Services include: ${namedServices.join(", ")}.`);
  }

  if (summary.asn || summary.as_name) {
    findings.push(
      `ASN: ${summary.asn ? `AS${summary.asn}` : "unknown"} ${
        summary.as_name ?? ""
      }.`.trim(),
    );
  }

  const country = stringValue(summary.geolocation?.country);
  const city = stringValue(summary.geolocation?.city);
  if (country || city) {
    findings.push(`Geolocation: ${[city, country].filter(Boolean).join(", ")}.`);
  }

  if (summary.tls_certificates.length > 0) {
    const cert = summary.tls_certificates[0];
    findings.push(
      `TLS certificate observed: subject=${
        stringValue(cert?.subject_dn ?? cert?.subject) ?? "unknown"
      }, issuer=${stringValue(cert?.issuer_dn ?? cert?.issuer) ?? "unknown"}.`,
    );
  }

  if (summary.jarm_fingerprints.length > 0) {
    findings.push(`JARM: ${summary.jarm_fingerprints[0]}.`);
  }

  if (summary.threats.length > 0) {
    findings.push(`Threat labels: ${summary.threats.slice(0, 8).join(", ")}.`);
  } else if (summary.labels.length > 0) {
    findings.push(`Labels: ${summary.labels.slice(0, 8).join(", ")}.`);
  }

  return findings;
}

function verdictFromCensys(summary: CensysHostSummary): {
  verdict: Verdict;
  score: number | null;
} {
  const highSignal = [...summary.threats, ...summary.labels].some((label) =>
    /(?:malware|botnet|c2|command|phish|bulletproof|sinkhole)/i.test(label),
  );

  if (highSignal) {
    return { verdict: "suspicious", score: 70 };
  }

  if (summary.services.length > 0) {
    return { verdict: "unknown", score: null };
  }

  return { verdict: "unknown", score: null };
}

function getServices(resource: Record<string, unknown>): Record<string, unknown>[] {
  const direct = Array.isArray(resource.services) ? resource.services : null;
  const nestedHost = isRecord(resource.host) ? resource.host : undefined;
  const nested = Array.isArray(nestedHost?.services)
    ? nestedHost.services
    : null;
  const services = direct ?? nested ?? [];

  return services.filter(isRecord);
}

function summarizeService(service: Record<string, unknown>): CensysServiceSummary {
  return {
    port: numberValue(service.port ?? service.port_number),
    protocol: stringValue(service.protocol),
    transport_protocol: stringValue(service.transport_protocol),
    service_name:
      stringValue(service.service_name) ??
      stringValue(service.extended_service_name) ??
      stringValue(service.name),
    observed_at: stringValue(service.observed_at),
  };
}

function extractTlsCertificate(
  service: Record<string, unknown>,
): Record<string, unknown> | null {
  const tls = isRecord(service.tls) ? service.tls : undefined;
  const certificates = isRecord(tls?.certificates) ? tls.certificates : undefined;
  const leaf =
    asRecord(certificates?.leaf_data) ??
    asRecord(certificates?.leaf) ??
    asRecord(service.certificate);

  if (!leaf) {
    return null;
  }

  return {
    subject_dn: leaf.subject_dn ?? leaf.subject,
    issuer_dn: leaf.issuer_dn ?? leaf.issuer,
    names: leaf.names ?? leaf.subject_alt_names,
    fingerprint_sha256:
      leaf.fingerprint_sha256 ?? leaf.sha256_fingerprint ?? leaf.fingerprint,
    not_before: leaf.not_before,
    not_after: leaf.not_after,
  };
}

function extractResource(data: Record<string, unknown>): Record<string, unknown> {
  const result = isRecord(data.result) ? data.result : undefined;
  return (
    asRecord(result?.resource) ??
    asRecord(data.resource) ??
    result ??
    data
  );
}

function collectIps(value: unknown): string[] {
  const ips = collectStringsByKey(value, (_key, item) => isIpv4(item));
  return [...new Set(ips)];
}

function collectStringsByKey(
  value: unknown,
  predicate: (key: string, value: string) => boolean,
  found = new Set<string>(),
): string[] {
  if (Array.isArray(value)) {
    for (const item of value) {
      collectStringsByKey(item, predicate, found);
    }
    return [...found];
  }

  if (!isRecord(value)) {
    return [...found];
  }

  for (const [key, child] of Object.entries(value)) {
    const normalizedKey = key.toLowerCase();
    if (typeof child === "string" && predicate(normalizedKey, child)) {
      found.add(child);
    }
    collectStringsByKey(child, predicate, found);
  }

  return [...found];
}

function collectLabelLike(
  value: unknown,
  keyFragment: "label" | "threat",
  found = new Set<string>(),
): string[] {
  if (Array.isArray(value)) {
    for (const item of value) {
      if (typeof item === "string") {
        found.add(item);
      } else if (isRecord(item)) {
        const valueField = stringValue(item.value) ?? stringValue(item.name);
        if (valueField) {
          found.add(valueField);
        }
        collectLabelLike(item, keyFragment, found);
      }
    }
    return [...found];
  }

  if (!isRecord(value)) {
    return [...found];
  }

  for (const [key, child] of Object.entries(value)) {
    if (key.toLowerCase().includes(keyFragment)) {
      collectLabelLike(child, keyFragment, found);
    } else if (isRecord(child) || Array.isArray(child)) {
      collectLabelLike(child, keyFragment, found);
    }
  }

  return [...found].slice(0, 25);
}

function getCensysToken(env: Env): string | undefined {
  return (
    env.CENSYS_API_TOKEN ??
    env.CENSYS_PLATFORM_TOKEN ??
    env.CENSYS_API_SECRET
  );
}

function toBearer(token: string): string {
  return token.toLowerCase().startsWith("bearer ") ? token : `Bearer ${token}`;
}

function addOrgId(env: Env, endpoint: string): string {
  const url = new URL(endpoint);
  if (env.CENSYS_ORG_ID) {
    url.searchParams.set("organization_id", env.CENSYS_ORG_ID);
  }
  return url.toString();
}

function excludeSelf(ips: string[], self: string | undefined): string[] {
  return ips.filter((ip) => ip !== self);
}

function uniqueNumbers(values: number[]): number[] {
  return [...new Set(values)].sort((a, b) => a - b);
}

function isIpv4(value: string): boolean {
  const parts = value.split(".");
  if (parts.length !== 4) {
    return false;
  }

  return parts.every((part) => {
    const num = Number.parseInt(part, 10);
    return /^\d{1,3}$/.test(part) && num >= 0 && num <= 255;
  });
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function numberValue(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return isRecord(value) ? value : undefined;
}

