import type { IndicatorType, ParsedIndicator } from "../types";

const HASH_RE = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i;
const DOMAIN_LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

export function refangIndicator(input: string): string {
  let value = input.trim();

  value = value.replace(/^[<"']+|[>"']+$/g, "");
  value = value.replace(/^hxxps?/i, (match) =>
    match.toLowerCase() === "hxxps" ? "https" : "http",
  );
  value = value.replace(/\[\s*(?:\.|dot)\s*\]/gi, ".");
  value = value.replace(/\(\s*(?:\.|dot)\s*\)/gi, ".");
  value = value.replace(/\{\s*(?:\.|dot)\s*\}/gi, ".");
  value = value.replace(/\[\s*:\s*\]|\(\s*:\s*\)|\{\s*:\s*\}/g, ":");
  value = value.replace(/\\\//g, "/");

  return value.trim();
}

export function parseIndicator(input: string): ParsedIndicator {
  const refanged = refangIndicator(input);
  const maybeUrl = parseUrl(refanged);

  if (maybeUrl) {
    return {
      original: input,
      normalized: maybeUrl.toString(),
      indicator_type: "url",
      hostname: maybeUrl.hostname.toLowerCase(),
    };
  }

  const lower = refanged.toLowerCase();

  if (HASH_RE.test(lower)) {
    return {
      original: input,
      normalized: lower,
      indicator_type: "file_hash",
    };
  }

  if (isIp(refanged)) {
    return {
      original: input,
      normalized: refanged,
      indicator_type: "ip",
    };
  }

  const domain = normalizeDomain(refanged);
  if (domain) {
    return {
      original: input,
      normalized: domain,
      indicator_type: "domain",
      hostname: domain,
    };
  }

  return {
    original: input,
    normalized: refanged,
    indicator_type: "unknown",
  };
}

export function detectIndicatorType(input: string): IndicatorType {
  return parseIndicator(input).indicator_type;
}

export function isIp(input: string): boolean {
  return isIpv4(input) || isLikelyIpv6(input);
}

export function normalizeDomain(input: string): string | null {
  const value = input.trim().replace(/\.$/, "").toLowerCase();
  const labels = value.split(".");

  if (labels.length < 2 || value.length > 253) {
    return null;
  }

  if (!labels.every((label) => DOMAIN_LABEL_RE.test(label))) {
    return null;
  }

  const tld = labels[labels.length - 1];
  if (!tld || /^\d+$/.test(tld)) {
    return null;
  }

  return value;
}

function parseUrl(input: string): URL | null {
  try {
    const url = new URL(input);
    if (url.protocol === "http:" || url.protocol === "https:") {
      return url;
    }
  } catch {
    // Fall through to the no-scheme URL case.
  }

  if (/^[^/\s]+\.[^/\s]+\/.+/.test(input)) {
    try {
      const url = new URL(`http://${input}`);
      if (normalizeDomain(url.hostname) || isIp(url.hostname)) {
        return url;
      }
    } catch {
      return null;
    }
  }

  return null;
}

function isIpv4(input: string): boolean {
  const parts = input.split(".");
  if (parts.length !== 4) {
    return false;
  }

  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) {
      return false;
    }

    const value = Number.parseInt(part, 10);
    return value >= 0 && value <= 255 && String(value) === part;
  });
}

function isLikelyIpv6(input: string): boolean {
  return (
    input.includes(":") &&
    /^[a-f0-9:]+$/i.test(input) &&
    input.split(":").filter(Boolean).length >= 2
  );
}

