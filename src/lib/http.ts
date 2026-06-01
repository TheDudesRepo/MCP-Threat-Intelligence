import { auditExternalQuery } from "./audit";
import type { SourceError, SourceName } from "../types";

interface FetchJsonOptions {
  source: SourceName;
  indicator: string;
  method?: string;
  headers?: HeadersInit;
  body?: BodyInit | null;
  retries?: number;
}

type FetchJsonResult<T> =
  | {
      ok: true;
      data: T;
      status: number;
      headers: Headers;
    }
  | {
      ok: false;
      error: SourceError;
      status?: number;
      headers?: Headers;
    };

const RETRYABLE_STATUSES = new Set([429, 500, 502, 503, 504]);

export async function fetchJson<T>(
  url: string,
  options: FetchJsonOptions,
): Promise<FetchJsonResult<T>> {
  const retries = options.retries ?? 2;
  const method = options.method ?? "GET";

  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      const response = await fetch(url, {
        method,
        headers: options.headers,
        body: options.body,
      });
      const text = await response.text();

      if (response.ok) {
        auditExternalQuery({
          source: options.source,
          indicator: options.indicator,
          status: "ok",
          status_code: response.status,
        });

        return {
          ok: true,
          data: parseJson<T>(text),
          status: response.status,
          headers: response.headers,
        };
      }

      if (attempt < retries && RETRYABLE_STATUSES.has(response.status)) {
        auditExternalQuery({
          source: options.source,
          indicator: options.indicator,
          status: "retry",
          status_code: response.status,
          detail: `retry ${attempt + 1} of ${retries}`,
        });
        await sleep(getRetryDelayMs(response.headers, attempt));
        continue;
      }

      auditExternalQuery({
        source: options.source,
        indicator: options.indicator,
        status: "error",
        status_code: response.status,
      });

      return {
        ok: false,
        status: response.status,
        headers: response.headers,
        error: {
          source: options.source,
          status: response.status,
          code: response.status === 429 ? "rate_limited" : "http_error",
          message: `External ${options.source} request failed with HTTP ${response.status}`,
          retry_after_seconds: getRetryAfterSeconds(response.headers),
          response_excerpt: text.slice(0, 500),
        },
      };
    } catch (error) {
      if (attempt < retries) {
        auditExternalQuery({
          source: options.source,
          indicator: options.indicator,
          status: "retry",
          detail: `network retry ${attempt + 1} of ${retries}`,
        });
        await sleep(250 * 2 ** attempt);
        continue;
      }

      auditExternalQuery({
        source: options.source,
        indicator: options.indicator,
        status: "error",
        detail: "network_error",
      });

      return {
        ok: false,
        error: {
          source: options.source,
          code: "network_error",
          message:
            error instanceof Error
              ? error.message
              : "External request failed before a response was returned",
        },
      };
    }
  }

  return {
    ok: false,
    error: {
      source: options.source,
      code: "unknown_error",
      message: "Request failed without returning a result",
    },
  };
}

function parseJson<T>(text: string): T {
  if (!text) {
    return {} as T;
  }

  return JSON.parse(text) as T;
}

function getRetryAfterSeconds(headers: Headers): number | undefined {
  const retryAfter = headers.get("retry-after");
  if (!retryAfter) {
    return undefined;
  }

  const seconds = Number.parseInt(retryAfter, 10);
  if (Number.isFinite(seconds)) {
    return seconds;
  }

  const retryDate = Date.parse(retryAfter);
  if (Number.isFinite(retryDate)) {
    return Math.max(0, Math.ceil((retryDate - Date.now()) / 1000));
  }

  return undefined;
}

function getRetryDelayMs(headers: Headers, attempt: number): number {
  const retryAfterSeconds = getRetryAfterSeconds(headers);
  if (retryAfterSeconds !== undefined) {
    return Math.min(retryAfterSeconds * 1000, 5000);
  }

  return Math.min(250 * 2 ** attempt, 2000);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

