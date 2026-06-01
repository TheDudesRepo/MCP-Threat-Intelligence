export function cacheEnabled(env: Env): boolean {
  return env.ENABLE_CACHE?.toLowerCase() === "true" && Boolean(env.TI_CACHE);
}

export function cacheKey(source: string, input: string): string {
  return `v1:${source}:${input}`;
}

export async function getCached<T>(env: Env, key: string): Promise<T | null> {
  if (!cacheEnabled(env) || !env.TI_CACHE) {
    return null;
  }

  const cached = await env.TI_CACHE.get(key, "json");
  return cached as T | null;
}

export async function putCached<T>(
  env: Env,
  key: string,
  value: T,
): Promise<void> {
  if (!cacheEnabled(env) || !env.TI_CACHE) {
    return;
  }

  const ttl = Number.parseInt(env.CACHE_TTL_SECONDS ?? "3600", 10);
  await env.TI_CACHE.put(key, JSON.stringify(value), {
    expirationTtl: Number.isFinite(ttl) && ttl > 0 ? ttl : 3600,
  });
}

