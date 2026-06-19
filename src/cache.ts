/**
 * In-memory token cache for the NetSuite token template functions.
 *
 * The cache lives at module scope (the plugin instance is long-lived), keyed by
 * the non-secret identifying inputs. Tokens are never persisted to disk.
 */
import { createHash } from "node:crypto";

/** Seconds of skew subtracted from the token lifetime so we re-mint early. */
export const EXPIRY_SKEW_SECONDS = 60;

interface CacheEntry {
  accessToken: string;
  /** Absolute expiry, ms since epoch. */
  expiresAt: number;
}

/** Fields used to build the cache key. Deliberately excludes `privateKey`. */
export interface CacheKeyParams {
  accountId: string;
  clientId: string;
  certId: string;
  scope: string;
  algorithm: string;
}

const store = new Map<string, CacheEntry>();

/**
 * Build a stable cache key from the non-secret identifying fields. A plain
 * delimited join is sufficient — no secret material is included, so no hashing
 * is needed. The unit separator (\x1f) avoids ambiguity between field values.
 */
export function cacheKey(params: CacheKeyParams): string {
  return [
    params.accountId,
    params.clientId,
    params.certId,
    params.scope,
    params.algorithm,
  ].join("\x1f");
}

/**
 * Cache key for the exchange-only flow, where the input *is* the signed
 * assertion. The assertion is a bearer credential, so it is hashed (sha256)
 * rather than held verbatim as a map key. Different account or assertion →
 * different key.
 */
export function exchangeCacheKey(accountId: string, assertion: string): string {
  const digest = createHash("sha256").update(assertion).digest("hex");
  return ["exchange", accountId, digest].join("\x1f");
}

/** Return the cached token if present and not yet expired (relative to `now`). */
export function getCached(key: string, now: number): string | null {
  const entry = store.get(key);
  if (entry == null) return null;
  if (now >= entry.expiresAt) {
    store.delete(key);
    return null;
  }
  return entry.accessToken;
}

/**
 * Cache a freshly minted token. `expiresAt = now + max(0, expiresIn - skew)`.
 * The `max(0, …)` guard keeps a degenerate `expires_in < skew` from producing a
 * negative TTL (such an entry is simply treated as already-expired on read).
 */
export function setCached(
  key: string,
  accessToken: string,
  expiresIn: number,
  now: number,
): void {
  const ttlSeconds = Math.max(0, expiresIn - EXPIRY_SKEW_SECONDS);
  store.set(key, { accessToken, expiresAt: now + ttlSeconds * 1000 });
}

/** Clear all cached entries. Intended for tests. */
export function clearCache(): void {
  store.clear();
}
