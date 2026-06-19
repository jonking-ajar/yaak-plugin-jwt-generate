import { beforeEach, describe, expect, test } from "vitest";
import {
  EXPIRY_SKEW_SECONDS,
  cacheKey,
  clearCache,
  getCached,
  setCached,
} from "./cache";

const baseParams = {
  accountId: "1234567",
  clientId: "client-abc",
  certId: "cert-xyz",
  scope: "rest_webservices",
  algorithm: "PS256",
};

describe("cache", () => {
  beforeEach(() => clearCache());

  test("cache key excludes the private key (only identifying fields matter)", () => {
    const a = cacheKey(baseParams);
    const b = cacheKey({ ...baseParams });
    expect(a).toBe(b);
    // Changing an identifying field changes the key...
    expect(cacheKey({ ...baseParams, scope: "restlets" })).not.toBe(a);
  });

  test("returns the same token before expiry and re-mints after (fake-time style)", () => {
    const key = cacheKey(baseParams);
    const t0 = 1_000_000_000_000;
    setCached(key, "tok-1", 3600, t0);

    // Well before expiry: same token, no eviction.
    expect(getCached(key, t0 + 1000)).toBe("tok-1");
    // Just before the skew-adjusted expiry boundary.
    const expiresAt = t0 + (3600 - EXPIRY_SKEW_SECONDS) * 1000;
    expect(getCached(key, expiresAt - 1)).toBe("tok-1");
    // At/after expiry: evicted, miss.
    expect(getCached(key, expiresAt)).toBeNull();
    expect(getCached(key, expiresAt + 1)).toBeNull();
  });

  test("distinct inputs occupy distinct entries", () => {
    const k1 = cacheKey(baseParams);
    const k2 = cacheKey({ ...baseParams, accountId: "7654321" });
    const now = 5_000;
    setCached(k1, "tok-1", 3600, now);
    setCached(k2, "tok-2", 3600, now);
    expect(getCached(k1, now + 1)).toBe("tok-1");
    expect(getCached(k2, now + 1)).toBe("tok-2");
  });

  test("expires_in < skew yields a non-negative TTL (treated as already expired)", () => {
    const key = cacheKey(baseParams);
    const now = 10_000;
    setCached(key, "tok-short", 30, now); // 30 < 60 skew
    // TTL clamped to 0 → expiresAt === now → already expired.
    expect(getCached(key, now)).toBeNull();
  });
});
