/**
 * Live smoke tests against a real NetSuite sandbox (§5 Manual/smoke #2).
 *
 * These are gated on a local, gitignored credentials fixture and are SKIPPED
 * when it is absent — so the offline suite and CI stay green and no secret is
 * ever committed. To run them, create `test-fixtures/netsuite-sandbox.json`:
 *
 * {
 *   "accountId": "1234567_SB1",
 *   "clientId": "<consumer key>",
 *   "certId": "<cert mapping id>",
 *   "privateKey": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
 *   "scope": "rest_webservices",
 *   "algorithm": "PS256",
 *   "restProbePath": "/services/rest/record/v1/metadata-catalog"
 * }
 *
 * Then: `pnpm vitest run src/netsuite.live.test.ts`
 *
 * The private key, signed assertion, and token are never logged.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { beforeAll, describe, expect, test } from "vitest";
import {
  type NetsuiteTokenParams,
  type NsAlgorithm,
  type TokenRequest,
  type TokenSendResult,
  audUrl,
  exchangeToken,
} from "./netsuite";

const FIXTURE_PATH = join(
  process.cwd(),
  "test-fixtures",
  "netsuite-sandbox.json",
);

interface Fixture extends NetsuiteTokenParams {
  algorithm: NsAlgorithm;
  restProbePath?: string;
}

const hasFixture = existsSync(FIXTURE_PATH);
const fixture: Fixture | null = hasFixture
  ? (JSON.parse(readFileSync(FIXTURE_PATH, "utf8")) as Fixture)
  : null;

/** Real fetch-backed sender (same shape index.ts wires for production). */
async function fetchSender(req: TokenRequest): Promise<TokenSendResult> {
  const res = await fetch(req.url, {
    method: req.method,
    headers: req.headers,
    body: req.body,
  });
  return { status: res.status, body: await res.text() };
}

describe.skipIf(!hasFixture)("NetSuite live sandbox", () => {
  if (fixture == null) return; // type narrowing; never reached when skipped

  const params: NetsuiteTokenParams = {
    accountId: fixture.accountId,
    clientId: fixture.clientId,
    certId: fixture.certId,
    privateKey: fixture.privateKey,
    scope: fixture.scope || "rest_webservices",
    algorithm: fixture.algorithm || "PS256",
  };

  let accessToken: string;

  // ni-0: mint a real, working access token end-to-end.
  test("mints a real access token against the live token endpoint", async () => {
    const minted = await exchangeToken(params, fetchSender, Date.now());
    expect(typeof minted.accessToken).toBe("string");
    expect(minted.accessToken.length).toBeGreaterThan(0);
    expect(minted.expiresIn).toBeGreaterThan(0);
    accessToken = minted.accessToken;
  }, 30_000);

  // ni-1: the minted token authorizes a real REST API call.
  test.skipIf(!fixture.restProbePath)(
    "minted token authorizes a real NetSuite REST call",
    async () => {
      expect(accessToken, "ni-0 must mint a token first").toBeTruthy();
      const host = params.accountId.toLowerCase().replace(/_/g, "-");
      const url = `https://${host}.suitetalk.api.netsuite.com${fixture.restProbePath}`;
      const res = await fetch(url, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      // 401/403 here indicates a fixture credential/scope misconfiguration,
      // not a plugin bug.
      expect(res.status).toBeLessThan(300);
    },
    30_000,
  );

  // Sanity: the token host derives from the account id as documented.
  beforeAll(() => {
    expect(audUrl(params.accountId)).toContain(".suitetalk.api.netsuite.com");
  });
});
