/**
 * One-off helper: build the signed client-assertion JWT (and exchange it for an
 * access token) from the local gitignored sandbox fixture, writing both to
 * gitignored files. Run with:
 *   node --experimental-strip-types scripts/dump-jwt.ts
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  type NetsuiteTokenParams,
  type TokenRequest,
  type TokenSendResult,
  buildAssertion,
  exchangeToken,
} from "../src/netsuite.ts";

const root = process.cwd();
const fixture = JSON.parse(
  readFileSync(join(root, "test-fixtures", "netsuite-sandbox.json"), "utf8"),
) as NetsuiteTokenParams;

async function fetchSender(req: TokenRequest): Promise<TokenSendResult> {
  const res = await fetch(req.url, {
    method: req.method,
    headers: req.headers,
    body: req.body,
  });
  return { status: res.status, body: await res.text() };
}

const now = Date.now();
const assertion = await buildAssertion(fixture, now);
const assertionPath = join(root, "test-fixtures", "assertion.jwt");
writeFileSync(assertionPath, `${assertion}\n`);
console.log(`wrote signed client-assertion JWT → ${assertionPath} (${assertion.length} chars)`);

const minted = await exchangeToken(fixture, fetchSender, now);
const tokenPath = join(root, "test-fixtures", "access-token.txt");
writeFileSync(tokenPath, `${minted.accessToken}\n`);
console.log(
  `wrote access token → ${tokenPath} (expires_in=${minted.expiresIn}s, ${minted.accessToken.length} chars)`,
);
