/**
 * Pure, testable core for the NetSuite OAuth 2.0 client-credentials
 * (JWT-bearer) flow: build a signed client-assertion JWT and exchange it for an
 * access token. No Yaak or environment dependencies live here — the network is
 * injected via the `TokenSender` abstraction.
 */
import { SignJWT, importPKCS8 } from "jose";

export type NsAlgorithm = "PS256" | "ES256";

/** Backdate `iat` to absorb clock drift between the host and NetSuite. */
export const IAT_SKEW_SECONDS = 30;
/** NetSuite caps the assertion lifetime at 60 minutes. */
export const ASSERTION_TTL_SECONDS = 3600;

export interface NetsuiteTokenParams {
  accountId: string;
  clientId: string;
  certId: string;
  /** PKCS#8 PEM. May contain literal `\n` escapes (normalized before use). */
  privateKey: string;
  /** Already defaulted upstream; passed through verbatim (may be multi-scope). */
  scope: string;
  algorithm: NsAlgorithm;
}

/** Transport request shape handed to a `TokenSender`. */
export interface TokenRequest {
  url: string;
  method: "POST";
  headers: Record<string, string>;
  /** url-encoded form body. */
  body: string;
}

export interface TokenSendResult {
  status: number;
  /** Raw response body text. */
  body: string;
}

/** Injected transport — `index.ts` wires a `fetch`-based implementation. */
export type TokenSender = (req: TokenRequest) => Promise<TokenSendResult>;

export interface MintedToken {
  accessToken: string;
  /** Seconds, from NetSuite's `expires_in`. */
  expiresIn: number;
}

/**
 * Error thrown when the token exchange fails. `message` is safe to surface to
 * the user — it never contains the private key or the signed assertion.
 */
export class TokenExchangeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TokenExchangeError";
  }
}

/**
 * Build the SuiteTalk REST `aud`/token URL for an account id. The host segment
 * is the lowercased account id with `_` replaced by `-`
 * (e.g. `1234567_SB1` → `1234567-sb1`).
 */
export function audUrl(accountId: string): string {
  const host = accountId.toLowerCase().replace(/_/g, "-");
  return `https://${host}.suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/token`;
}

/** Normalize a pasted PEM: convert literal `\n` escapes to real newlines. */
export function normalizePem(pem: string): string {
  return pem.replace(/\\n/g, "\n");
}

/**
 * Build and sign the client-assertion JWT. `now` is ms since epoch (injectable
 * for tests). Throws if the key cannot be imported or signed (e.g. the key type
 * does not match `algorithm`).
 */
export async function buildAssertion(
  params: NetsuiteTokenParams,
  now: number,
): Promise<string> {
  const nowSeconds = Math.floor(now / 1000);
  const iat = nowSeconds - IAT_SKEW_SECONDS;
  const exp = iat + ASSERTION_TTL_SECONDS;
  const aud = audUrl(params.accountId);

  const key = await importPKCS8(normalizePem(params.privateKey), params.algorithm);

  return new SignJWT({ scope: params.scope })
    .setProtectedHeader({ alg: params.algorithm, typ: "JWT", kid: params.certId })
    .setIssuer(params.clientId)
    .setAudience(aud)
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .sign(key);
}

/** The form fields required by the NetSuite token endpoint. */
function buildFormBody(assertion: string): string {
  const form = new URLSearchParams();
  form.set("grant_type", "client_credentials");
  form.set(
    "client_assertion_type",
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
  );
  form.set("client_assertion", assertion);
  return form.toString();
}

/**
 * Exchange an already-signed client-assertion JWT for an access token: POST it
 * to the account's token endpoint via `send` and parse the response. Throws
 * `TokenExchangeError` (safe message) on non-2xx or a malformed body.
 *
 * The assertion carries its own `scope`/`iss`/`exp`; only `accountId` is needed
 * here to build the token URL host.
 */
export async function exchangeAssertion(
  accountId: string,
  assertion: string,
  send: TokenSender,
): Promise<MintedToken> {
  const url = audUrl(accountId);

  const result = await send({
    url,
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: buildFormBody(assertion),
  });

  if (result.status < 200 || result.status >= 300) {
    throw new TokenExchangeError(describeError(result));
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(result.body);
  } catch {
    throw new TokenExchangeError(
      `NetSuite returned a non-JSON token response (status ${result.status})`,
    );
  }

  const accessToken = (parsed as Record<string, unknown>)?.["access_token"];
  const expiresIn = (parsed as Record<string, unknown>)?.["expires_in"];
  if (typeof accessToken !== "string" || accessToken.length === 0) {
    throw new TokenExchangeError("NetSuite response did not contain an access_token");
  }
  // NetSuite always returns a numeric `expires_in`; a response missing it is
  // malformed. Treat it as an error rather than caching for a guessed lifetime.
  if (typeof expiresIn !== "number" || !Number.isFinite(expiresIn) || expiresIn <= 0) {
    throw new TokenExchangeError(
      "NetSuite response did not contain a valid expires_in",
    );
  }

  return { accessToken, expiresIn };
}

/**
 * Build (sign) the assertion from `params`, then exchange it. Throws
 * `TokenExchangeError` (safe message) on a signing failure, non-2xx, or a
 * malformed body.
 */
export async function exchangeToken(
  params: NetsuiteTokenParams,
  send: TokenSender,
  now: number,
): Promise<MintedToken> {
  let assertion: string;
  try {
    assertion = await buildAssertion(params, now);
  } catch {
    // Most commonly: the private key cannot be imported, or its type does not
    // match the selected algorithm. Keep the message generic — never echo key
    // material.
    throw new TokenExchangeError(
      "Failed to sign the assertion — check the private key is valid PKCS#8 PEM and matches the selected algorithm",
    );
  }
  return exchangeAssertion(params.accountId, assertion, send);
}

/**
 * Derive a safe, debuggable message from a non-2xx response. Surfaces only the
 * standard OAuth `error` / `error_description` fields, never the full raw body.
 */
function describeError(result: TokenSendResult): string {
  try {
    const body = JSON.parse(result.body) as Record<string, unknown>;
    const error = typeof body["error"] === "string" ? body["error"] : undefined;
    const description =
      typeof body["error_description"] === "string"
        ? body["error_description"]
        : undefined;
    if (error || description) {
      return `NetSuite token request failed (${result.status}): ${[error, description]
        .filter(Boolean)
        .join(" — ")}`;
    }
  } catch {
    // fall through to the generic message
  }
  return `NetSuite token request failed (status ${result.status})`;
}
