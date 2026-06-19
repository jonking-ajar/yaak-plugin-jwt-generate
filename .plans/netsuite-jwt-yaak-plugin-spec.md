# Plan: NetSuite M2M JWT Yaak Plugin

## Context

NetSuite's REST API supports OAuth 2.0 **client credentials** auth via a signed
**client-assertion JWT** (the "M2M" flow). Today, using NetSuite REST from Yaak
means hand-crafting and re-signing a JWT for every session and pasting the
resulting access token into an `Authorization` header — tokens expire after ~1h,
so this is repetitive and error-prone.

This feature adds a Yaak **template function** `netsuite.token` that performs the
full flow inline inside any request field:

```
Authorization: Bearer ${[ netsuite.token(accountId='…', clientId='…', …) ]}
```

It signs the assertion (PS256/ES256) with `jose`, exchanges it at the NetSuite
token endpoint, returns the `access_token`, and caches it until just before
expiry so repeated renders don't re-sign or re-POST.

Source spec: `~/Downloads/netsuite-jwt-yaak-plugin-spec.md`.

### Verified API facts (`@yaakapp/api@0.7.0`, read from installed `.d.ts`)

These were confirmed against `node_modules/@yaakapp/api/lib` and override any
guesses in the spec:

- **Entry point:** `export const plugin: PluginDefinition = { templateFunctions: [...] }`.
  There is no `definePlugin` helper in this version — the scaffold's
  `export const plugin` pattern is correct.
- **`TemplateFunctionPlugin`** = `{ name, description?, aliases?, args: TemplateFunctionArg[], onRender(ctx, args): Promise<string|null> }`.
- **`TemplateFunctionArg = FormInput`**, a discriminated union keyed on `type`:
  - `type: 'text'` → `FormInputText`: supports `name`, `label`, `optional`,
    `placeholder`, `defaultValue`, `description`, `password` (boolean — the
    secret flag), `multiLine` (textarea), `completionOptions`.
  - `type: 'select'` → `FormInputSelect`: supports `options: Array<{label,value}>`,
    `defaultValue`, plus the common `name`/`label`/`optional`.
- **`onRender(ctx, args)`** receives `args: CallTemplateFunctionArgs` =
  `{ purpose, values: { [key: string]?: JsonValue } }`. User input is read as
  `args.values.<argName>` and is typed `JsonValue` (coerce to string).
- **HTTP send:** `ctx.httpRequest.send({ httpRequest: Partial<HttpRequest> })`
  → `Promise<HttpResponse>`. Critically, **`HttpResponse` has no inline body** —
  it exposes `status: number`, `error: string | null`, `headers`, and
  `bodyPath: string | null` (a path to a temp file on disk). To read the JSON
  token response we must `fs.readFile(bodyPath)`. The request `body` is a
  `Record<string, any>` whose form-urlencoded shape is version-specific.
- **Error surfacing:** `ctx.toast.show({ color, message })` (`color` is a `Color`,
  e.g. `'danger'`/`'warning'`/`'success'`).
- **`ctx.store`** offers async `get`/`set`/`delete`, but the spec mandates an
  **in-memory `Map`** cache (do not persist tokens), so we use a module-level Map.

### Token-exchange transport decision (resolved — product review)

Because `ctx.httpRequest.send` returns the body only via a temp `bodyPath` file
and the form-body encoding for `Record<string,any>` is undocumented/version-specific,
we will use Node's global **`fetch`** for the token POST. Rationale:

- The plugin runs in a Node.js runtime where `fetch` is available globally.
- `fetch` gives us the response body and status inline, with a stable, testable
  contract (no temp-file reads, no guessing Yaak's body schema).
- The spec's preference for `ctx.httpRequest.send` is "so the request honors
  Yaak's proxy/TLS settings"; the token endpoint is a fixed public NetSuite host,
  so proxy/TLS routing is a low-value concern here.

To keep this decision reversible and the core unit-testable, `netsuite.ts`
depends on an injected **`TokenSender`** abstraction
(`(req: TokenRequest) => Promise<TokenSendResult>`), not on `fetch` directly.
`index.ts` wires the concrete `fetch` implementation; tests inject a mock. If a
future version exposes inline response bodies, swapping in a `ctx`-based sender
is a one-file change. Confirmed in product review (2026-06-19): `fetch` is the
chosen transport for v1.

**Concurrency:** two fields rendering the same tag simultaneously can both miss
the cache and fire parallel mints. We **allow this redundancy** (worst case: one
extra POST; both results cache identically) rather than adding an in-flight
promise map — documented here and in §4 rather than engineered around.

## 1 · UX

The function appears in Yaak's template autocomplete as `netsuite.token(...)`
with the args below surfaced as form inputs. Sensitive inputs render as secret
(password) fields.

### Arguments

| arg          | type     | label                     | flags / default                                   |
|--------------|----------|---------------------------|---------------------------------------------------|
| `accountId`  | text     | Account ID                | required; placeholder `1234567` or `1234567_SB1`  |
| `clientId`   | text     | Client ID (Consumer Key)  | required                                          |
| `certId`     | text     | Certificate ID            | required; → JWT header `kid`                       |
| `privateKey` | text     | Private Key (PKCS#8 PEM)  | required; `password: true`, `multiLine: true`      |
| `scope`      | text     | Scope                     | optional; `defaultValue: 'rest_webservices'`       |
| `algorithm`  | select   | Algorithm                 | options `PS256`,`ES256`; `defaultValue: 'PS256'`   |

All args carry a `description` for the tooltip. `privateKey` is flagged
`password: true` so it renders masked; the README recommends pulling `clientId`
and `privateKey` from Yaak secrets via `${[ secret_name ]}` rather than typing
them inline.

### Behavior

1. `onRender` reads + normalizes args. Any **missing/empty required arg** →
   return `null` immediately (mirrors the `fs.read` example; no toast — empty
   while the user is still typing the tag is normal).
2. Compute the cache key from `(accountId, clientId, certId, scope, algorithm)`.
   If a cached, unexpired token exists → return it (no signing, no network).
3. On a **cache miss**, mint regardless of `args.purpose` (`'send' | 'preview'`):
   build + sign the assertion JWT, POST it to the token endpoint, parse
   `access_token` + `expires_in`, cache, and return the token. Minting on
   `'preview'` is intentional — Yaak renders the editor's Rendered Preview (and
   its refresh button) with `purpose: 'preview'`, so a cache-only preview would
   always show empty. The required-arg guard (step 1) plus the ~1h cache bound
   this to at most one mint per credential set, so it does **not** re-sign or
   re-POST on every keystroke. (Reversed the original eng-review decision after
   real-world UX feedback — see Revision history.)
   - Error toasts are shown only when `purpose === 'send'`; during `'preview'`
     a failure returns `null` silently, to avoid toast noise while args are
     being configured.
4. **On any failure** (bad key, non-2xx, malformed response, network/timeout):
   return `null` and `ctx.toast.show({ color: 'danger', … })` with a useful
   message. Two message-derivation rules:
   - **NetSuite non-2xx** → surface **only the `error` and `error_description`
     fields** of the JSON body (not the full raw body), falling back to a generic
     message if those fields are absent.
   - **`fetch` rejection** (network / DNS / abort-on-timeout) → a **generic**
     message (e.g. "NetSuite token request failed"), never echoing inputs.
   **Never** include the private key or signed assertion in the message or any log.

### Edge cases

| case | handling |
|------|----------|
| Missing required arg | return `null` early, silently |
| PEM pasted with literal `\n` escapes | normalize `\\n` → real newline before `importPKCS8` |
| `algorithm` ≠ key type (e.g. PS256 with an EC key) | `importPKCS8` throws → caught → `null` + toast |
| Sandbox account id `1234567_SB1` | host becomes `1234567-sb1` (lowercase, `_`→`-`) |
| Non-2xx from NetSuite | return `null`, toast only `error`/`error_description` from the body |
| Token near expiry | 60s skew — re-mint before NetSuite would reject |
| `expires_in` < 60 (degenerate) | clamp TTL to ≥0 so a tiny lifetime never yields a negative `expiresAt` (cache simply treats it as already-expired → re-mint) |

## 2 · Data model

```ts
// netsuite.ts — public types
export type NsAlgorithm = 'PS256' | 'ES256';

export interface NetsuiteTokenParams {
  accountId: string;
  clientId: string;
  certId: string;
  privateKey: string;   // PKCS#8 PEM, possibly \n-escaped
  scope: string;        // already defaulted
  algorithm: NsAlgorithm;
}

// JWT claims (built internally)
const IAT_SKEW_SECONDS = 30;        // backdate iat to absorb host/NetSuite clock drift
const ASSERTION_TTL_SECONDS = 3600; // NetSuite caps assertion lifetime at 60 min
interface AssertionClaims {
  iss: string;          // clientId
  scope: string;
  aud: string;          // token URL
  iat: number;          // floor(now/1000) - IAT_SKEW_SECONDS
  exp: number;          // iat + ASSERTION_TTL_SECONDS
}

// Transport abstraction (injected; lets tests mock the network)
export interface TokenRequest {
  url: string;
  method: 'POST';
  headers: Record<string, string>;   // Content-Type: application/x-www-form-urlencoded
  body: string;                       // urlencoded form
}
export interface TokenSendResult {
  status: number;
  body: string;          // raw response body text
}
export type TokenSender = (req: TokenRequest) => Promise<TokenSendResult>;

// Returned to caller
export interface MintedToken {
  accessToken: string;
  expiresIn: number;     // seconds, from NetSuite `expires_in`
}
```

```ts
// cache.ts
interface CacheEntry { accessToken: string; expiresAt: number; } // expiresAt = ms epoch
// module-level Map<string, CacheEntry>; key = plain delimited join of non-secret
// identifying fields (no hashing needed since no secret material is included)
```

### Key formatting helpers (pure, in `netsuite.ts`)

- `audUrl(accountId)` → `https://<host>.suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/token`
  where `host = accountId.toLowerCase().replace(/_/g, '-')`.
- `normalizePem(pem)` → `pem.replace(/\\n/g, '\n')`.

## 3 · Implementation

Files (matches spec layout; scaffold currently has only a sample `index.ts` +
`index.test.ts` to be replaced):

1. **`package.json`** — add **`jose@^5`** to `dependencies` (the v5 API surface —
   `importPKCS8`/`SignJWT`/`generateKeyPair`/`jwtVerify` — is what §3/§5 target).
   Add a `"test": "vitest run"`
   script. Keep `vitest` dev dep. **Verify `yaak plugin build` bundles `jose`**
   into the output (it uses esbuild, so this is expected) — check the built bundle
   includes the dep rather than leaving a bare `require('jose')`; if not, add the
   needed bundling config before shipping.
2. **`src/cache.ts`** — module-level `Map`; `getCached(key, now)`,
   `setCached(key, accessToken, expiresIn, now)` (stores `expiresAt = now +
   max(0, expiresIn-60)*1000` — the `max(0, …)` guard keeps a degenerate
   `expires_in < 60` from producing a negative TTL), `cacheKey(params)` (plain
   delimited join — no secret material: uses
   accountId/clientId/certId/scope/algorithm, **not** the private key).
   `clearCache()` for tests.
3. **`src/netsuite.ts`** — pure, testable core:
   - `audUrl`, `normalizePem` helpers.
   - `buildAssertion(params, now)` → signs with `jose` (`importPKCS8` +
     `new SignJWT(claims).setProtectedHeader({ alg, typ:'JWT', kid: certId }).sign(key)`),
     returns the compact JWT string.
   - `scope` is passed through **verbatim** (no allowlist validation, no
     space-splitting) — multiple space-delimited scopes flow straight into the
     assertion `scope` claim and the POST.
   - `exchangeToken(params, send, now)` → builds assertion, calls `send` with the
     urlencoded body (`grant_type=client_credentials`,
     `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`,
     `client_assertion=<jwt>`), parses JSON, returns `MintedToken` or throws a
     typed error on non-2xx / malformed body.
4. **`src/index.ts`** — plugin definition:
   - `export const plugin: PluginDefinition = { templateFunctions: [netsuiteToken] }`.
   - The template function's `name` is the literal string **`'netsuite.token'`**
     (the dot is part of the name, matching the documented `${[ netsuite.token(...) ]}`
     usage).
   - Arg defs per §1.
   - `onRender(ctx, args)`: read/normalize `args.values.*`; early-`null` on missing
     required; cache lookup; **branch on `args.purpose`** (preview → cache-only,
     `null` on miss; send → mint on miss); on a send-miss call `exchangeToken`
     with a `fetch`-based `TokenSender`; cache + return; `try/catch` → `null` +
     `ctx.toast.show`. The `fetch` sender lives here (not in `netsuite.ts`) so the
     core stays environment-free.
   - The `fetch` sender enforces a **30s timeout** via `AbortController`; an abort
     (or any network error) rejects and is caught → `null` + generic danger toast.
5. **`README.md`** — usage (the `${[ netsuite.token(...) ]}` example), arg table,
   secret-storage recommendation, build/dev instructions.
6. **`src/index.test.ts`** — replace the sample test (see §5).

Ordering: cache → netsuite (core) → index (wiring) → README. Run `tsc --noEmit`
(via the existing tsconfig; note `noEmit:true`, build is delegated to
`yaak plugin build`) and `vitest run` as we go.

## 4 · Risks

- **Transport choice (resolved).** Using `fetch` instead of
  `ctx.httpRequest.send` means the token POST bypasses Yaak's configured
  proxy/TLS. Product review confirmed `fetch` for v1. Mitigation: injected
  `TokenSender` keeps it swappable; the endpoint is a fixed public host.
- **Concurrent cache-miss mints (accepted).** Parallel renders of the same tag
  can fire redundant token POSTs; we accept this (both cache the same result)
  rather than adding in-flight de-duplication.
- **Hung endpoint.** Without a timeout the render would hang indefinitely. The
  `fetch` sender uses a 30s `AbortController` timeout; an abort funnels to the
  same `null` + toast failure path.
- **Preview-render cost.** Preview now mints on a cache miss (so the Rendered
  Preview shows a token). The required-arg guard + ~1h cache bound this to at
  most one mint per credential set; preview errors are silent (no toast).
- **Form-body encoding for `ctx.httpRequest.send` is undocumented** in the 0.7.0
  types (`body: Record<string,any>`). This is the main reason for the `fetch`
  decision; if we must use the ctx sender, this needs spiking first.
- **`aud`/host formatting for sandbox** accounts (`_SB1` → `-sb1`) is asserted by
  the spec but not independently verified against live NetSuite. Covered by a
  unit test for the documented rule; flagged for end-to-end confirmation.
- **Key/alg mismatch** is a common user error; handled by catching `importPKCS8`
  / `sign` throws and toasting, but the message must stay generic (no key
  material).
- **Secret leakage** — private key & signed assertion must never reach a toast,
  `console`, or thrown error message. Enforce by only ever logging
  `error.message` from our own typed errors, never raw inputs.
- **Plugin instance lifetime** — the module-level Map assumes a long-lived
  process; if Yaak reloads the plugin the cache resets (acceptable — worst case
  is one extra mint).
- **Rollback:** plugin is additive and standalone; removing it has no external
  impact.

## 5 · Acceptance criteria & tests

Unit tests with **Vitest** (`vitest run`), mostly against `netsuite.ts` and
`cache.ts`:

1. **JWT claims & header** — `buildAssertion` produces a JWT whose decoded
   payload has correct `iss` (=clientId), `scope`, `aud`, `iat`, and
   `exp === iat + 3600`; protected header has `alg` (=algorithm), `typ:'JWT'`,
   and `kid` (=certId).
2. **Signature verifies** — generate an RSA (PS256) and an EC P-256 (ES256)
   keypair in-test (via `jose.generateKeyPair` → export PKCS#8); sign, then
   `jose.jwtVerify` against the public key succeeds; a wrong key fails.
3. **`aud` host formatting** — production `1234567` →
   `https://1234567.suitetalk…`; sandbox `1234567_SB1` →
   `https://1234567-sb1.suitetalk…`.
4. **PEM normalization** — a key string with literal `\n` escapes imports
   successfully (round-trips through `normalizePem`).
5. **Token exchange request shape** — with a mocked `TokenSender`, assert the
   request URL == `audUrl`, method `POST`, `Content-Type:
   application/x-www-form-urlencoded`, and the body contains the three fields
   `grant_type`, `client_assertion_type`, `client_assertion` with correct values.
6. **Exchange success** — mock send returns `{status:200, body:'{"access_token":"abc","expires_in":3600}'}`
   → `exchangeToken` resolves `{accessToken:'abc', expiresIn:3600}`.
7. **Exchange failure** — mock send returns `status:400` with a NetSuite error
   body → `exchangeToken` throws a typed error (message derived from the body),
   and (at the `index` layer) `onRender` returns `null` + toasts.
8. **Cache hit/miss with fake timers** — `vi.useFakeTimers()`: first call mints
   and caches; second call before `expiresAt` returns the same token without
   re-sending; advancing past `expiresAt` re-mints. Different inputs → different
   key → separate entries.
9. **Cache key excludes private key** — changing only `privateKey` does **not**
   change the cache key (the key is built from non-secret identifying fields).
10. **`onRender` purpose branch (required, mocked `ctx`)** — with `purpose:'preview'`
    and an empty cache, `onRender` returns `null` and the mock `TokenSender`/`fetch`
    is **never** called; with a warm cache it returns the cached token. With
    `purpose:'send'` and a cold cache it mints. Exercises the cache wiring + toast
    logic that lives only in `index.ts`.
11. **`fetch` rejection path** — when the sender rejects (network error / abort),
    `onRender` returns `null` and toasts a generic message containing no inputs.
12. **`iat` backdating** — decoded assertion has `iat === floor(now/1000) - 30`
    and `exp === iat + 3600`.

Manual / smoke (documented, end-to-end against a NetSuite sandbox — see §6 of
pipeline):
- Function appears in Yaak autocomplete as `netsuite.token`.
- Returns a working bearer token against a real sandbox; a subsequent REST call
  with `Authorization: Bearer ${[ netsuite.token(...) ]}` succeeds.

Doc updates: `README.md` per §3.

## Non-goals

- No support for OAuth flows other than client-credentials JWT-bearer (no
  authorization-code, no TBA/OAuth 1.0a).
- No on-disk / cross-session token persistence (in-memory only, per spec).
- No automatic key-type detection — the user selects `algorithm` and must match
  it to their key.
- No `jsonwebtoken` dependency (spec forbids it; we use `jose`).
- Not implementing a generic Yaak HTTP-send transport unless review requires it.

## Revision history

- 2026-06-19: Revised after product review (0 blockers resolved; 2 questions
  auto-resolved at high confidence, 5 answered by author — all matched the
  reviewer's recommendation). Resolved the `fetch` transport decision; documented
  accepted concurrent-mint redundancy; scoped the failure toast to
  `error`/`error_description`; clarified plain-join cache key and added an
  `expires_in < 60` TTL clamp; added a `jose` bundling-verification step.
- 2026-06-19: Revised after staff-engineer review (1 blocker resolved; 3 questions
  auto-resolved at high confidence, 3 answered by author — all matched the
  reviewer's recommendation). Blocker: defined `preview` vs `send` purpose
  branching (preview is cache-only, no sign/POST). Pinned `jose@^5`; added a 30s
  `AbortController` timeout + generic network-error toast path; pinned the function
  `name` to literal `'netsuite.token'`; specified `scope` pass-through; backdated
  assertion `iat` by 30s; named the TTL/skew constants; added required `onRender`
  purpose/rejection tests and an `iat`-backdating test.
- 2026-06-19: Reversed the preview-render decision after live UX testing — the
  editor's Rendered Preview (and its refresh button) render with
  `purpose: 'preview'`, so the original cache-only-preview behavior always
  showed an empty preview. Preview now mints on a cache miss (bounded by the
  required-arg guard + cache); preview-time errors are suppressed (no toast).
  Verified end-to-end against a live NetSuite sandbox (token mint succeeds).
