---
reviewer: product
status: approved_with_questions
blockers: 0
questions: 7
open_questions: 5
plan_path: /Users/jonking/code/src/github/jonking-ajar/yaak-plugin-jwt-generate/.plans/netsuite-jwt-yaak-plugin-spec.md
reviewed_at: 2026-06-18T00:00:00Z
---

# Product review: NetSuite M2M JWT Yaak Plugin

## Summary

The plan adds a Yaak template function `netsuite.token(...)` that mints a NetSuite
OAuth2 client-credentials JWT-bearer assertion (PS256/ES256 via `jose`), exchanges
it at the NetSuite token endpoint, and caches the resulting access token in an
in-memory `Map` until ~60s before expiry. The core logic lives in pure, testable
modules (`netsuite.ts`, `cache.ts`) with an injected `TokenSender` transport, and
`index.ts` wires a `fetch`-based sender. The plan's "Verified API facts" were
spot-checked against the installed `@yaakapp/api@0.7.0` `.d.ts` files and are
accurate (HttpResponse `bodyPath`, `CallTemplateFunctionArgs.values`,
`FormInputText` password/multiLine, `ctx.toast.show`, `export const plugin`).

This is a strong, implementation-ready plan with explicit Non-goals, Risks, and
Acceptance criteria sections. The findings below are refinements, and the
questions are mostly product/scope judgment calls rather than gaps.

## Findings

### Ambiguous sections
- §1 Behavior step 4 / §1 Edge cases: "toast the NetSuite error body" vs. §4
  "message must stay generic (no key material)" — these are not in tension (the
  NetSuite error body contains no secret), but the plan should state which fields
  of the error body are surfaced verbatim. NetSuite error bodies can occasionally
  echo request context; worth confirming the toast only renders `error` /
  `error_description` and not the full body.
- §1 Edge cases "Token near expiry — 60s skew": the 60s skew is applied at cache
  *write* time (§3 cache.ts `expiresAt = now + (expiresIn-60)*1000`). If
  `expires_in` were ever < 60 this yields a non-positive TTL. Edge but cheap to
  note.

### Implicit assumptions
- The plan assumes `fetch` is available in the Yaak plugin Node runtime (§context,
  §4). This is asserted but not independently verified against the actual runtime
  Yaak embeds. It drives the central transport decision (§4 open decision).
- Assumes a single shared module-level cache is acceptable across all workspaces /
  environments in one Yaak process. Two environments using different credentials
  produce different cache keys, so this is safe, but the assumption that the
  module is shared process-wide (not per-render-isolated) is implicit.
- Assumes `iat`/`exp` of the *assertion* (fixed at `iat + 3600`, §2) is acceptable
  to NetSuite. The access-token lifetime (`expires_in`) is separate; this is fine
  but the two "3600"s are unrelated and could confuse a reader.

### Edge cases & failure scenarios
- Clock skew on the signing side: §1 handles token *near expiry* but not a local
  clock that is far off, which would make NetSuite reject the assertion `iat`/`exp`.
  Likely out of scope, but undocumented.
- Concurrent renders racing on a cache miss (two fields rendering simultaneously)
  could trigger two parallel mints for the same key. Worst case is a redundant
  POST; worth a one-line note on whether in-flight de-duplication is needed.
- §1 step 1 returns `null` silently on missing required args, but a *partially*
  malformed PEM (present but invalid) routes to the toast path — confirm the
  boundary between "still typing" (silent) and "bad input" (toast) is where intended.

### Non-functional considerations
- Observability: the plan deliberately avoids logging secrets (good), but there is
  no mention of any non-sensitive diagnostic signal (e.g. cache hit/miss) for
  debugging. Likely fine to defer, but currently a silent `null` is the only
  failure signal besides the toast.
- The `cacheKey` is described as a "stable hash of inputs" in §2 but "stable string,
  e.g. join of fields" in §3. A plain join is simpler and adequate since no secret
  is included; the word "hash" may over-imply a crypto requirement. Minor clarity.

### Dependencies and risks
- The §4 transport decision (`fetch` vs `ctx.httpRequest.send`) is correctly
  flagged as the primary open decision and is well-mitigated by the injected
  `TokenSender`. Surfaced as a question below.
- `jose` is a new runtime dependency added to a plugin built via `yaak plugin
  build`. The plan assumes `yaak plugin build` bundles dependencies; if it expects
  zero-dependency or specific bundling, this is a risk worth confirming. Surfaced
  below.
- Sandbox host formatting (`_SB1` → `-sb1`, §1/§4) is asserted from the spec, not
  verified live. Already flagged for E2E confirmation — adequate for this stage.

### Structural or clarity improvements
- The plan is well-organized. Consider a one-line mapping in §3 from each
  acceptance test (§5) to the module it exercises — most are already implied.
- §2 reuses the literal `3600` for the assertion `exp` and §5 test 1 asserts
  `exp === iat + 3600`; consider naming this constant to avoid drift.

## Questions for human

1. Transport for the token POST: `fetch` (per §4 recommendation) or
   `ctx.httpRequest.send` + bodyPath?  · confidence: low · recommended: fetch (global Node)
   - fetch (global Node)
   - ctx.httpRequest.send + bodyPath
   - spike both, decide later

   **Answer:** fetch (global Node)

2. Assertion JWT lifetime (`exp = iat + 3600`, §2) — keep fixed at 1h, or make it
   shorter/configurable?  · confidence: high · recommended: fixed 3600s
   - fixed 3600s
   - shorter fixed (e.g. 300s)
   - configurable arg

   **Answer:** fixed 3600s _(auto-applied · high confidence)_

3. Concurrent cache-miss renders for the same key — de-duplicate in-flight mints,
   or allow redundant parallel POSTs?  · confidence: low · recommended: allow redundant (document)
   - allow redundant (document)
   - de-dup via in-flight promise map
   - defer, not a concern

   **Answer:** allow redundant (document)

4. What does the failure toast surface from a NetSuite non-2xx body (§1)?  · confidence: low · recommended: error + error_description only
   - error + error_description only
   - full response body
   - generic static message

   **Answer:** error + error_description only

5. Does `yaak plugin build` bundle the new `jose` runtime dependency, or is extra
   config needed?  · confidence: low · recommended: bundled by build (verify)
   - bundled by build (verify)
   - needs explicit bundling config
   - vendor jose into source

   **Answer:** bundled by build (verify)

6. Cache key construction (§2 vs §3 wording): plain field join or hashed?  · confidence: high · recommended: plain delimited join
   - plain delimited join
   - hashed (sha256)

   **Answer:** plain delimited join _(auto-applied · high confidence)_

7. `scope` arg: keep single text field defaulting to `rest_webservices`, or support
   multiple space-delimited scopes explicitly?  · confidence: low · recommended: single text, space-delimited allowed
   - single text, space-delimited allowed
   - multi-select of known scopes
   - single fixed value, no arg

   **Answer:** single text, space-delimited allowed
