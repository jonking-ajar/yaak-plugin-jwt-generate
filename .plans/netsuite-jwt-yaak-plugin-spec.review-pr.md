---
reviewer: pr
status: approved
blockers: 0
important: 1
nits: 2
pr_number: 1
plan_path: /Users/jonking/code/src/github/jonking-ajar/yaak-plugin-jwt-generate/.plans/netsuite-jwt-yaak-plugin-spec.md
reviewed_at: 2026-06-19T07:19:00Z
---

# PR review: feat: NetSuite JWT template function (netsuite.token)

## Summary

The diff implements the `netsuite.token` Yaak template function exactly as planned:
a pure, testable core (`netsuite.ts`) for building/signing the client-assertion JWT
and exchanging it for a token, an in-memory cache (`cache.ts`) keyed only by
non-secret fields, and `index.ts` wiring the plugin definition plus a `fetch`-based
transport with a 30s abort timeout. All 24 unit tests pass and `tsc --noEmit` is
clean. Code quality is high: secret material is kept out of errors/toasts, error
messages are scoped per the spec, and the build output bundles `jose` inline.

## Spec conformance

Strong conformance. Every file in plan §3 was created/touched (`package.json`,
`src/cache.ts`, `src/netsuite.ts`, `src/index.ts`, `README.md`, tests). Every
acceptance criterion in §5 is covered by a test (claims/header, signature verify
for PS256 + ES256, aud host formatting, PEM normalization, request shape, success,
failure, cache hit/miss, cache key excludes private key, onRender purpose branch,
fetch-rejection path, iat backdating). Behavior details match: preview is
cache-only, send mints on miss, missing required arg returns null silently, non-2xx
surfaces only `error`/`error_description`, network rejection yields a generic toast,
`scope` is passed through verbatim, `iat` is backdated 30s, and TTL is clamped at 0.

Two minor deviations, both acceptable: (1) the cache TTL skew constant is named
`EXPIRY_SKEW_SECONDS` rather than referenced in §2 prose, and the expiry test uses
explicit `now` arguments instead of `vi.useFakeTimers()` — functionally equivalent
and arguably cleaner. (2) The §3.1 "verify jose is bundled" step is a build-time
check, not code; I confirmed the built `build/index.js` inlines `jose` with no bare
`require("jose")`, so the requirement is satisfied.

## Findings

### Blockers

None.

### Important

- **f1** — End-to-end NetSuite verification still outstanding — `src/netsuite.ts:993` (`audUrl`)
  Plan §4 flags the sandbox host rule (`1234567_SB1` → `1234567-sb1`) and the
  overall token flow as asserted-but-not-verified against live NetSuite. The unit
  test covers the documented rule, but the manual/smoke acceptance items in §5
  (function appears in autocomplete; a real bearer token works against a sandbox)
  are not demonstrable from the diff. Recommend confirming end-to-end against a
  sandbox before merge, or explicitly deferring it as a tracked follow-up. No code
  change required.

### Nits

- **f2** — Toast classification keys off `err.name` string rather than `instanceof` — `src/index.ts:699`
  `onRender` decides generic-vs-specific message via `err.name === "TokenExchangeError"`.
  This is actually a deliberate, bundling-robust choice (the constructor sets
  `this.name` to a literal, surviving esbuild minification where `instanceof` against
  the class identifier could be fragile). Worth a one-line comment noting why
  `err.name` is used instead of `instanceof TokenExchangeError`, to prevent a future
  reader from "fixing" it.

- **f3** — `expiresIn` falls back to assertion TTL on a missing/non-numeric value — `src/netsuite.ts:1090`
  When `expires_in` is absent or non-numeric, the code defaults to
  `ASSERTION_TTL_SECONDS` (3600). This is reasonable, but NetSuite always returns
  `expires_in`; a malformed token response is arguably better treated as an error
  than silently cached for an hour. Low priority — optional hardening.
