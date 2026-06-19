---
reviewer: staff-engineer
status: needs_revision
blockers: 1
questions: 6
open_questions: 4
plan_path: /Users/jonking/code/src/github/jonking-ajar/yaak-plugin-jwt-generate/.plans/netsuite-jwt-yaak-plugin-spec.md
reviewed_at: 2026-06-18T00:00:00Z
---

# Staff engineer review: NetSuite M2M JWT Yaak Plugin

## Summary

The plan adds a `netsuite.token` Yaak template function that mints a NetSuite OAuth2
client-credentials access token inline: it signs a client-assertion JWT (PS256/ES256)
with `jose`, exchanges it at the NetSuite token endpoint via Node global `fetch` (behind
an injected `TokenSender` abstraction), and caches the result in a module-level `Map`
until ~60s before expiry. The core logic lives in pure, testable modules (`cache.ts`,
`netsuite.ts`) with `index.ts` wiring the Yaak plugin and the concrete `fetch` sender.
The plan is mature: API facts were verified against the installed `.d.ts`, transport
and concurrency decisions are documented, and the test matrix is concrete. The one
material gap is unhandled behavior for the `preview` render purpose, plus a few
unspecified knobs (timeout, function name format, jose version).

## Blockers

- [x] **RESOLVED (preview = cache-only, null on miss; see plan §1.3 / §3.4).** **`RenderPurpose: 'preview'` behavior is unspecified** — `onRender` receives
  `args.purpose`, which the installed types define as `"send" | "preview"`
  (verified `gen_events.d.ts:731`). The plan's behavior in §1 makes no distinction:
  as written, every preview render (autocomplete preview, request-preview pane, which
  can fire on each keystroke) would sign a JWT and POST to NetSuite on a cache miss.
  That is a real network/CPU cost and a potential rate-limit/credential-exposure
  concern triggered by typing, not sending. The implementer cannot tell whether to
  (a) treat preview identically to send, (b) serve from cache only and return `null`
  on a preview cache miss (no sign/network), or (c) return a placeholder string for
  preview. This forces an unflagged design decision. Resolve in §1 / §3.4. See Q1.

## Findings

### Ambiguities
- **Template function `name` format** (§1, §3.4). The plan calls the tag
  `netsuite.token` but the `TemplateFunction.name` field (verified
  `gen_events.d.ts:749`) is a plain string. Whether the namespacing `netsuite.token`
  is the literal `name` value, or whether Yaak derives the `netsuite.` prefix
  elsewhere, is not stated. Needs to be pinned so autocomplete renders the documented
  tag. See Q2.
- **`scope` multi-value handling** (§1). `scope` defaults to `rest_webservices` but
  the plan doesn't say whether multiple space-separated scopes are supported/validated
  or passed through verbatim. Low impact; pass-through is the safe default. See Q5.

### Explicit requirements to add
- **Token POST timeout** (§3.3, §4). The `fetch`-based `TokenSender` has no specified
  timeout. Without one, a hung NetSuite endpoint hangs the render indefinitely.
  Specify an `AbortController` timeout and the resulting behavior (treat as failure →
  `null` + toast). See Q3.
- **`jose` version pin** (§3.1). The plan says "add `jose` to dependencies" but no
  version is specified. Pin a concrete major (`jose@^5`) so the `importPKCS8` /
  `SignJWT` / `generateKeyPair` / `jwtVerify` API surface used in §3 and §5 is stable.
  See Q4.
- **`iat`/`exp` clock-skew on the assertion** (§2). `exp = iat + 3600` with no
  backdating of `iat`. If the plugin host clock runs slightly ahead of NetSuite, a
  freshly-issued assertion can be rejected as not-yet-valid. Consider whether `iat`
  should be backdated a few seconds. Minor; sandbox e2e will reveal it. See Q6.

### Edge cases & error handling
- Sufficient as written for the enumerated cases (missing arg → silent `null`;
  PEM `\n` normalization; alg/key mismatch caught; sandbox host formatting; non-2xx
  scoped to `error`/`error_description`; `expires_in < 60` TTL clamp via `max(0, …)`).
- One addition: the plan should state behavior when `fetch` itself rejects (network
  error / DNS / timeout) vs. a non-2xx HTTP response. Both should funnel to
  `null` + danger toast, but only the latter has its message-derivation rule
  specified. Make the network-error message explicitly generic (no inputs).

### Non-functional requirements
- Secret-handling rules are well specified (no key/assertion in toast, console, or
  thrown error). Good.
- Observability: the plan forbids logging secrets but says nothing about whether any
  diagnostic logging is desired at all. Acceptable for v1 (no logging) — confirm this
  is intentional rather than an omission. Folded into the network-error finding above;
  not raised as a separate question.

### Data & state considerations
- Cache model is clear: module-level `Map<string, CacheEntry>`, key from non-secret
  identifying fields, `expiresAt = now + max(0, expiresIn-60)*1000`. Cache-key
  exclusion of the private key is explicitly tested (§5.9). No persistence by design.
  Sufficient.

### Dependencies & integration points
- `@yaakapp/api@0.7.0` surface verified (see below). `jose` is the only new runtime
  dep. The `yaak plugin build` bundling-verification step (§3.1) is the right call
  since `jose` must be bundled, not left as a bare `require`. Acceptable as a build-time
  check.

### Testing & acceptance criteria gaps
- Unit matrix (§5) is strong and concrete. Gaps that follow from the findings above:
  add a test for the chosen `preview` behavior (Q1), and a test that a `fetch`
  rejection (not just non-2xx) yields `null` + toast at the `index` layer.
- The `index.ts` `onRender` layer is only lightly covered (§5.7 mentions it). Since
  `onRender` contains the purpose-branching, cache wiring, and toast logic, at least
  one direct `onRender` test with a mocked `ctx` should be required, not optional.

### Operational considerations
- Rollback is correctly characterized as trivial (additive, standalone). No
  monitoring/alerting applies to a client-side plugin. Sufficient.

## Feasibility verification

- ✓ `PluginDefinition.templateFunctions?: TemplateFunctionPlugin[]` — verified
  `node_modules/@yaakapp/api/lib/plugins/index.d.ts:22`.
- ✓ `TemplateFunctionPlugin = TemplateFunction & { args, onRender(ctx, args): Promise<string|null> }`
  — verified `plugins/TemplateFunctionPlugin.d.ts:7`.
- ✓ `TemplateFunction = { name, description?, aliases?, args: TemplateFunctionArg[] }`
  — verified `gen_events.d.ts:749`.
- ✓ `FormInputText` supports `placeholder`, `password`, `multiLine`,
  `completionOptions`, plus base `name`/`label`/`optional`/`defaultValue`/`description`
  — verified `gen_events.d.ts:382` + `FormInputBase:153`.
- ✓ `FormInputSelect` supports `options: Array<{label,value}>` and `defaultValue` —
  verified `gen_events.d.ts:342`, `FormInputSelectOption:378`.
- ✓ `CallTemplateFunctionArgs = { purpose: RenderPurpose, values: { [key]?: JsonValue } }`
  — verified `gen_events.d.ts:56`.
- ✓ `ctx.toast.show({ message, color?, icon?, timeout? })`, `Color` includes
  `'danger'`/`'warning'`/`'success'` — verified `Context.d.ts:7`, `gen_events.d.ts:73`,
  `ShowToastRequest:743`.
- ✓ `ctx.store` has async `get`/`set`/`delete`; `ctx.httpRequest.send` exists — verified
  `Context.d.ts:13,36`.
- ✓ `tsconfig` has `noEmit: true` and `include: ["src"]` — verified `tsconfig.json:17,20`.
- ✓ Scaffold currently has only sample `src/index.ts` + `src/index.test.ts` to be
  replaced — verified.
- ✗ `RenderPurpose` is `"send" | "preview"` (verified `gen_events.d.ts:731`), but the
  plan never branches on it — see blocker / Q1.

## Questions for human

1. How should `onRender` behave when `args.purpose === 'preview'` (e.g. autocomplete / request-preview renders that can fire on keystroke)?  · confidence: low · recommended: Serve cache only; null on preview miss
   - Same as send (sign + POST)
   - Serve cache only; null on preview miss
   - Always return placeholder string

   **Answer:** Serve cache only; null on preview miss

2. What is the literal `TemplateFunction.name` value for the tag?  · confidence: low · recommended: `netsuite.token`
   - `netsuite.token`
   - `token` (Yaak adds namespace)
   - `netsuite_token`

   **Answer:** `netsuite.token`

3. What timeout should the `fetch` token POST use, with timeout treated as failure (null + toast)?  · confidence: high · recommended: 30s
   - 10s
   - 30s
   - 60s
   - No timeout

   **Answer:** 30s _(auto-applied · high confidence)_

4. What `jose` version should be pinned in `package.json`?  · confidence: high · recommended: `^5`
   - `^5`
   - `^4`
   - latest unpinned

   **Answer:** `^5` _(auto-applied · high confidence)_

5. How should a multi-scope `scope` value be handled?  · confidence: high · recommended: Pass through verbatim
   - Pass through verbatim
   - Validate against allowlist
   - Reject if contains space

   **Answer:** Pass through verbatim _(auto-applied · high confidence)_

6. Should the assertion `iat` be backdated to absorb clock skew between the plugin host and NetSuite?  · confidence: low · recommended: Backdate iat by 30s
   - No backdating (iat = now)
   - Backdate iat by 30s
   - Backdate iat by 60s

   **Answer:** Backdate iat by 30s
