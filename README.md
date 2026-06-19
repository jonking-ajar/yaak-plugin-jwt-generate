# yaak-plugin-jwt-generate

A [Yaak](https://yaak.app) plugin that adds a `netsuite.token` template function.
It performs the full NetSuite OAuth 2.0 **client credentials (JWT bearer)** flow —
signing a client-assertion JWT, exchanging it at the NetSuite token endpoint, and
returning an **access token** you can drop straight into an `Authorization` header.

The minted token is cached in memory until just before it expires, so repeated
renders don't re-sign or re-POST.

## Usage

Reference the function in any Yaak text field:

```
Authorization: Bearer ${[ netsuite.token(
  accountId='1234567_SB1',
  clientId='${[ secret_client_id ]}',
  certId='abc123...',
  privateKey='${[ ns_private_key ]}',
  scope='rest_webservices',
  algorithm='PS256'
) ]}
```

> **Store secrets as Yaak secrets.** Rather than typing `clientId` / `privateKey`
> inline, store them as Yaak secrets / environment variables and reference them as
> template variables (`${[ secret_name ]}`), as shown above. The `privateKey` field
> renders as a masked (password) input.

### Arguments

| Arg          | Label                    | Notes |
|--------------|--------------------------|-------|
| `accountId`  | Account ID               | e.g. `1234567` (production) or `1234567_SB1` (sandbox). Used to build the token URL host. |
| `clientId`   | Client ID (Consumer Key) | Becomes the JWT `iss` and the POST `client_id`. |
| `certId`     | Certificate ID           | NetSuite-assigned certificate mapping id → JWT header `kid`. |
| `privateKey` | Private Key (PKCS#8 PEM) | Secret/masked. PEM string; literal `\n` escapes are normalized automatically. |
| `scope`      | Scope                    | Defaults to `rest_webservices`. Space-delimited for multiple scopes (e.g. `rest_webservices restlets`). |
| `algorithm`  | Algorithm                | `PS256` (default) or `ES256`. **Must match your key type:** PS256 ⇒ RSA, ES256 ⇒ EC P-256. |

### Behavior

- **Caching** — tokens are cached in memory keyed by
  `(accountId, clientId, certId, scope, algorithm)` and reused until ~60s before
  expiry. The private key is never part of the cache key and is never persisted.
- **Autocomplete / preview** — while you type, preview renders serve only from the
  cache (no signing, no network). A real token is minted only on send.
- **Failures** — on a bad key, a non-2xx response, or a network error, the function
  returns nothing and shows a Yaak toast describing the problem. The private key and
  the signed assertion are never logged or shown.

## Account host formatting

The token endpoint host is derived from the account id by lowercasing it and
replacing `_` with `-`:

| Account ID    | Token host segment |
|---------------|--------------------|
| `1234567`     | `1234567`          |
| `1234567_SB1` | `1234567-sb1`      |

→ `https://<host>.suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/token`

## Development

```bash
pnpm install
pnpm test          # vitest unit tests
pnpm check-types   # tsc --noEmit
pnpm build         # yaak plugin build (bundles jose)
pnpm dev           # yaak plugin dev — rebuilds on change
```

Source layout:

```
src/index.ts      # plugin definition + onRender (Yaak wiring, fetch transport)
src/netsuite.ts   # JWT build + token exchange (pure, testable)
src/cache.ts      # in-memory token cache keyed by non-secret inputs
```

Once built, verify the function appears in Yaak's template autocomplete as
`netsuite.token` and returns a working token end-to-end against a NetSuite sandbox.
