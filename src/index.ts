import type { Context, PluginDefinition } from "@yaakapp/api";
import { cacheKey, getCached, setCached } from "./cache";
import {
  exchangeToken,
  type NetsuiteTokenParams,
  type NsAlgorithm,
  type TokenRequest,
  type TokenSendResult,
} from "./netsuite";

const DEFAULT_SCOPE = "rest_webservices";
const FETCH_TIMEOUT_MS = 30_000;

/**
 * `fetch`-based transport. Lives here (not in `netsuite.ts`) so the core stays
 * environment-free. Enforces a timeout via `AbortController`; an abort rejects
 * and is caught by `onRender` → null + toast.
 */
async function fetchSender(req: TokenRequest): Promise<TokenSendResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(req.url, {
      method: req.method,
      headers: req.headers,
      body: req.body,
      signal: controller.signal,
    });
    const body = await res.text();
    return { status: res.status, body };
  } finally {
    clearTimeout(timer);
  }
}

/** Read a value as a trimmed string, or null if absent/empty. */
function readString(values: Record<string, unknown>, name: string): string | null {
  const raw = values[name];
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function readAlgorithm(values: Record<string, unknown>): NsAlgorithm {
  return values["algorithm"] === "ES256" ? "ES256" : "PS256";
}

export const plugin: PluginDefinition = {
  templateFunctions: [
    {
      name: "netsuite.token",
      description:
        "Mint a NetSuite OAuth2 client-credentials (JWT-bearer) access token, usable in an Authorization: Bearer header. Caches until just before expiry.",
      args: [
        {
          type: "text",
          name: "accountId",
          label: "Account ID",
          placeholder: "1234567 or 1234567_SB1",
          description: "NetSuite account id; used to build the token URL host.",
        },
        {
          type: "text",
          name: "clientId",
          label: "Client ID (Consumer Key)",
          description: "Becomes the JWT `iss` and the POST `client_id`.",
        },
        {
          type: "text",
          name: "certId",
          label: "Certificate ID",
          description: "NetSuite-assigned certificate mapping id → JWT header `kid`.",
        },
        {
          type: "text",
          name: "privateKey",
          label: "Private Key (PKCS#8 PEM)",
          password: true,
          multiLine: true,
          description:
            "PKCS#8 PEM. Recommended: store as a Yaak secret and reference it as ${[ secret_name ]} rather than typing it inline.",
        },
        {
          type: "text",
          name: "scope",
          label: "Scope",
          defaultValue: DEFAULT_SCOPE,
          description:
            "Space-delimited scope(s), e.g. `rest_webservices` or `restlets`.",
        },
        {
          type: "select",
          name: "algorithm",
          label: "Algorithm",
          defaultValue: "PS256",
          description: "Must match the key type: PS256 ⇒ RSA, ES256 ⇒ EC P-256.",
          options: [
            { label: "PS256", value: "PS256" },
            { label: "ES256", value: "ES256" },
          ],
        },
      ],
      async onRender(ctx: Context, args): Promise<string | null> {
        const values = (args.values ?? {}) as Record<string, unknown>;

        const accountId = readString(values, "accountId");
        const clientId = readString(values, "clientId");
        const certId = readString(values, "certId");
        const privateKey = readString(values, "privateKey");
        // Missing/empty required args → silent null (normal while typing the tag).
        if (!accountId || !clientId || !certId || !privateKey) {
          return null;
        }

        const scope = readString(values, "scope") ?? DEFAULT_SCOPE;
        const algorithm = readAlgorithm(values);

        const params: NetsuiteTokenParams = {
          accountId,
          clientId,
          certId,
          privateKey,
          scope,
          algorithm,
        };

        const key = cacheKey(params);
        const now = Date.now();

        const cached = getCached(key, now);
        if (cached != null) return cached;

        // Both send and preview mint on a cache miss, so the editor's Rendered
        // Preview (and its refresh button — Yaak renders both with purpose
        // 'preview') shows a real token. The required-arg guard above plus the
        // ~1h token cache bound this to at most one mint per credential set, so
        // it does not re-sign or re-POST on every keystroke.
        try {
          const { accessToken, expiresIn } = await exchangeToken(
            params,
            fetchSender,
            now,
          );
          setCached(key, accessToken, expiresIn, now);
          return accessToken;
        } catch (err) {
          // Suppress error toasts during preview: the editor preview/refresh
          // fires with purpose 'preview' and partially-configured args would
          // otherwise spam toasts. Surface failures only on a real send.
          if (args.purpose === "send") {
            // Key off `err.name` (a literal set in the constructor) rather than
            // `instanceof TokenExchangeError`: the literal survives esbuild
            // bundling/minification, whereas instanceof against the class
            // identifier can be fragile across bundle boundaries. A
            // TokenExchangeError carries a vetted, secret-free message; anything
            // else (e.g. a fetch/network rejection) gets a generic message.
            const message =
              err instanceof Error && err.name === "TokenExchangeError"
                ? err.message
                : "NetSuite token request failed";
            await ctx.toast.show({ color: "danger", message });
          }
          return null;
        }
      },
    },
  ],
};
