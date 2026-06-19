import { exportPKCS8, generateKeyPair } from "jose";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { clearCache } from "./cache";
import { plugin } from "./index";

// Resolve the onRender + arg definitions from the plugin export.
const fn = plugin.templateFunctions![0]!;
const onRender = (ctx: unknown, args: unknown): Promise<string | null> =>
  fn.onRender(ctx as never, args as never);

const exchangeFn = plugin.templateFunctions![1]!;
const onRenderExchange = (ctx: unknown, args: unknown): Promise<string | null> =>
  exchangeFn.onRender(ctx as never, args as never);

let privateKeyPem: string;

beforeEach(async () => {
  clearCache();
  const { privateKey } = await generateKeyPair("PS256", { extractable: true });
  privateKeyPem = await exportPKCS8(privateKey);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

interface ToastArg {
  color?: string;
  message: string;
}

function makeCtx() {
  return {
    toast: { show: vi.fn(async (_req: ToastArg) => {}) },
  };
}

function fullValues() {
  return {
    accountId: "1234567_SB1",
    clientId: "client-abc",
    certId: "cert-xyz",
    privateKey: privateKeyPem,
    scope: "rest_webservices",
    algorithm: "PS256",
  };
}

function stubFetch(
  impl: (
    input?: RequestInfo | URL,
    init?: RequestInit,
  ) => Promise<Response> | Response,
) {
  const spy = vi.fn(impl);
  vi.stubGlobal("fetch", spy);
  return spy;
}

function tokenResponse(token = "the-token", expiresIn = 3600): Response {
  return new Response(
    JSON.stringify({ access_token: token, expires_in: expiresIn }),
    { status: 200 },
  );
}

describe("plugin definition", () => {
  test("registers the netsuite.token template function with all args", () => {
    expect(fn.name).toBe("netsuite.token");
    const names = fn.args.map((a) => (a as { name: string }).name);
    expect(names).toEqual([
      "accountId",
      "clientId",
      "certId",
      "privateKey",
      "scope",
      "algorithm",
    ]);
    const privateKeyArg = fn.args.find(
      (a) => (a as { name: string }).name === "privateKey",
    ) as { password?: boolean };
    expect(privateKeyArg.password).toBe(true);
  });
});

describe("onRender", () => {
  test("missing required arg → null, no network call", async () => {
    const spy = stubFetch(() => tokenResponse());
    const ctx = makeCtx();
    const result = await onRender(ctx, {
      purpose: "send",
      values: { accountId: "1234567" }, // missing the rest
    });
    expect(result).toBeNull();
    expect(spy).not.toHaveBeenCalled();
  });

  test("send + cold cache → mints a token", async () => {
    const spy = stubFetch(() => tokenResponse("minted"));
    const result = await onRender(makeCtx(), {
      purpose: "send",
      values: fullValues(),
    });
    expect(result).toBe("minted");
    expect(spy).toHaveBeenCalledTimes(1);
  });

  test("preview + cold cache → mints a token (so the Rendered Preview shows it)", async () => {
    const spy = stubFetch(() => tokenResponse("previewed"));
    const result = await onRender(makeCtx(), {
      purpose: "preview",
      values: fullValues(),
    });
    expect(result).toBe("previewed");
    expect(spy).toHaveBeenCalledTimes(1);
  });

  test("preview error → null and NO toast (suppressed during preview)", async () => {
    stubFetch(
      () =>
        new Response(JSON.stringify({ error: "invalid_client" }), {
          status: 400,
        }),
    );
    const ctx = makeCtx();
    const result = await onRender(ctx, {
      purpose: "preview",
      values: fullValues(),
    });
    expect(result).toBeNull();
    expect(ctx.toast.show).not.toHaveBeenCalled();
  });

  test("preview + warm cache → returns cached token without a network call", async () => {
    // Warm the cache via a send render.
    const spy = stubFetch(() => tokenResponse("warmed"));
    const sendResult = await onRender(makeCtx(), {
      purpose: "send",
      values: fullValues(),
    });
    expect(sendResult).toBe("warmed");
    expect(spy).toHaveBeenCalledTimes(1);

    // Now a preview render should serve from cache, no further fetch.
    const previewResult = await onRender(makeCtx(), {
      purpose: "preview",
      values: fullValues(),
    });
    expect(previewResult).toBe("warmed");
    expect(spy).toHaveBeenCalledTimes(1);
  });

  test("a second send render serves from cache (no re-mint)", async () => {
    const spy = stubFetch(() => tokenResponse("once"));
    await onRender(makeCtx(), { purpose: "send", values: fullValues() });
    const again = await onRender(makeCtx(), {
      purpose: "send",
      values: fullValues(),
    });
    expect(again).toBe("once");
    expect(spy).toHaveBeenCalledTimes(1);
  });

  test("NetSuite non-2xx → null + danger toast surfacing error/description", async () => {
    stubFetch(
      () =>
        new Response(
          JSON.stringify({
            error: "invalid_client",
            error_description: "bad cert",
          }),
          { status: 400 },
        ),
    );
    const ctx = makeCtx();
    const result = await onRender(ctx, {
      purpose: "send",
      values: fullValues(),
    });
    expect(result).toBeNull();
    expect(ctx.toast.show).toHaveBeenCalledTimes(1);
    const arg = ctx.toast.show.mock.calls[0]![0];
    expect(arg.color).toBe("danger");
    expect(arg.message).toMatch(/invalid_client/);
    expect(arg.message).toMatch(/bad cert/);
  });

  test("fetch rejection (network/abort) → null + generic toast with no inputs", async () => {
    stubFetch(() => Promise.reject(new Error("ECONNREFUSED 1.2.3.4")));
    const ctx = makeCtx();
    const result = await onRender(ctx, {
      purpose: "send",
      values: fullValues(),
    });
    expect(result).toBeNull();
    expect(ctx.toast.show).toHaveBeenCalledTimes(1);
    const arg = ctx.toast.show.mock.calls[0]![0];
    expect(arg.color).toBe("danger");
    // Generic message — must not echo the raw error or any input.
    expect(arg.message).not.toContain("ECONNREFUSED");
    expect(arg.message).not.toContain(privateKeyPem.slice(40, 80));
  });
});

describe("netsuite.exchangeToken", () => {
  test("registers with accountId + assertion args (assertion masked)", () => {
    expect(exchangeFn.name).toBe("netsuite.exchangeToken");
    const names = exchangeFn.args.map((a) => (a as { name: string }).name);
    expect(names).toEqual(["accountId", "assertion"]);
    const assertionArg = exchangeFn.args.find(
      (a) => (a as { name: string }).name === "assertion",
    ) as { password?: boolean };
    expect(assertionArg.password).toBe(true);
  });

  test("missing assertion → null, no network call", async () => {
    const spy = stubFetch(() => tokenResponse());
    const result = await onRenderExchange(makeCtx(), {
      purpose: "send",
      values: { accountId: "391656-sb1" },
    });
    expect(result).toBeNull();
    expect(spy).not.toHaveBeenCalled();
  });

  test("send → POSTs the given assertion and returns the token", async () => {
    const spy = stubFetch(() => tokenResponse("exchanged"));
    const result = await onRenderExchange(makeCtx(), {
      purpose: "send",
      values: { accountId: "391656-sb1", assertion: "the.signed.jwt" },
    });
    expect(result).toBe("exchanged");
    expect(spy).toHaveBeenCalledTimes(1);
    const body = String(spy.mock.calls[0]![1]?.body ?? "");
    expect(new URLSearchParams(body).get("client_assertion")).toBe(
      "the.signed.jwt",
    );
  });

  test("preview mints too, then caches (no second network call)", async () => {
    const spy = stubFetch(() => tokenResponse("cached-exchange"));
    const values = { accountId: "391656-sb1", assertion: "abc.def.ghi" };
    const first = await onRenderExchange(makeCtx(), { purpose: "preview", values });
    expect(first).toBe("cached-exchange");
    const second = await onRenderExchange(makeCtx(), { purpose: "send", values });
    expect(second).toBe("cached-exchange");
    expect(spy).toHaveBeenCalledTimes(1);
  });
});
