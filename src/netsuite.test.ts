import {
  decodeProtectedHeader,
  exportPKCS8,
  generateKeyPair,
  jwtVerify,
} from "jose";
import { describe, expect, test } from "vitest";
import {
  ASSERTION_TTL_SECONDS,
  IAT_SKEW_SECONDS,
  type NetsuiteTokenParams,
  type NsAlgorithm,
  type TokenRequest,
  type TokenSendResult,
  TokenExchangeError,
  audUrl,
  buildAssertion,
  exchangeAssertion,
  exchangeToken,
  normalizePem,
} from "./netsuite";

type GeneratedPublicKey = Awaited<
  ReturnType<typeof generateKeyPair>
>["publicKey"];
type KeyPair = { privateKeyPem: string; publicKey: GeneratedPublicKey };

async function makeKeyPair(alg: NsAlgorithm): Promise<KeyPair> {
  const { privateKey, publicKey } = await generateKeyPair(alg, {
    extractable: true,
  });
  return { privateKeyPem: await exportPKCS8(privateKey), publicKey };
}

async function makeParams(
  alg: NsAlgorithm,
  overrides: Partial<NetsuiteTokenParams> = {},
): Promise<{ params: NetsuiteTokenParams; key: KeyPair }> {
  const key = await makeKeyPair(alg);
  return {
    key,
    params: {
      accountId: "1234567_SB1",
      clientId: "client-abc",
      certId: "cert-xyz",
      privateKey: key.privateKeyPem,
      scope: "rest_webservices",
      algorithm: alg,
      ...overrides,
    },
  };
}

const NOW = 1_700_000_000_000; // fixed ms epoch

describe("audUrl", () => {
  test("production account id", () => {
    expect(audUrl("1234567")).toBe(
      "https://1234567.suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/token",
    );
  });

  test("sandbox account id lowercases and hyphenates", () => {
    expect(audUrl("1234567_SB1")).toBe(
      "https://1234567-sb1.suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/token",
    );
  });
});

describe("normalizePem", () => {
  test("converts literal \\n escapes to real newlines, leaving real newlines", () => {
    expect(normalizePem("a\\nb\nc")).toBe("a\nb\nc");
  });

  test("a key pasted with literal \\n escapes still imports & signs", async () => {
    const { params } = await makeParams("PS256");
    const escaped = params.privateKey.replace(/\n/g, "\\n");
    const jwt = await buildAssertion({ ...params, privateKey: escaped }, NOW);
    expect(jwt.split(".")).toHaveLength(3);
  });
});

describe("buildAssertion", () => {
  test("claims and protected header are correct", async () => {
    const { params } = await makeParams("PS256");
    const jwt = await buildAssertion(params, NOW);

    const header = decodeProtectedHeader(jwt);
    expect(header).toMatchObject({ alg: "PS256", typ: "JWT", kid: "cert-xyz" });

    const payloadB64 = jwt.split(".")[1]!;
    const payload = JSON.parse(
      Buffer.from(payloadB64, "base64url").toString("utf8"),
    );
    const nowSec = Math.floor(NOW / 1000);
    expect(payload.iss).toBe("client-abc");
    expect(payload.scope).toBe("rest_webservices");
    expect(payload.aud).toBe(audUrl("1234567_SB1"));
    expect(payload.iat).toBe(nowSec - IAT_SKEW_SECONDS);
    expect(payload.exp).toBe(payload.iat + ASSERTION_TTL_SECONDS);
  });

  test("PS256 assertion verifies against its public key, fails against a wrong key", async () => {
    const { params, key } = await makeParams("PS256");
    const jwt = await buildAssertion(params, NOW);

    const opts = { currentDate: new Date(NOW) };
    const { payload, protectedHeader } = await jwtVerify(
      jwt,
      key.publicKey,
      opts,
    );
    expect(protectedHeader.alg).toBe("PS256");
    expect(payload.iss).toBe("client-abc");

    const other = await makeKeyPair("PS256");
    await expect(jwtVerify(jwt, other.publicKey, opts)).rejects.toThrow();
  });

  test("ES256 assertion verifies against its public key", async () => {
    const { params, key } = await makeParams("ES256");
    const jwt = await buildAssertion(params, NOW);
    const { protectedHeader } = await jwtVerify(jwt, key.publicKey, {
      currentDate: new Date(NOW),
    });
    expect(protectedHeader.alg).toBe("ES256");
  });
});

describe("exchangeToken", () => {
  test("request shape: url, method, content-type, and the three form fields", async () => {
    const { params } = await makeParams("PS256");
    let captured: Parameters<Parameters<typeof exchangeToken>[1]>[0] | undefined;
    const send = async (req: typeof captured): Promise<TokenSendResult> => {
      captured = req;
      return { status: 200, body: '{"access_token":"abc","expires_in":3600}' };
    };

    await exchangeToken(params, send as never, NOW);

    expect(captured?.url).toBe(audUrl("1234567_SB1"));
    expect(captured?.method).toBe("POST");
    expect(captured?.headers["Content-Type"]).toBe(
      "application/x-www-form-urlencoded",
    );
    const form = new URLSearchParams(captured?.body);
    expect(form.get("grant_type")).toBe("client_credentials");
    expect(form.get("client_assertion_type")).toBe(
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    );
    expect(form.get("client_assertion")?.split(".")).toHaveLength(3);
  });

  test("success returns the access token and expires_in", async () => {
    const { params } = await makeParams("PS256");
    const send = async (): Promise<TokenSendResult> => ({
      status: 200,
      body: '{"access_token":"the-token","expires_in":3600}',
    });
    await expect(exchangeToken(params, send, NOW)).resolves.toEqual({
      accessToken: "the-token",
      expiresIn: 3600,
    });
  });

  test("non-2xx throws a typed error surfacing error/error_description", async () => {
    const { params } = await makeParams("PS256");
    const send = async (): Promise<TokenSendResult> => ({
      status: 400,
      body: '{"error":"invalid_client","error_description":"bad cert"}',
    });
    await expect(exchangeToken(params, send, NOW)).rejects.toBeInstanceOf(
      TokenExchangeError,
    );
    await expect(exchangeToken(params, send, NOW)).rejects.toThrow(
      /invalid_client/,
    );
    await expect(exchangeToken(params, send, NOW)).rejects.toThrow(/bad cert/);
  });

  test("missing/non-numeric expires_in throws a typed error", async () => {
    const { params } = await makeParams("PS256");
    const send = async (): Promise<TokenSendResult> => ({
      status: 200,
      body: '{"access_token":"abc"}', // no expires_in
    });
    await expect(exchangeToken(params, send, NOW)).rejects.toBeInstanceOf(
      TokenExchangeError,
    );
    await expect(exchangeToken(params, send, NOW)).rejects.toThrow(/expires_in/);
  });

  test("malformed (non-JSON) success body throws a typed error", async () => {
    const { params } = await makeParams("PS256");
    const send = async (): Promise<TokenSendResult> => ({
      status: 200,
      body: "<html>not json</html>",
    });
    await expect(exchangeToken(params, send, NOW)).rejects.toBeInstanceOf(
      TokenExchangeError,
    );
  });

});

describe("exchangeAssertion", () => {
  test("POSTs the given assertion verbatim and returns the token", async () => {
    let captured: TokenRequest | undefined;
    const send = async (req: TokenRequest): Promise<TokenSendResult> => {
      captured = req;
      return { status: 200, body: '{"access_token":"abc","expires_in":3600}' };
    };

    const result = await exchangeAssertion("1234567_SB1", "the.signed.jwt", send);

    expect(result).toEqual({ accessToken: "abc", expiresIn: 3600 });
    expect(captured?.url).toBe(audUrl("1234567_SB1"));
    expect(captured?.method).toBe("POST");
    const form = new URLSearchParams(captured?.body);
    expect(form.get("client_assertion")).toBe("the.signed.jwt");
    expect(form.get("grant_type")).toBe("client_credentials");
  });

  test("non-2xx throws a typed error", async () => {
    const send = async (): Promise<TokenSendResult> => ({
      status: 401,
      body: '{"error":"invalid_grant","error_description":"expired"}',
    });
    await expect(
      exchangeAssertion("1234567", "jwt", send),
    ).rejects.toBeInstanceOf(TokenExchangeError);
  });
});

describe("buildAssertion key/alg mismatch", () => {
  test("a key that does not match the algorithm throws a safe typed error (no key material)", async () => {
    // ES256 selected, but an RSA (PS256) key supplied → import/sign mismatch.
    const rsa = await makeKeyPair("PS256");
    const params: NetsuiteTokenParams = {
      accountId: "1234567",
      clientId: "c",
      certId: "k",
      privateKey: rsa.privateKeyPem,
      scope: "rest_webservices",
      algorithm: "ES256",
    };
    const send = async (): Promise<TokenSendResult> => ({ status: 200, body: "{}" });
    const err = await exchangeToken(params, send, NOW).catch((e) => e);
    expect(err).toBeInstanceOf(TokenExchangeError);
    expect(err.message).not.toContain("BEGIN");
    expect(err.message).not.toContain(rsa.privateKeyPem.slice(40, 80));
  });
});
