
//#region src/cache.ts
/**
* In-memory token cache for the NetSuite token template function.
*
* The cache lives at module scope (the plugin instance is long-lived), keyed by
* the non-secret identifying inputs. Tokens are never persisted to disk.
*/
/** Seconds of skew subtracted from the token lifetime so we re-mint early. */
const EXPIRY_SKEW_SECONDS = 60;
const store = /* @__PURE__ */ new Map();
/**
* Build a stable cache key from the non-secret identifying fields. A plain
* delimited join is sufficient — no secret material is included, so no hashing
* is needed. The unit separator (\x1f) avoids ambiguity between field values.
*/
function cacheKey(params) {
	return [
		params.accountId,
		params.clientId,
		params.certId,
		params.scope,
		params.algorithm
	].join("");
}
/** Return the cached token if present and not yet expired (relative to `now`). */
function getCached(key, now) {
	const entry = store.get(key);
	if (entry == null) return null;
	if (now >= entry.expiresAt) {
		store.delete(key);
		return null;
	}
	return entry.accessToken;
}
/**
* Cache a freshly minted token. `expiresAt = now + max(0, expiresIn - skew)`.
* The `max(0, …)` guard keeps a degenerate `expires_in < skew` from producing a
* negative TTL (such an entry is simply treated as already-expired on read).
*/
function setCached(key, accessToken, expiresIn, now) {
	const ttlSeconds = Math.max(0, expiresIn - EXPIRY_SKEW_SECONDS);
	store.set(key, {
		accessToken,
		expiresAt: now + ttlSeconds * 1e3
	});
}

//#endregion
//#region node_modules/.pnpm/jose@6.2.3/node_modules/jose/dist/webapi/lib/buffer_utils.js
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const MAX_INT32 = 2 ** 32;
function concat(...buffers) {
	const size = buffers.reduce((acc, { length }) => acc + length, 0);
	const buf = new Uint8Array(size);
	let i = 0;
	for (const buffer of buffers) {
		buf.set(buffer, i);
		i += buffer.length;
	}
	return buf;
}
function encode$1(string) {
	const bytes = new Uint8Array(string.length);
	for (let i = 0; i < string.length; i++) {
		const code = string.charCodeAt(i);
		if (code > 127) throw new TypeError("non-ASCII string encountered in encode()");
		bytes[i] = code;
	}
	return bytes;
}

//#endregion
//#region node_modules/.pnpm/jose@6.2.3/node_modules/jose/dist/webapi/lib/base64.js
function encodeBase64(input) {
	if (Uint8Array.prototype.toBase64) return input.toBase64();
	const CHUNK_SIZE = 32768;
	const arr = [];
	for (let i = 0; i < input.length; i += CHUNK_SIZE) arr.push(String.fromCharCode.apply(null, input.subarray(i, i + CHUNK_SIZE)));
	return btoa(arr.join(""));
}
function decodeBase64(encoded) {
	if (Uint8Array.fromBase64) return Uint8Array.fromBase64(encoded);
	const binary = atob(encoded);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
	return bytes;
}

//#endregion
//#region node_modules/.pnpm/jose@6.2.3/node_modules/jose/dist/webapi/util/base64url.js
function decode(input) {
	if (Uint8Array.fromBase64) return Uint8Array.fromBase64(typeof input === "string" ? input : decoder.decode(input), { alphabet: "base64url" });
	let encoded = input;
	if (encoded instanceof Uint8Array) encoded = decoder.decode(encoded);
	encoded = encoded.replace(/-/g, "+").replace(/_/g, "/");
	try {
		return decodeBase64(encoded);
	} catch {
		throw new TypeError("The input to be decoded is not correctly encoded.");
	}
}
function encode(input) {
	let unencoded = input;
	if (typeof unencoded === "string") unencoded = encoder.encode(unencoded);
	if (Uint8Array.prototype.toBase64) return unencoded.toBase64({
		alphabet: "base64url",
		omitPadding: true
	});
	return encodeBase64(unencoded).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

//#endregion
//#region node_modules/.pnpm/jose@6.2.3/node_modules/jose/dist/webapi/lib/crypto_key.js
const unusable = (name, prop = "algorithm.name") => /* @__PURE__ */ new TypeError(`CryptoKey does not support this operation, its ${prop} must be ${name}`);
const isAlgorithm = (algorithm, name) => algorithm.name === name;
function getHashLength(hash) {
	return parseInt(hash.name.slice(4), 10);
}
function checkHashLength(algorithm, expected) {
	if (getHashLength(algorithm.hash) !== expected) throw unusable(`SHA-${expected}`, "algorithm.hash");
}
function getNamedCurve(alg) {
	switch (alg) {
		case "ES256": return "P-256";
		case "ES384": return "P-384";
		case "ES512": return "P-521";
		default: throw new Error("unreachable");
	}
}
function checkUsage(key, usage) {
	if (usage && !key.usages.includes(usage)) throw new TypeError(`CryptoKey does not support this operation, its usages must include ${usage}.`);
}
function checkSigCryptoKey(key, alg, usage) {
	switch (alg) {
		case "HS256":
		case "HS384":
		case "HS512":
			if (!isAlgorithm(key.algorithm, "HMAC")) throw unusable("HMAC");
			checkHashLength(key.algorithm, parseInt(alg.slice(2), 10));
			break;
		case "RS256":
		case "RS384":
		case "RS512":
			if (!isAlgorithm(key.algorithm, "RSASSA-PKCS1-v1_5")) throw unusable("RSASSA-PKCS1-v1_5");
			checkHashLength(key.algorithm, parseInt(alg.slice(2), 10));
			break;
		case "PS256":
		case "PS384":
		case "PS512":
			if (!isAlgorithm(key.algorithm, "RSA-PSS")) throw unusable("RSA-PSS");
			checkHashLength(key.algorithm, parseInt(alg.slice(2), 10));
			break;
		case "Ed25519":
		case "EdDSA":
			if (!isAlgorithm(key.algorithm, "Ed25519")) throw unusable("Ed25519");
			break;
		case "ML-DSA-44":
		case "ML-DSA-65":
		case "ML-DSA-87":
			if (!isAlgorithm(key.algorithm, alg)) throw unusable(alg);
			break;
		case "ES256":
		case "ES384":
		case "ES512": {
			if (!isAlgorithm(key.algorithm, "ECDSA")) throw unusable("ECDSA");
			const expected = getNamedCurve(alg);
			if (key.algorithm.namedCurve !== expected) throw unusable(expected, "algorithm.namedCurve");
			break;
		}
		default: throw new TypeError("CryptoKey does not support this operation");
	}
	checkUsage(key, usage);
}

//#endregion
//#region node_modules/.pnpm/jose@6.2.3/node_modules/jose/dist/webapi/lib/invalid_key_input.js
function message(msg, actual, ...types) {
	types = types.filter(Boolean);
	if (types.length > 2) {
		const last = types.pop();
		msg += `one of type ${types.join(", ")}, or ${last}.`;
	} else if (types.length === 2) msg += `one of type ${types[0]} or ${types[1]}.`;
	else msg += `of type ${types[0]}.`;
	if (actual == null) msg += ` Received ${actual}`;
	else if (typeof actual === "function" && actual.name) msg += ` Received function ${actual.name}`;
	else if (typeof actual === "object" && actual != null) {
		if (actual.constructor?.name) msg += ` Received an instance of ${actual.constructor.name}`;
	}
	return msg;
}
const invalidKeyInput = (actual, ...types) => message("Key must be ", actual, ...types);
const withAlg = (alg, actual, ...types) => message(`Key for the ${alg} algorithm must be `, actual, ...types);

//#endregion
//#region node_modules/.pnpm/jose@6.2.3/node_modules/jose/dist/webapi/util/errors.js
var JOSEError = class extends Error {
	static code = "ERR_JOSE_GENERIC";
	code = "ERR_JOSE_GENERIC";
	constructor(message$1, options) {
		super(message$1, options);
		this.name = this.constructor.name;
		Error.captureStackTrace?.(this, this.constructor);
	}
};
var JOSENotSupported = class extends JOSEError {
	static code = "ERR_JOSE_NOT_SUPPORTED";
	code = "ERR_JOSE_NOT_SUPPORTED";
};
var JWSInvalid = class extends JOSEError {
	static code = "ERR_JWS_INVALID";
	code = "ERR_JWS_INVALID";
};
var JWTInvalid = class extends JOSEError {
	static code = "ERR_JWT_INVALID";
	code = "ERR_JWT_INVALID";
};
var JWKSMultipleMatchingKeys = class extends JOSEError {
	[Symbol.asyncIterator];
	static code = "ERR_JWKS_MULTIPLE_MATCHING_KEYS";
	code = "ERR_JWKS_MULTIPLE_MATCHING_KEYS";
	constructor(message$1 = "multiple matching keys found in the JSON Web Key Set", options) {
		super(message$1, options);
	}
};

//#endregion
//#region node_modules/.pnpm/jose@6.2.3/node_modules/jose/dist/webapi/lib/is_key_like.js
const isCryptoKey = (key) => {
	if (key?.[Symbol.toStringTag] === "CryptoKey") return true;
	try {
		return key instanceof CryptoKey;
	} catch {
		return false;
	}
};
const isKeyObject = (key) => key?.[Symbol.toStringTag] === "KeyObject";
const isKeyLike = (key) => isCryptoKey(key) || isKeyObject(key);

//#endregion
//#region node_modules/.pnpm/jose@6.2.3/node_modules/jose/dist/webapi/lib/helpers.js
const unprotected = Symbol();
function assertNotSet(value, name) {
	if (value) throw new TypeError(`${name} can only be called once`);
}

//#endregion
//#region node_modules/.pnpm/jose@6.2.3/node_modules/jose/dist/webapi/lib/type_checks.js
const isObjectLike = (value) => typeof value === "object" && value !== null;
function isObject(input) {
	if (!isObjectLike(input) || Object.prototype.toString.call(input) !== "[object Object]") return false;
	if (Object.getPrototypeOf(input) === null) return true;
	let proto = input;
	while (Object.getPrototypeOf(proto) !== null) proto = Object.getPrototypeOf(proto);
	return Object.getPrototypeOf(input) === proto;
}
function isDisjoint(...headers) {
	const sources = headers.filter(Boolean);
	if (sources.length === 0 || sources.length === 1) return true;
	let acc;
	for (const header of sources) {
		const parameters = Object.keys(header);
		if (!acc || acc.size === 0) {
			acc = new Set(parameters);
			continue;
		}
		for (const parameter of parameters) {
			if (acc.has(parameter)) return false;
			acc.add(parameter);
		}
	}
	return true;
}
const isJWK = (key) => isObject(key) && typeof key.kty === "string";
const isPrivateJWK = (key) => key.kty !== "oct" && (key.kty === "AKP" && typeof key.priv === "string" || typeof key.d === "string");
const isPublicJWK = (key) => key.kty !== "oct" && key.d === void 0 && key.priv === void 0;
const isSecretJWK = (key) => key.kty === "oct" && typeof key.k === "string";

//#endregion
//#region node_modules/.pnpm/jose@6.2.3/node_modules/jose/dist/webapi/lib/signing.js
function checkKeyLength(alg, key) {
	if (alg.startsWith("RS") || alg.startsWith("PS")) {
		const { modulusLength } = key.algorithm;
		if (typeof modulusLength !== "number" || modulusLength < 2048) throw new TypeError(`${alg} requires key modulusLength to be 2048 bits or larger`);
	}
}
function subtleAlgorithm(alg, algorithm) {
	const hash = `SHA-${alg.slice(-3)}`;
	switch (alg) {
		case "HS256":
		case "HS384":
		case "HS512": return {
			hash,
			name: "HMAC"
		};
		case "PS256":
		case "PS384":
		case "PS512": return {
			hash,
			name: "RSA-PSS",
			saltLength: parseInt(alg.slice(-3), 10) >> 3
		};
		case "RS256":
		case "RS384":
		case "RS512": return {
			hash,
			name: "RSASSA-PKCS1-v1_5"
		};
		case "ES256":
		case "ES384":
		case "ES512": return {
			hash,
			name: "ECDSA",
			namedCurve: algorithm.namedCurve
		};
		case "Ed25519":
		case "EdDSA": return { name: "Ed25519" };
		case "ML-DSA-44":
		case "ML-DSA-65":
		case "ML-DSA-87": return { name: alg };
		default: throw new JOSENotSupported(`alg ${alg} is not supported either by JOSE or your javascript runtime`);
	}
}
async function getSigKey(alg, key, usage) {
	if (key instanceof Uint8Array) {
		if (!alg.startsWith("HS")) throw new TypeError(invalidKeyInput(key, "CryptoKey", "KeyObject", "JSON Web Key"));
		return crypto.subtle.importKey("raw", key, {
			hash: `SHA-${alg.slice(-3)}`,
			name: "HMAC"
		}, false, [usage]);
	}
	checkSigCryptoKey(key, alg, usage);
	return key;
}
async function sign(alg, key, data) {
	const cryptoKey = await getSigKey(alg, key, "sign");
	checkKeyLength(alg, cryptoKey);
	const signature = await crypto.subtle.sign(subtleAlgorithm(alg, cryptoKey.algorithm), cryptoKey, data);
	return new Uint8Array(signature);
}

//#endregion
//#region node_modules/.pnpm/jose@6.2.3/node_modules/jose/dist/webapi/lib/jwk_to_key.js
const unsupportedAlg = "Invalid or unsupported JWK \"alg\" (Algorithm) Parameter value";
function subtleMapping(jwk) {
	let algorithm;
	let keyUsages;
	switch (jwk.kty) {
		case "AKP":
			switch (jwk.alg) {
				case "ML-DSA-44":
				case "ML-DSA-65":
				case "ML-DSA-87":
					algorithm = { name: jwk.alg };
					keyUsages = jwk.priv ? ["sign"] : ["verify"];
					break;
				default: throw new JOSENotSupported(unsupportedAlg);
			}
			break;
		case "RSA":
			switch (jwk.alg) {
				case "PS256":
				case "PS384":
				case "PS512":
					algorithm = {
						name: "RSA-PSS",
						hash: `SHA-${jwk.alg.slice(-3)}`
					};
					keyUsages = jwk.d ? ["sign"] : ["verify"];
					break;
				case "RS256":
				case "RS384":
				case "RS512":
					algorithm = {
						name: "RSASSA-PKCS1-v1_5",
						hash: `SHA-${jwk.alg.slice(-3)}`
					};
					keyUsages = jwk.d ? ["sign"] : ["verify"];
					break;
				case "RSA-OAEP":
				case "RSA-OAEP-256":
				case "RSA-OAEP-384":
				case "RSA-OAEP-512":
					algorithm = {
						name: "RSA-OAEP",
						hash: `SHA-${parseInt(jwk.alg.slice(-3), 10) || 1}`
					};
					keyUsages = jwk.d ? ["decrypt", "unwrapKey"] : ["encrypt", "wrapKey"];
					break;
				default: throw new JOSENotSupported(unsupportedAlg);
			}
			break;
		case "EC":
			switch (jwk.alg) {
				case "ES256":
				case "ES384":
				case "ES512":
					algorithm = {
						name: "ECDSA",
						namedCurve: {
							ES256: "P-256",
							ES384: "P-384",
							ES512: "P-521"
						}[jwk.alg]
					};
					keyUsages = jwk.d ? ["sign"] : ["verify"];
					break;
				case "ECDH-ES":
				case "ECDH-ES+A128KW":
				case "ECDH-ES+A192KW":
				case "ECDH-ES+A256KW":
					algorithm = {
						name: "ECDH",
						namedCurve: jwk.crv
					};
					keyUsages = jwk.d ? ["deriveBits"] : [];
					break;
				default: throw new JOSENotSupported(unsupportedAlg);
			}
			break;
		case "OKP":
			switch (jwk.alg) {
				case "Ed25519":
				case "EdDSA":
					algorithm = { name: "Ed25519" };
					keyUsages = jwk.d ? ["sign"] : ["verify"];
					break;
				case "ECDH-ES":
				case "ECDH-ES+A128KW":
				case "ECDH-ES+A192KW":
				case "ECDH-ES+A256KW":
					algorithm = { name: jwk.crv };
					keyUsages = jwk.d ? ["deriveBits"] : [];
					break;
				default: throw new JOSENotSupported(unsupportedAlg);
			}
			break;
		default: throw new JOSENotSupported("Invalid or unsupported JWK \"kty\" (Key Type) Parameter value");
	}
	return {
		algorithm,
		keyUsages
	};
}
async function jwkToKey(jwk) {
	if (!jwk.alg) throw new TypeError("\"alg\" argument is required when \"jwk.alg\" is not present");
	const { algorithm, keyUsages } = subtleMapping(jwk);
	const keyData = { ...jwk };
	if (keyData.kty !== "AKP") delete keyData.alg;
	delete keyData.use;
	return crypto.subtle.importKey("jwk", keyData, algorithm, jwk.ext ?? (jwk.d || jwk.priv ? false : true), jwk.key_ops ?? keyUsages);
}

//#endregion
//#region node_modules/.pnpm/jose@6.2.3/node_modules/jose/dist/webapi/lib/normalize_key.js
const unusableForAlg = "given KeyObject instance cannot be used for this algorithm";
let cache;
const handleJWK = async (key, jwk, alg, freeze = false) => {
	cache ||= /* @__PURE__ */ new WeakMap();
	let cached = cache.get(key);
	if (cached?.[alg]) return cached[alg];
	const cryptoKey = await jwkToKey({
		...jwk,
		alg
	});
	if (freeze) Object.freeze(key);
	if (!cached) cache.set(key, { [alg]: cryptoKey });
	else cached[alg] = cryptoKey;
	return cryptoKey;
};
const handleKeyObject = (keyObject, alg) => {
	cache ||= /* @__PURE__ */ new WeakMap();
	let cached = cache.get(keyObject);
	if (cached?.[alg]) return cached[alg];
	const isPublic = keyObject.type === "public";
	const extractable = isPublic ? true : false;
	let cryptoKey;
	if (keyObject.asymmetricKeyType === "x25519") {
		switch (alg) {
			case "ECDH-ES":
			case "ECDH-ES+A128KW":
			case "ECDH-ES+A192KW":
			case "ECDH-ES+A256KW": break;
			default: throw new TypeError(unusableForAlg);
		}
		cryptoKey = keyObject.toCryptoKey(keyObject.asymmetricKeyType, extractable, isPublic ? [] : ["deriveBits"]);
	}
	if (keyObject.asymmetricKeyType === "ed25519") {
		if (alg !== "EdDSA" && alg !== "Ed25519") throw new TypeError(unusableForAlg);
		cryptoKey = keyObject.toCryptoKey(keyObject.asymmetricKeyType, extractable, [isPublic ? "verify" : "sign"]);
	}
	switch (keyObject.asymmetricKeyType) {
		case "ml-dsa-44":
		case "ml-dsa-65":
		case "ml-dsa-87":
			if (alg !== keyObject.asymmetricKeyType.toUpperCase()) throw new TypeError(unusableForAlg);
			cryptoKey = keyObject.toCryptoKey(keyObject.asymmetricKeyType, extractable, [isPublic ? "verify" : "sign"]);
	}
	if (keyObject.asymmetricKeyType === "rsa") {
		let hash;
		switch (alg) {
			case "RSA-OAEP":
				hash = "SHA-1";
				break;
			case "RS256":
			case "PS256":
			case "RSA-OAEP-256":
				hash = "SHA-256";
				break;
			case "RS384":
			case "PS384":
			case "RSA-OAEP-384":
				hash = "SHA-384";
				break;
			case "RS512":
			case "PS512":
			case "RSA-OAEP-512":
				hash = "SHA-512";
				break;
			default: throw new TypeError(unusableForAlg);
		}
		if (alg.startsWith("RSA-OAEP")) return keyObject.toCryptoKey({
			name: "RSA-OAEP",
			hash
		}, extractable, isPublic ? ["encrypt"] : ["decrypt"]);
		cryptoKey = keyObject.toCryptoKey({
			name: alg.startsWith("PS") ? "RSA-PSS" : "RSASSA-PKCS1-v1_5",
			hash
		}, extractable, [isPublic ? "verify" : "sign"]);
	}
	if (keyObject.asymmetricKeyType === "ec") {
		const namedCurve = new Map([
			["prime256v1", "P-256"],
			["secp384r1", "P-384"],
			["secp521r1", "P-521"]
		]).get(keyObject.asymmetricKeyDetails?.namedCurve);
		if (!namedCurve) throw new TypeError(unusableForAlg);
		const expectedCurve = {
			ES256: "P-256",
			ES384: "P-384",
			ES512: "P-521"
		};
		if (expectedCurve[alg] && namedCurve === expectedCurve[alg]) cryptoKey = keyObject.toCryptoKey({
			name: "ECDSA",
			namedCurve
		}, extractable, [isPublic ? "verify" : "sign"]);
		if (alg.startsWith("ECDH-ES")) cryptoKey = keyObject.toCryptoKey({
			name: "ECDH",
			namedCurve
		}, extractable, isPublic ? [] : ["deriveBits"]);
	}
	if (!cryptoKey) throw new TypeError(unusableForAlg);
	if (!cached) cache.set(keyObject, { [alg]: cryptoKey });
	else cached[alg] = cryptoKey;
	return cryptoKey;
};
async function normalizeKey(key, alg) {
	if (key instanceof Uint8Array) return key;
	if (isCryptoKey(key)) return key;
	if (isKeyObject(key)) {
		if (key.type === "secret") return key.export();
		if ("toCryptoKey" in key && typeof key.toCryptoKey === "function") try {
			return handleKeyObject(key, alg);
		} catch (err) {
			if (err instanceof TypeError) throw err;
		}
		return handleJWK(key, key.export({ format: "jwk" }), alg);
	}
	if (isJWK(key)) {
		if (key.k) return decode(key.k);
		return handleJWK(key, key, alg, true);
	}
	throw new Error("unreachable");
}

//#endregion
//#region node_modules/.pnpm/jose@6.2.3/node_modules/jose/dist/webapi/lib/asn1.js
const bytesEqual = (a, b) => {
	if (a.byteLength !== b.length) return false;
	for (let i = 0; i < a.byteLength; i++) if (a[i] !== b[i]) return false;
	return true;
};
const createASN1State = (data) => ({
	data,
	pos: 0
});
const parseLength = (state) => {
	const first = state.data[state.pos++];
	if (first & 128) {
		const lengthOfLen = first & 127;
		let length = 0;
		for (let i = 0; i < lengthOfLen; i++) length = length << 8 | state.data[state.pos++];
		return length;
	}
	return first;
};
const expectTag = (state, expectedTag, errorMessage) => {
	if (state.data[state.pos++] !== expectedTag) throw new Error(errorMessage);
};
const getSubarray = (state, length) => {
	const result = state.data.subarray(state.pos, state.pos + length);
	state.pos += length;
	return result;
};
const parseAlgorithmOID = (state) => {
	expectTag(state, 6, "Expected algorithm OID");
	return getSubarray(state, parseLength(state));
};
function parsePKCS8Header(state) {
	expectTag(state, 48, "Invalid PKCS#8 structure");
	parseLength(state);
	expectTag(state, 2, "Expected version field");
	const verLen = parseLength(state);
	state.pos += verLen;
	expectTag(state, 48, "Expected algorithm identifier");
	const algIdLen = parseLength(state);
	return {
		algIdStart: state.pos,
		algIdLength: algIdLen
	};
}
const parseECAlgorithmIdentifier = (state) => {
	const algOid = parseAlgorithmOID(state);
	if (bytesEqual(algOid, [
		43,
		101,
		110
	])) return "X25519";
	if (!bytesEqual(algOid, [
		42,
		134,
		72,
		206,
		61,
		2,
		1
	])) throw new Error("Unsupported key algorithm");
	expectTag(state, 6, "Expected curve OID");
	const curveOid = getSubarray(state, parseLength(state));
	for (const { name, oid } of [
		{
			name: "P-256",
			oid: [
				42,
				134,
				72,
				206,
				61,
				3,
				1,
				7
			]
		},
		{
			name: "P-384",
			oid: [
				43,
				129,
				4,
				0,
				34
			]
		},
		{
			name: "P-521",
			oid: [
				43,
				129,
				4,
				0,
				35
			]
		}
	]) if (bytesEqual(curveOid, oid)) return name;
	throw new Error("Unsupported named curve");
};
const genericImport = async (keyFormat, keyData, alg, options) => {
	let algorithm;
	let keyUsages;
	const isPublic = keyFormat === "spki";
	const getSigUsages = () => isPublic ? ["verify"] : ["sign"];
	const getEncUsages = () => isPublic ? ["encrypt", "wrapKey"] : ["decrypt", "unwrapKey"];
	switch (alg) {
		case "PS256":
		case "PS384":
		case "PS512":
			algorithm = {
				name: "RSA-PSS",
				hash: `SHA-${alg.slice(-3)}`
			};
			keyUsages = getSigUsages();
			break;
		case "RS256":
		case "RS384":
		case "RS512":
			algorithm = {
				name: "RSASSA-PKCS1-v1_5",
				hash: `SHA-${alg.slice(-3)}`
			};
			keyUsages = getSigUsages();
			break;
		case "RSA-OAEP":
		case "RSA-OAEP-256":
		case "RSA-OAEP-384":
		case "RSA-OAEP-512":
			algorithm = {
				name: "RSA-OAEP",
				hash: `SHA-${parseInt(alg.slice(-3), 10) || 1}`
			};
			keyUsages = getEncUsages();
			break;
		case "ES256":
		case "ES384":
		case "ES512":
			algorithm = {
				name: "ECDSA",
				namedCurve: {
					ES256: "P-256",
					ES384: "P-384",
					ES512: "P-521"
				}[alg]
			};
			keyUsages = getSigUsages();
			break;
		case "ECDH-ES":
		case "ECDH-ES+A128KW":
		case "ECDH-ES+A192KW":
		case "ECDH-ES+A256KW":
			try {
				const namedCurve = options.getNamedCurve(keyData);
				algorithm = namedCurve === "X25519" ? { name: "X25519" } : {
					name: "ECDH",
					namedCurve
				};
			} catch (cause) {
				throw new JOSENotSupported("Invalid or unsupported key format");
			}
			keyUsages = isPublic ? [] : ["deriveBits"];
			break;
		case "Ed25519":
		case "EdDSA":
			algorithm = { name: "Ed25519" };
			keyUsages = getSigUsages();
			break;
		case "ML-DSA-44":
		case "ML-DSA-65":
		case "ML-DSA-87":
			algorithm = { name: alg };
			keyUsages = getSigUsages();
			break;
		default: throw new JOSENotSupported("Invalid or unsupported \"alg\" (Algorithm) value");
	}
	return crypto.subtle.importKey(keyFormat, keyData, algorithm, options?.extractable ?? (isPublic ? true : false), keyUsages);
};
const processPEMData = (pem, pattern) => {
	return decodeBase64(pem.replace(pattern, ""));
};
const fromPKCS8 = (pem, alg, options) => {
	const keyData = processPEMData(pem, /(?:-----(?:BEGIN|END) PRIVATE KEY-----|\s)/g);
	let opts = options;
	if (alg?.startsWith?.("ECDH-ES")) {
		opts ||= {};
		opts.getNamedCurve = (keyData$1) => {
			const state = createASN1State(keyData$1);
			parsePKCS8Header(state);
			return parseECAlgorithmIdentifier(state);
		};
	}
	return genericImport("pkcs8", keyData, alg, opts);
};

//#endregion
//#region node_modules/.pnpm/jose@6.2.3/node_modules/jose/dist/webapi/key/import.js
async function importPKCS8(pkcs8, alg, options) {
	if (typeof pkcs8 !== "string" || pkcs8.indexOf("-----BEGIN PRIVATE KEY-----") !== 0) throw new TypeError("\"pkcs8\" must be PKCS#8 formatted string");
	return fromPKCS8(pkcs8, alg, options);
}

//#endregion
//#region node_modules/.pnpm/jose@6.2.3/node_modules/jose/dist/webapi/lib/validate_crit.js
function validateCrit(Err, recognizedDefault, recognizedOption, protectedHeader, joseHeader) {
	if (joseHeader.crit !== void 0 && protectedHeader?.crit === void 0) throw new Err("\"crit\" (Critical) Header Parameter MUST be integrity protected");
	if (!protectedHeader || protectedHeader.crit === void 0) return /* @__PURE__ */ new Set();
	if (!Array.isArray(protectedHeader.crit) || protectedHeader.crit.length === 0 || protectedHeader.crit.some((input) => typeof input !== "string" || input.length === 0)) throw new Err("\"crit\" (Critical) Header Parameter MUST be an array of non-empty strings when present");
	let recognized;
	if (recognizedOption !== void 0) recognized = new Map([...Object.entries(recognizedOption), ...recognizedDefault.entries()]);
	else recognized = recognizedDefault;
	for (const parameter of protectedHeader.crit) {
		if (!recognized.has(parameter)) throw new JOSENotSupported(`Extension Header Parameter "${parameter}" is not recognized`);
		if (joseHeader[parameter] === void 0) throw new Err(`Extension Header Parameter "${parameter}" is missing`);
		if (recognized.get(parameter) && protectedHeader[parameter] === void 0) throw new Err(`Extension Header Parameter "${parameter}" MUST be integrity protected`);
	}
	return new Set(protectedHeader.crit);
}

//#endregion
//#region node_modules/.pnpm/jose@6.2.3/node_modules/jose/dist/webapi/lib/check_key_type.js
const tag = (key) => key?.[Symbol.toStringTag];
const jwkMatchesOp = (alg, key, usage) => {
	if (key.use !== void 0) {
		let expected;
		switch (usage) {
			case "sign":
			case "verify":
				expected = "sig";
				break;
			case "encrypt":
			case "decrypt":
				expected = "enc";
				break;
		}
		if (key.use !== expected) throw new TypeError(`Invalid key for this operation, its "use" must be "${expected}" when present`);
	}
	if (key.alg !== void 0 && key.alg !== alg) throw new TypeError(`Invalid key for this operation, its "alg" must be "${alg}" when present`);
	if (Array.isArray(key.key_ops)) {
		let expectedKeyOp;
		switch (true) {
			case usage === "sign" || usage === "verify":
			case alg === "dir":
			case alg.includes("CBC-HS"):
				expectedKeyOp = usage;
				break;
			case alg.startsWith("PBES2"):
				expectedKeyOp = "deriveBits";
				break;
			case /^A\d{3}(?:GCM)?(?:KW)?$/.test(alg):
				if (!alg.includes("GCM") && alg.endsWith("KW")) expectedKeyOp = usage === "encrypt" ? "wrapKey" : "unwrapKey";
				else expectedKeyOp = usage;
				break;
			case usage === "encrypt" && alg.startsWith("RSA"):
				expectedKeyOp = "wrapKey";
				break;
			case usage === "decrypt":
				expectedKeyOp = alg.startsWith("RSA") ? "unwrapKey" : "deriveBits";
				break;
		}
		if (expectedKeyOp && key.key_ops?.includes?.(expectedKeyOp) === false) throw new TypeError(`Invalid key for this operation, its "key_ops" must include "${expectedKeyOp}" when present`);
	}
	return true;
};
const symmetricTypeCheck = (alg, key, usage) => {
	if (key instanceof Uint8Array) return;
	if (isJWK(key)) {
		if (isSecretJWK(key) && jwkMatchesOp(alg, key, usage)) return;
		throw new TypeError(`JSON Web Key for symmetric algorithms must have JWK "kty" (Key Type) equal to "oct" and the JWK "k" (Key Value) present`);
	}
	if (!isKeyLike(key)) throw new TypeError(withAlg(alg, key, "CryptoKey", "KeyObject", "JSON Web Key", "Uint8Array"));
	if (key.type !== "secret") throw new TypeError(`${tag(key)} instances for symmetric algorithms must be of type "secret"`);
};
const asymmetricTypeCheck = (alg, key, usage) => {
	if (isJWK(key)) switch (usage) {
		case "decrypt":
		case "sign":
			if (isPrivateJWK(key) && jwkMatchesOp(alg, key, usage)) return;
			throw new TypeError(`JSON Web Key for this operation must be a private JWK`);
		case "encrypt":
		case "verify":
			if (isPublicJWK(key) && jwkMatchesOp(alg, key, usage)) return;
			throw new TypeError(`JSON Web Key for this operation must be a public JWK`);
	}
	if (!isKeyLike(key)) throw new TypeError(withAlg(alg, key, "CryptoKey", "KeyObject", "JSON Web Key"));
	if (key.type === "secret") throw new TypeError(`${tag(key)} instances for asymmetric algorithms must not be of type "secret"`);
	if (key.type === "public") switch (usage) {
		case "sign": throw new TypeError(`${tag(key)} instances for asymmetric algorithm signing must be of type "private"`);
		case "decrypt": throw new TypeError(`${tag(key)} instances for asymmetric algorithm decryption must be of type "private"`);
	}
	if (key.type === "private") switch (usage) {
		case "verify": throw new TypeError(`${tag(key)} instances for asymmetric algorithm verifying must be of type "public"`);
		case "encrypt": throw new TypeError(`${tag(key)} instances for asymmetric algorithm encryption must be of type "public"`);
	}
};
function checkKeyType(alg, key, usage) {
	switch (alg.substring(0, 2)) {
		case "A1":
		case "A2":
		case "di":
		case "HS":
		case "PB":
			symmetricTypeCheck(alg, key, usage);
			break;
		default: asymmetricTypeCheck(alg, key, usage);
	}
}

//#endregion
//#region node_modules/.pnpm/jose@6.2.3/node_modules/jose/dist/webapi/lib/jwt_claims_set.js
const epoch = (date) => Math.floor(date.getTime() / 1e3);
const minute = 60;
const hour = minute * 60;
const day = hour * 24;
const week = day * 7;
const year = day * 365.25;
const REGEX = /^(\+|\-)? ?(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?$/i;
function secs(str) {
	const matched = REGEX.exec(str);
	if (!matched || matched[4] && matched[1]) throw new TypeError("Invalid time period format");
	const value = parseFloat(matched[2]);
	const unit = matched[3].toLowerCase();
	let numericDate;
	switch (unit) {
		case "sec":
		case "secs":
		case "second":
		case "seconds":
		case "s":
			numericDate = Math.round(value);
			break;
		case "minute":
		case "minutes":
		case "min":
		case "mins":
		case "m":
			numericDate = Math.round(value * minute);
			break;
		case "hour":
		case "hours":
		case "hr":
		case "hrs":
		case "h":
			numericDate = Math.round(value * hour);
			break;
		case "day":
		case "days":
		case "d":
			numericDate = Math.round(value * day);
			break;
		case "week":
		case "weeks":
		case "w":
			numericDate = Math.round(value * week);
			break;
		default:
			numericDate = Math.round(value * year);
			break;
	}
	if (matched[1] === "-" || matched[4] === "ago") return -numericDate;
	return numericDate;
}
function validateInput(label, input) {
	if (!Number.isFinite(input)) throw new TypeError(`Invalid ${label} input`);
	return input;
}
var JWTClaimsBuilder = class {
	#payload;
	constructor(payload) {
		if (!isObject(payload)) throw new TypeError("JWT Claims Set MUST be an object");
		this.#payload = structuredClone(payload);
	}
	data() {
		return encoder.encode(JSON.stringify(this.#payload));
	}
	get iss() {
		return this.#payload.iss;
	}
	set iss(value) {
		this.#payload.iss = value;
	}
	get sub() {
		return this.#payload.sub;
	}
	set sub(value) {
		this.#payload.sub = value;
	}
	get aud() {
		return this.#payload.aud;
	}
	set aud(value) {
		this.#payload.aud = value;
	}
	set jti(value) {
		this.#payload.jti = value;
	}
	set nbf(value) {
		if (typeof value === "number") this.#payload.nbf = validateInput("setNotBefore", value);
		else if (value instanceof Date) this.#payload.nbf = validateInput("setNotBefore", epoch(value));
		else this.#payload.nbf = epoch(/* @__PURE__ */ new Date()) + secs(value);
	}
	set exp(value) {
		if (typeof value === "number") this.#payload.exp = validateInput("setExpirationTime", value);
		else if (value instanceof Date) this.#payload.exp = validateInput("setExpirationTime", epoch(value));
		else this.#payload.exp = epoch(/* @__PURE__ */ new Date()) + secs(value);
	}
	set iat(value) {
		if (value === void 0) this.#payload.iat = epoch(/* @__PURE__ */ new Date());
		else if (value instanceof Date) this.#payload.iat = validateInput("setIssuedAt", epoch(value));
		else if (typeof value === "string") this.#payload.iat = validateInput("setIssuedAt", epoch(/* @__PURE__ */ new Date()) + secs(value));
		else this.#payload.iat = validateInput("setIssuedAt", value);
	}
};

//#endregion
//#region node_modules/.pnpm/jose@6.2.3/node_modules/jose/dist/webapi/jws/flattened/sign.js
var FlattenedSign = class {
	#payload;
	#protectedHeader;
	#unprotectedHeader;
	constructor(payload) {
		if (!(payload instanceof Uint8Array)) throw new TypeError("payload must be an instance of Uint8Array");
		this.#payload = payload;
	}
	setProtectedHeader(protectedHeader) {
		assertNotSet(this.#protectedHeader, "setProtectedHeader");
		this.#protectedHeader = protectedHeader;
		return this;
	}
	setUnprotectedHeader(unprotectedHeader) {
		assertNotSet(this.#unprotectedHeader, "setUnprotectedHeader");
		this.#unprotectedHeader = unprotectedHeader;
		return this;
	}
	async sign(key, options) {
		if (!this.#protectedHeader && !this.#unprotectedHeader) throw new JWSInvalid("either setProtectedHeader or setUnprotectedHeader must be called before #sign()");
		if (!isDisjoint(this.#protectedHeader, this.#unprotectedHeader)) throw new JWSInvalid("JWS Protected and JWS Unprotected Header Parameter names must be disjoint");
		const joseHeader = {
			...this.#protectedHeader,
			...this.#unprotectedHeader
		};
		const extensions = validateCrit(JWSInvalid, new Map([["b64", true]]), options?.crit, this.#protectedHeader, joseHeader);
		let b64 = true;
		if (extensions.has("b64")) {
			b64 = this.#protectedHeader.b64;
			if (typeof b64 !== "boolean") throw new JWSInvalid("The \"b64\" (base64url-encode payload) Header Parameter must be a boolean");
		}
		const { alg } = joseHeader;
		if (typeof alg !== "string" || !alg) throw new JWSInvalid("JWS \"alg\" (Algorithm) Header Parameter missing or invalid");
		checkKeyType(alg, key, "sign");
		let payloadS;
		let payloadB;
		if (b64) {
			payloadS = encode(this.#payload);
			payloadB = encode$1(payloadS);
		} else {
			payloadB = this.#payload;
			payloadS = "";
		}
		let protectedHeaderString;
		let protectedHeaderBytes;
		if (this.#protectedHeader) {
			protectedHeaderString = encode(JSON.stringify(this.#protectedHeader));
			protectedHeaderBytes = encode$1(protectedHeaderString);
		} else {
			protectedHeaderString = "";
			protectedHeaderBytes = new Uint8Array();
		}
		const data = concat(protectedHeaderBytes, encode$1("."), payloadB);
		const jws = {
			signature: encode(await sign(alg, await normalizeKey(key, alg), data)),
			payload: payloadS
		};
		if (this.#unprotectedHeader) jws.header = this.#unprotectedHeader;
		if (this.#protectedHeader) jws.protected = protectedHeaderString;
		return jws;
	}
};

//#endregion
//#region node_modules/.pnpm/jose@6.2.3/node_modules/jose/dist/webapi/jws/compact/sign.js
var CompactSign = class {
	#flattened;
	constructor(payload) {
		this.#flattened = new FlattenedSign(payload);
	}
	setProtectedHeader(protectedHeader) {
		this.#flattened.setProtectedHeader(protectedHeader);
		return this;
	}
	async sign(key, options) {
		const jws = await this.#flattened.sign(key, options);
		if (jws.payload === void 0) throw new TypeError("use the flattened module for creating JWS with b64: false");
		return `${jws.protected}.${jws.payload}.${jws.signature}`;
	}
};

//#endregion
//#region node_modules/.pnpm/jose@6.2.3/node_modules/jose/dist/webapi/jwt/sign.js
var SignJWT = class {
	#protectedHeader;
	#jwt;
	constructor(payload = {}) {
		this.#jwt = new JWTClaimsBuilder(payload);
	}
	setIssuer(issuer) {
		this.#jwt.iss = issuer;
		return this;
	}
	setSubject(subject) {
		this.#jwt.sub = subject;
		return this;
	}
	setAudience(audience) {
		this.#jwt.aud = audience;
		return this;
	}
	setJti(jwtId) {
		this.#jwt.jti = jwtId;
		return this;
	}
	setNotBefore(input) {
		this.#jwt.nbf = input;
		return this;
	}
	setExpirationTime(input) {
		this.#jwt.exp = input;
		return this;
	}
	setIssuedAt(input) {
		this.#jwt.iat = input;
		return this;
	}
	setProtectedHeader(protectedHeader) {
		this.#protectedHeader = protectedHeader;
		return this;
	}
	async sign(key, options) {
		const sig = new CompactSign(this.#jwt.data());
		sig.setProtectedHeader(this.#protectedHeader);
		if (Array.isArray(this.#protectedHeader?.crit) && this.#protectedHeader.crit.includes("b64") && this.#protectedHeader.b64 === false) throw new JWTInvalid("JWTs MUST NOT use unencoded payload");
		return sig.sign(key, options);
	}
};

//#endregion
//#region src/netsuite.ts
/** Backdate `iat` to absorb clock drift between the host and NetSuite. */
const IAT_SKEW_SECONDS = 30;
/** NetSuite caps the assertion lifetime at 60 minutes. */
const ASSERTION_TTL_SECONDS = 3600;
/**
* Error thrown when the token exchange fails. `message` is safe to surface to
* the user — it never contains the private key or the signed assertion.
*/
var TokenExchangeError = class extends Error {
	constructor(message$1) {
		super(message$1);
		this.name = "TokenExchangeError";
	}
};
/**
* Build the SuiteTalk REST `aud`/token URL for an account id. The host segment
* is the lowercased account id with `_` replaced by `-`
* (e.g. `1234567_SB1` → `1234567-sb1`).
*/
function audUrl(accountId) {
	return `https://${accountId.toLowerCase().replace(/_/g, "-")}.suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/token`;
}
/** Normalize a pasted PEM: convert literal `\n` escapes to real newlines. */
function normalizePem(pem) {
	return pem.replace(/\\n/g, "\n");
}
/**
* Build and sign the client-assertion JWT. `now` is ms since epoch (injectable
* for tests). Throws if the key cannot be imported or signed (e.g. the key type
* does not match `algorithm`).
*/
async function buildAssertion(params, now) {
	const iat = Math.floor(now / 1e3) - IAT_SKEW_SECONDS;
	const exp = iat + ASSERTION_TTL_SECONDS;
	const aud = audUrl(params.accountId);
	const key = await importPKCS8(normalizePem(params.privateKey), params.algorithm);
	return new SignJWT({ scope: params.scope }).setProtectedHeader({
		alg: params.algorithm,
		typ: "JWT",
		kid: params.certId
	}).setIssuer(params.clientId).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(key);
}
/** The form fields required by the NetSuite token endpoint. */
function buildFormBody(assertion) {
	const form = new URLSearchParams();
	form.set("grant_type", "client_credentials");
	form.set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
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
async function exchangeAssertion(accountId, assertion, send) {
	const result = await send({
		url: audUrl(accountId),
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body: buildFormBody(assertion)
	});
	if (result.status < 200 || result.status >= 300) throw new TokenExchangeError(describeError(result));
	let parsed;
	try {
		parsed = JSON.parse(result.body);
	} catch {
		throw new TokenExchangeError(`NetSuite returned a non-JSON token response (status ${result.status})`);
	}
	const accessToken = parsed?.["access_token"];
	const expiresIn = parsed?.["expires_in"];
	if (typeof accessToken !== "string" || accessToken.length === 0) throw new TokenExchangeError("NetSuite response did not contain an access_token");
	if (typeof expiresIn !== "number" || !Number.isFinite(expiresIn) || expiresIn <= 0) throw new TokenExchangeError("NetSuite response did not contain a valid expires_in");
	return {
		accessToken,
		expiresIn
	};
}
/**
* Build (sign) the assertion from `params`, then exchange it. Throws
* `TokenExchangeError` (safe message) on a signing failure, non-2xx, or a
* malformed body.
*/
async function exchangeToken(params, send, now) {
	let assertion;
	try {
		assertion = await buildAssertion(params, now);
	} catch {
		throw new TokenExchangeError("Failed to sign the assertion — check the private key is valid PKCS#8 PEM and matches the selected algorithm");
	}
	return exchangeAssertion(params.accountId, assertion, send);
}
/**
* Derive a safe, debuggable message from a non-2xx response. Surfaces only the
* standard OAuth `error` / `error_description` fields, never the full raw body.
*/
function describeError(result) {
	try {
		const body = JSON.parse(result.body);
		const error = typeof body["error"] === "string" ? body["error"] : void 0;
		const description = typeof body["error_description"] === "string" ? body["error_description"] : void 0;
		if (error || description) return `NetSuite token request failed (${result.status}): ${[error, description].filter(Boolean).join(" — ")}`;
	} catch {}
	return `NetSuite token request failed (status ${result.status})`;
}

//#endregion
//#region src/index.ts
const DEFAULT_SCOPE = "rest_webservices";
const FETCH_TIMEOUT_MS = 3e4;
/**
* `fetch`-based transport. Lives here (not in `netsuite.ts`) so the core stays
* environment-free. Enforces a timeout via `AbortController`; an abort rejects
* and is caught by the render helper → null + toast.
*/
async function fetchSender(req) {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
	try {
		const res = await fetch(req.url, {
			method: req.method,
			headers: req.headers,
			body: req.body,
			signal: controller.signal
		});
		const body = await res.text();
		return {
			status: res.status,
			body
		};
	} finally {
		clearTimeout(timer);
	}
}
/** Read a value as a trimmed string, or null if absent/empty. */
function readString(values, name) {
	const raw = values[name];
	if (typeof raw !== "string") return null;
	const trimmed = raw.trim();
	return trimmed.length > 0 ? trimmed : null;
}
function readAlgorithm(values) {
	return values["algorithm"] === "ES256" ? "ES256" : "PS256";
}
/**
* Shared render logic for both token functions: serve a cached token, otherwise
* mint via `mint`, cache it, and return it.
*
* Both `send` and `preview` mint on a cache miss, so the editor's Rendered
* Preview (and its refresh button — Yaak renders both with purpose 'preview')
* shows a real token. The caller's required-arg guard plus the ~1h token cache
* bound this to at most one mint per credential set, so it does not re-sign or
* re-POST on every keystroke. Error toasts are surfaced only on a real send;
* during preview a failure returns null silently to avoid noise while args are
* being configured.
*/
async function renderCachedToken(ctx, purpose, key, mint) {
	const now = Date.now();
	const cached = getCached(key, now);
	if (cached != null) return cached;
	try {
		const { accessToken, expiresIn } = await mint(now);
		setCached(key, accessToken, expiresIn, now);
		return accessToken;
	} catch (err) {
		if (purpose === "send") {
			const message$1 = err instanceof Error && err.name === "TokenExchangeError" ? err.message : "NetSuite token request failed";
			await ctx.toast.show({
				color: "danger",
				message: message$1
			});
		}
		return null;
	}
}
const plugin = { templateFunctions: [{
	name: "netsuite.token",
	description: "Mint a NetSuite OAuth2 client-credentials (JWT-bearer) access token, usable in an Authorization: Bearer header. Caches until just before expiry.",
	args: [
		{
			type: "text",
			name: "accountId",
			label: "Account ID",
			placeholder: "1234567 or 1234567_SB1",
			description: "NetSuite account id; used to build the token URL host."
		},
		{
			type: "text",
			name: "clientId",
			label: "Client ID (Consumer Key)",
			description: "Becomes the JWT `iss` and the POST `client_id`."
		},
		{
			type: "text",
			name: "certId",
			label: "Certificate ID",
			description: "NetSuite-assigned certificate mapping id → JWT header `kid`."
		},
		{
			type: "text",
			name: "privateKey",
			label: "Private Key (PKCS#8 PEM)",
			password: true,
			multiLine: true,
			description: "PKCS#8 PEM. Recommended: store as a Yaak secret and reference it as ${[ secret_name ]} rather than typing it inline."
		},
		{
			type: "text",
			name: "scope",
			label: "Scope",
			defaultValue: DEFAULT_SCOPE,
			description: "Space-delimited scope(s), e.g. `rest_webservices` or `restlets`."
		},
		{
			type: "select",
			name: "algorithm",
			label: "Algorithm",
			defaultValue: "PS256",
			description: "Must match the key type: PS256 ⇒ RSA, ES256 ⇒ EC P-256.",
			options: [{
				label: "PS256",
				value: "PS256"
			}, {
				label: "ES256",
				value: "ES256"
			}]
		}
	],
	async onRender(ctx, args) {
		const values = args.values ?? {};
		const accountId = readString(values, "accountId");
		const clientId = readString(values, "clientId");
		const certId = readString(values, "certId");
		const privateKey = readString(values, "privateKey");
		if (!accountId || !clientId || !certId || !privateKey) return null;
		const params = {
			accountId,
			clientId,
			certId,
			privateKey,
			scope: readString(values, "scope") ?? DEFAULT_SCOPE,
			algorithm: readAlgorithm(values)
		};
		return renderCachedToken(ctx, args.purpose, cacheKey(params), (now) => exchangeToken(params, fetchSender, now));
	}
}] };

//#endregion
exports.plugin = plugin;