/**
 * Browser-side ephemeral session-key infrastructure for Data Integrity
 * proofs on REQUIRED-spec trust-task envelopes (acl/grant, acl/revoke,
 * acl/change-role).
 *
 * Lifecycle:
 *  1. `generateSessionKeypair()` on login — fresh Ed25519 keypair per
 *     browser session via WebCrypto. Public key is encoded as an Ed25519
 *     multikey (`z6Mk…`) and sent to the server during
 *     `/api/auth/passkey/login/finish`; the server stores it on the
 *     session record.
 *  2. `signEnvelope()` on every REQUIRED-spec request — implements the
 *     `eddsa-jcs-2022` cryptosuite (W3C VC Data Integrity ed25519):
 *     JCS-canonicalize doc and proof config, SHA-256 each, concat, sign
 *     with the session private key, base58btc-encode signature into
 *     `proof.proofValue`.
 *  3. Server-side `dispatch_trust_task` reads the bound pubkey from
 *     AuthClaims, checks that `proof.verificationMethod` matches the
 *     session-bound `did:key`, and lets the AffinidiVerifier verify
 *     the signature.
 *
 * The private key is held as a non-extractable `CryptoKey` in module
 * scope; it never crosses the JS boundary or hits storage. A page
 * reload starts a fresh session and a fresh key.
 */

// ---------------------------------------------------------------------------
// Module-scoped session state
// ---------------------------------------------------------------------------

let sessionKeypair: CryptoKeyPair | null = null;
let sessionPubkeyMultikey: string | null = null;
let sessionDidKey: string | null = null;

/**
 * Generate a fresh Ed25519 keypair for this browser session. The private
 * key is stored as a non-extractable `CryptoKey` in module scope; the
 * public key is exposed as a `did:key` multikey for the server to bind
 * to the JWT session.
 *
 * Calling twice replaces the previous keypair (e.g. on re-login).
 */
export async function generateSessionKeypair(): Promise<{
  pubkeyMultikey: string;
  didKey: string;
}> {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    throw new Error(
      "WebCrypto is not available in this environment — session-key signing requires crypto.subtle",
    );
  }

  // Ed25519 in WebCrypto is supported on Chrome 137+, Firefox 130+,
  // Safari 17+. `extractable=true` is needed to export the raw public
  // key bytes; the private key stays inside the CryptoKey wrapper and
  // is used only via `crypto.subtle.sign(...)`.
  const keypair = (await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;

  const rawPub = new Uint8Array(
    await crypto.subtle.exportKey("raw", keypair.publicKey),
  );
  if (rawPub.length !== 32) {
    throw new Error(
      `unexpected Ed25519 public key length: ${rawPub.length} bytes (expected 32)`,
    );
  }

  const multikey = ed25519Multikey(rawPub);
  const didKey = `did:key:${multikey}`;

  sessionKeypair = keypair;
  sessionPubkeyMultikey = multikey;
  sessionDidKey = didKey;

  return { pubkeyMultikey: multikey, didKey };
}

/** Returns `true` once a session keypair has been generated. */
export function hasSessionKeypair(): boolean {
  return sessionKeypair !== null;
}

/** Drop the current session keypair (logout / re-login). */
export function clearSessionKeypair(): void {
  sessionKeypair = null;
  sessionPubkeyMultikey = null;
  sessionDidKey = null;
}

// ---------------------------------------------------------------------------
// eddsa-jcs-2022 envelope signing
// ---------------------------------------------------------------------------

/** Subset of the trust-task envelope shape relevant to signing. */
export type SignableEnvelope = {
  [key: string]: unknown;
  proof?: unknown;
};

/**
 * Attach an `eddsa-jcs-2022` Data Integrity proof to a trust-task
 * envelope. Mutates `envelope.proof` in place and returns the same
 * envelope for convenience.
 *
 * Spec: https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022
 *
 * Hash data = SHA-256(JCS(proofConfig)) || SHA-256(JCS(unsignedDoc)),
 * where `unsignedDoc` is the envelope minus `proof` and `proofConfig`
 * is the proof minus `proofValue`.
 */
export async function signEnvelope<T extends SignableEnvelope>(
  envelope: T,
): Promise<T> {
  if (sessionKeypair === null || sessionDidKey === null) {
    throw new Error(
      "no session keypair available — call generateSessionKeypair() before signEnvelope()",
    );
  }

  // Build the proof object minus proofValue. `verificationMethod` is
  // the session-bound did:key fragment; server-side
  // `dispatch_trust_task` verifies this matches the JWT-bound session
  // pubkey before the framework's AffinidiVerifier resolves it.
  const proofConfig: Record<string, unknown> = {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    verificationMethod: `${sessionDidKey}#${sessionDidKey.slice("did:key:".length)}`,
    created: new Date().toISOString(),
    proofPurpose: "assertionMethod",
  };

  // Hash the proof config and the doc (envelope minus proof).
  const docCopy: SignableEnvelope = { ...envelope };
  delete docCopy.proof;
  const proofConfigHash = await sha256(jcsCanonicalize(proofConfig));
  const docHash = await sha256(jcsCanonicalize(docCopy));

  // Sign the concatenated hashes with the session private key.
  const toSign = new Uint8Array(proofConfigHash.length + docHash.length);
  toSign.set(proofConfigHash, 0);
  toSign.set(docHash, proofConfigHash.length);
  const sigBuf = await crypto.subtle.sign(
    { name: "Ed25519" },
    sessionKeypair.privateKey,
    toSign,
  );
  const sig = new Uint8Array(sigBuf);
  if (sig.length !== 64) {
    throw new Error(
      `unexpected Ed25519 signature length: ${sig.length} bytes (expected 64)`,
    );
  }

  // The W3C Data Integrity spec encodes Ed25519 proofValue as
  // base58btc with the `z` multibase prefix.
  proofConfig.proofValue = "z" + base58btcEncode(sig);
  envelope.proof = proofConfig;
  return envelope;
}

// ---------------------------------------------------------------------------
// Helpers — base58btc, multikey, JCS, SHA-256
// ---------------------------------------------------------------------------

const B58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * Encode raw bytes as base58btc. Standard Bitcoin alphabet (no `0`,
 * `O`, `I`, `l`). Preserves leading zero bytes as leading `1`s per
 * the base58btc spec.
 */
function base58btcEncode(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;

  // Convert from base-256 to base-58 by repeated division.
  const digits: number[] = [];
  for (let i = 0; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  let result = "";
  for (let i = 0; i < zeros; i++) result += B58_ALPHABET[0];
  for (let i = digits.length - 1; i >= 0; i--) result += B58_ALPHABET[digits[i]];
  return result;
}

/**
 * Encode a raw 32-byte Ed25519 public key as the W3C Data Integrity
 * multikey form: `0xed 0x01 || pubkey` base58btc-encoded with the `z`
 * multibase prefix. Produces the canonical `z6Mk…` representation.
 */
function ed25519Multikey(rawPubKey: Uint8Array): string {
  if (rawPubKey.length !== 32) {
    throw new Error(
      `Ed25519 multikey expects 32-byte pubkey, got ${rawPubKey.length}`,
    );
  }
  const prefixed = new Uint8Array(34);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(rawPubKey, 2);
  return "z" + base58btcEncode(prefixed);
}

/**
 * Canonicalize a JSON value per RFC 8785 (JSON Canonicalization
 * Scheme). The eddsa-jcs-2022 cryptosuite requires JCS output as the
 * input to SHA-256. Implemented inline (~30 LOC) rather than pulled in
 * as a dep so this module has no npm footprint.
 *
 * Rules: minified JSON, object keys sorted lexicographically by UTF-16
 * code unit, strict JSON-only string escaping (per ECMA-404), no
 * trailing commas. Numbers use ECMA-262 minimal form for finite values.
 *
 * Throws on non-finite numbers, undefined, functions, symbols, or
 * circular references — JCS doesn't model those.
 */
function jcsCanonicalize(value: unknown): string {
  const seen = new WeakSet<object>();
  return enc(value);

  function enc(v: unknown): string {
    if (v === null) return "null";
    if (v === true) return "true";
    if (v === false) return "false";
    if (typeof v === "number") {
      if (!Number.isFinite(v)) {
        throw new Error("JCS rejects non-finite numbers");
      }
      // JCS / ECMA-404 minimal numeric form. ES toString matches the
      // form for finite numbers; -0 collapses to "0".
      if (Object.is(v, -0)) return "0";
      return String(v);
    }
    if (typeof v === "string") return encString(v);
    if (Array.isArray(v)) {
      if (seen.has(v)) throw new Error("circular reference in JCS input");
      seen.add(v);
      const out = "[" + v.map(enc).join(",") + "]";
      seen.delete(v);
      return out;
    }
    if (typeof v === "object" && v !== null) {
      if (seen.has(v as object)) throw new Error("circular reference in JCS input");
      seen.add(v as object);
      const obj = v as Record<string, unknown>;
      // Keys sorted as UTF-16 code-unit strings. ECMA String#sort uses
      // exactly that ordering.
      const keys = Object.keys(obj).sort();
      const parts = keys.map((k) => encString(k) + ":" + enc(obj[k]));
      seen.delete(v as object);
      return "{" + parts.join(",") + "}";
    }
    throw new Error(`JCS cannot encode value of type ${typeof v}`);
  }

  function encString(s: string): string {
    let out = '"';
    for (let i = 0; i < s.length; i++) {
      const ch = s.charCodeAt(i);
      if (ch === 0x22) out += '\\"';
      else if (ch === 0x5c) out += "\\\\";
      else if (ch === 0x08) out += "\\b";
      else if (ch === 0x0c) out += "\\f";
      else if (ch === 0x0a) out += "\\n";
      else if (ch === 0x0d) out += "\\r";
      else if (ch === 0x09) out += "\\t";
      else if (ch < 0x20) {
        out += "\\u" + ch.toString(16).padStart(4, "0");
      } else {
        out += s[i];
      }
    }
    return out + '"';
  }
}

async function sha256(input: string): Promise<Uint8Array> {
  const buf = new TextEncoder().encode(input);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
}
