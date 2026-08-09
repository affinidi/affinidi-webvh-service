/**
 * The operator's six-character comparison code, derived from a
 * `payloadDigest`.
 *
 * Kept in its own module — with no imports — so it is reachable from the
 * test runner. `wallet.ts` pulls in `react-native`, which vitest cannot
 * parse, and this is the piece whose agreement with the approver's device
 * most needs pinning down. `wallet.ts` re-exports both names, so callers
 * are unaffected.
 */

/**
 * How much of the digest a human is asked to compare.
 *
 * Must stay equal to `vta-mobile-core`'s `MATCH_CODE_LEN`, and derived
 * the same way: this is the *requesting* screen, the approver's device
 * is the other one, and the operator compares the two by eye. Changing
 * the derivation on one side alone breaks matching outright.
 */
export const DIGEST_PREFIX_LEN = 6;

const BASE58BTC_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** Multihash prefix for SHA-256 with a 32-byte digest: `0x12 0x20`. */
const MULTIHASH_SHA2_256_32 = [0x12, 0x20];

/**
 * Decode a base58btc payload (the body of a multibase `z…` string).
 * Returns `null` on any character outside the alphabet.
 *
 * Hand-rolled rather than pulled from a dependency: this is the only
 * multiformats need in the UI, and the alternative is a transitive tree
 * for twenty lines of arithmetic.
 */
function decodeBase58btc(body: string): Uint8Array | null {
  const bytes: number[] = [];
  for (const ch of body) {
    let carry = BASE58BTC_ALPHABET.indexOf(ch);
    if (carry < 0) return null;
    for (let i = 0; i < bytes.length; i++) {
      carry += bytes[i] * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  // Each leading '1' encodes one leading zero byte.
  for (const ch of body) {
    if (ch !== "1") break;
    bytes.push(0);
  }
  return new Uint8Array(bytes.reverse());
}

/**
 * The operator's comparison code: the first {@link DIGEST_PREFIX_LEN}
 * hex characters of the **digest bytes**, not of their multibase
 * encoding.
 *
 * That distinction is the whole point. `payloadDigest` is a multibase
 * multihash, so its first three characters are always `zQm` — the
 * base58btc marker plus the sha2-256 multihash prefix, identical for
 * every digest ever produced:
 *
 * ```text
 * zQmcdLJ…   zQmRTnb…   zQmb7oR…   zQmbu6r…     ← four different payloads
 * ```
 *
 * Slicing the encoded string would spend half a six-character code on a
 * constant, leaving ~17.6 bits where the operator believes they are
 * comparing ~35 — and it would still *look* like six random characters,
 * which is what makes it dangerous rather than merely wasteful.
 *
 * Decoding first restores the full entropy and, because the digest is
 * still SHA-256, reproduces **exactly** the code this screen showed when
 * the wire carried bare hex (`hex(digest)[..6]` either way) — so the
 * encoding migration is invisible here. This mirrors
 * `vta-mobile-core`'s `match_code_from_digest`, which the operator
 * compares against; the two derivations must stay identical.
 *
 * Fails closed: anything that is not a base58btc sha2-256 multihash
 * yields `""`, so the operator sees no code to match and denies, rather
 * than being shown a plausible-looking prefix of an unparseable value.
 */
export function digestPrefix(payloadDigest: string): string {
  if (!payloadDigest.startsWith("z")) return "";
  const bytes = decodeBase58btc(payloadDigest.slice(1));
  if (!bytes) return "";
  if (
    bytes.length < MULTIHASH_SHA2_256_32.length + DIGEST_PREFIX_LEN / 2 ||
    bytes[0] !== MULTIHASH_SHA2_256_32[0] ||
    bytes[1] !== MULTIHASH_SHA2_256_32[1]
  ) {
    return "";
  }
  const digest = bytes.subarray(MULTIHASH_SHA2_256_32.length);
  // Two hex characters per byte.
  return Array.from(digest.subarray(0, Math.ceil(DIGEST_PREFIX_LEN / 2)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, DIGEST_PREFIX_LEN);
}
