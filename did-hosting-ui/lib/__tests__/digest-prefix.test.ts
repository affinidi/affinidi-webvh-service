/**
 * Tests for `digestPrefix` — the six-character code the operator compares
 * between this (requesting) screen and the approver's device.
 *
 * The load-bearing property is cross-repo: this function and
 * `vta-mobile-core`'s `match_code_from_digest` must produce the *same*
 * string for the same `payloadDigest`, because a human compares them by
 * eye and is told "if the codes differ, deny it". A silent divergence
 * does not fail loudly — it trains the operator to deny legitimate
 * changes, or worse, to stop checking.
 *
 * So the vector below is deliberately the VTA's own test vector, copied
 * verbatim from `match_code_is_derived_from_the_digest_bytes_not_the_encoding`.
 * If either side changes its derivation, this test is what notices.
 */

import { describe, expect, it } from "vitest";

import { DIGEST_PREFIX_LEN, digestPrefix } from "../digest-code";

/** Decodes to 3b0c7f1d9e2a… — the VTA's shared fixture. */
const VTA_VECTOR = "zQmSK9pGKFnmc77pqyNAPJyPKt8rMqctngfg3vwuMArwGYZ";

describe("digestPrefix", () => {
  it("agrees with vta-mobile-core on the shared vector", () => {
    expect(digestPrefix(VTA_VECTOR)).toBe("3b0c7f");
  });

  it("derives from the digest bytes, not the multibase encoding", () => {
    const code = digestPrefix(VTA_VECTOR);
    expect(code).toHaveLength(DIGEST_PREFIX_LEN);
    // Every digestMultibase starts `zQm`; a code that does too was sliced
    // off the encoding and is three characters of constant.
    expect(code.startsWith("zQm")).toBe(false);
  });

  it("gives distinct codes to distinct digests", () => {
    // sha256("payload-0") and sha256("payload-1") as digestMultibase —
    // the same two encodings the approver's doc comment uses to show that
    // every one of them opens `zQm`. That shared prefix is the regression
    // the decode guards against: slicing the encoding collides them.
    const P0 = "zQmcdLJLamhV3fpaGRVUhKdJmnimG2hA3hKj7TV38eM9RHe";
    const P1 = "zQmRTnbDmR6pcRAYMcWHdRBKn4KZmYFJLPGpM4JtEZfrgz8";
    expect(P0.slice(0, 3)).toBe(P1.slice(0, 3));

    expect(digestPrefix(P0)).toBe("d449ac");
    expect(digestPrefix(P1)).toBe("2e6709");
    expect(new Set([VTA_VECTOR, P0, P1].map(digestPrefix)).size).toBe(3);
  });

  it("fails closed on a stale bare-hex digest", () => {
    // What the wire carried before the migration. Showing its first six
    // characters would look exactly like a valid code while matching
    // nothing the approver displays.
    expect(
      digestPrefix(
        "3b0c7f1d9e2a5648c1f30b7ae4d2986153ca0f7b8d41e6295af03c8bd71e4a62",
      ),
    ).toBe("");
  });

  it("fails closed on values it cannot decode", () => {
    expect(digestPrefix("")).toBe("");
    expect(digestPrefix("z")).toBe("");
    // Valid base58btc, but not a sha2-256 multihash.
    expect(digestPrefix("z111111111111")).toBe("");
    // Non-base58 characters (0, O, I, l are excluded from the alphabet).
    expect(digestPrefix("zQm0OIl")).toBe("");
  });
});
