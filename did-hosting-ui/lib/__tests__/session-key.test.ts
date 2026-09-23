/**
 * Tests for the session keypair's extractability.
 *
 * The load-bearing property is that the session *private* key cannot be
 * read out by script. It is the key the server binds to the JWT session
 * and accepts `eddsa-jcs-2022` proofs from on `acl/grant`, `acl/revoke`
 * and `acl/change-role`, so an exportable copy is a portable, offline
 * forgery capability for those operations.
 *
 * The flag is easy to get wrong in exactly one direction, which is why
 * this file exists: `generateKey`'s `extractable` argument governs the
 * **private** key only — WebCrypto marks the public key of a generated
 * pair extractable unconditionally. So `exportKey("raw", publicKey)`
 * works either way, and someone reading the code who assumes the flag
 * is what makes the public key exportable will "fix" the `false` back
 * to `true` and silently hand the private key to the origin. These
 * tests measure both halves so that flip fails here instead.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  generateSessionKeypair,
  signEnvelope,
  type SignableEnvelope,
} from "../session-key";

afterEach(() => {
  vi.restoreAllMocks();
});

/** Runs `generateSessionKeypair()` and hands back the CryptoKeyPair it
 * actually created — the module keeps it private, so the only way to
 * inspect it is to watch the call it makes. */
async function captureSessionKeypair(): Promise<{
  keypair: CryptoKeyPair;
  extractableArg: unknown;
  result: { pubkeyMultikey: string; didKey: string };
}> {
  const spy = vi.spyOn(crypto.subtle, "generateKey");
  const result = await generateSessionKeypair();
  expect(spy).toHaveBeenCalledOnce();
  const keypair = (await spy.mock.results[0].value) as CryptoKeyPair;
  return { keypair, extractableArg: spy.mock.calls[0][1], result };
}

describe("generateSessionKeypair", () => {
  it("generates a private key that script in this origin cannot export", async () => {
    const { keypair, extractableArg } = await captureSessionKeypair();

    expect(extractableArg).toBe(false);
    expect(keypair.privateKey.extractable).toBe(false);

    await expect(
      crypto.subtle.exportKey("pkcs8", keypair.privateKey),
    ).rejects.toThrow(/not extractable/i);
    await expect(
      crypto.subtle.exportKey("jwk", keypair.privateKey),
    ).rejects.toThrow(/not extractable/i);
  });

  it("still exports the raw public key, which is what the flag is not for", async () => {
    const { keypair, result } = await captureSessionKeypair();

    // The public key of a generated pair is extractable regardless of
    // the argument — this is the fact the comment in session-key.ts
    // records, and the reason `false` costs nothing here.
    expect(keypair.publicKey.extractable).toBe(true);

    const raw = new Uint8Array(
      await crypto.subtle.exportKey("raw", keypair.publicKey),
    );
    expect(raw).toHaveLength(32);
    expect(result.pubkeyMultikey).toMatch(/^z6Mk/);
    expect(result.didKey).toBe(`did:key:${result.pubkeyMultikey}`);
  });

  it("signs with the non-extractable key", async () => {
    // A non-extractable key is still a usable signing key; if this ever
    // regresses, the temptation is to "fix" it by making it extractable.
    await generateSessionKeypair();
    const envelope: SignableEnvelope = { id: "urn:test", value: 1 };
    const proof = (await signEnvelope(envelope)).proof as Record<string, unknown>;

    expect(proof.cryptosuite).toBe("eddsa-jcs-2022");
    expect(proof.proofValue).toMatch(/^z/);
  });
});

describe("WebCrypto generateKey extractability contract", () => {
  // Measured directly rather than assumed: the whole defect was a
  // mistaken belief about which key this argument governs.
  it.for([false, true])(
    "marks the public key extractable whatever the argument is (%s)",
    async (extractable) => {
      const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, extractable, [
        "sign",
        "verify",
      ])) as CryptoKeyPair;

      expect(pair.publicKey.extractable).toBe(true);
      expect(pair.privateKey.extractable).toBe(extractable);

      const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
      expect(raw).toHaveLength(32);
    },
  );
});
