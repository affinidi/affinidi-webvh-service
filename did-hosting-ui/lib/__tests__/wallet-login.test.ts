/**
 * Wallet login binds this browser's session key (`auth/authenticate/0.2`).
 *
 * The key is the real one (WebCrypto Ed25519); the wallet is a stub that
 * answers the way the extension does.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { hasSessionKeypair, signEnvelope } from "../session-key";
import { resetServiceInfo } from "../trust-task";
import {
  SERVICE_DID,
  installControlPlane,
  rejection,
  seal,
  stubStorage,
} from "./fake-control-plane";
import {
  authenticateIdTokenBindingSessionKey,
  loginBindingSessionKey,
  type VtaWalletLoginParams,
} from "../wallet-login";

const PARAMS = { rpDid: "did:webvh:QmRp:example.com", baseUrl: "https://console.example.com/api" };
const TOKENS = {
  accessToken: "AT",
  refreshToken: "RT",
  sessionId: "sess-1",
  holderDid: "did:peer:2.holder",
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe("wallet login", () => {
  it("asks the wallet to bind a fresh non-extractable did:key and keeps it", async () => {
    let asked: VtaWalletLoginParams | undefined;
    const wallet = {
      login: vi.fn(async (p: VtaWalletLoginParams) => {
        asked = p;
        return { ...TOKENS, sessionKey: p.sessionKey };
      }),
    };

    const result = await loginBindingSessionKey(wallet, PARAMS);

    expect(asked).toMatchObject(PARAMS);
    expect(asked!.sessionKey).toMatch(/^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$/);
    expect(result.sessionKey).toBe(asked!.sessionKey);
    expect(hasSessionKeypair()).toBe(true);
  });

  it("uses a new key for every login", async () => {
    const keys: string[] = [];
    const wallet = {
      login: async (p: VtaWalletLoginParams) => {
        keys.push(p.sessionKey!);
        return { ...TOKENS, sessionKey: p.sessionKey };
      },
    };
    await loginBindingSessionKey(wallet, PARAMS);
    await loginBindingSessionKey(wallet, PARAMS);
    expect(keys[0]).not.toBe(keys[1]);
  });

  it("fails, and drops the key, when the wallet signs in without binding it", async () => {
    const wallet = { login: async () => ({ ...TOKENS }) };
    await expect(loginBindingSessionKey(wallet, PARAMS)).rejects.toThrow(/without binding/);
    expect(hasSessionKeypair()).toBe(false);
  });

  it("drops the key when the login is refused", async () => {
    const wallet = {
      login: async () => {
        throw new Error("login denied by user");
      },
    };
    await expect(loginBindingSessionKey(wallet, PARAMS)).rejects.toThrow(/denied/);
    expect(hasSessionKeypair()).toBe(false);
  });
});

describe("wallet proxy login", () => {
  const AUTHENTICATE = "https://trusttasks.org/spec/auth/authenticate/0.3";
  const ARGS = {
    idToken: "h.p.s",
    sessionId: "sess-1",
    challenge: "the-challenge-nonce",
    principalDid: "did:webvh:QmP:example.com:persona",
  };
  const OK_PAYLOAD = {
    session: {
      id: "sess-1",
      subject: "did:webvh:QmP:example.com:persona",
      issuedAt: "",
      expiresAt: "",
    },
    tokens: { accessToken: "AT", refreshToken: "RT", tokenType: "Bearer", expiresIn: 900 },
  };

  beforeEach(() => {
    resetServiceInfo();
    stubStorage({});
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("signs an auth/authenticate/0.3 proxied document with a fresh session key and keeps it", async () => {
    // Without a bound key every call went through the wallet's
    // `signTrustTask`, which prompts each time: one popup per request.
    const sent = installControlPlane((req) =>
      req.type === AUTHENTICATE ? seal(req, OK_PAYLOAD) : undefined,
    );

    const response = await authenticateIdTokenBindingSessionKey(ARGS);

    const doc = sent.find((s) => s.doc.type === AUTHENTICATE)!;
    // No bearer: the document's own proof is the credential.
    expect(doc.bearer).toBeUndefined();
    expect(doc.doc.recipient).toBe(SERVICE_DID);
    expect(doc.doc.payload).toMatchObject({
      challenge: ARGS.challenge,
      sessionId: "sess-1",
      principal: ARGS.principalDid,
      delegationEvidence: { kind: "siopIdToken", credential: { idToken: "h.p.s" } },
    });
    const didKey = doc.doc.issuer as string;
    expect(didKey).toMatch(/^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$/);
    // The document's own issuer and the bound `sessionKey` are the same
    // fresh key — the delegate that signed doubles as the session key.
    expect(doc.doc.payload.sessionKey).toBe(didKey);
    expect((doc.doc.proof as { verificationMethod: string }).verificationMethod).toBe(
      `${didKey}#${didKey.slice("did:key:".length)}`,
    );
    // The key held is the one bound, so `trust-task.ts` signs with it.
    const signed = await signEnvelope<{ type: string; proof?: unknown }>({ type: "t" });
    expect((signed.proof as { verificationMethod: string }).verificationMethod).toBe(
      `${didKey}#${didKey.slice("did:key:".length)}`,
    );
    expect(response.tokens.accessToken).toBe("AT");
  });

  it("refuses, and drops the key, when the reply is not the service's signed answer", async () => {
    // The raw `fetch` this used to be accepted any JSON with a token in it.
    installControlPlane((req) =>
      req.type === AUTHENTICATE ? seal(req, OK_PAYLOAD, { proof: undefined }) : undefined,
    );
    await expect(authenticateIdTokenBindingSessionKey(ARGS)).rejects.toThrow(/unsigned/);
    expect(hasSessionKeypair()).toBe(false);
  });

  it("drops the key when the control plane refuses the login", async () => {
    installControlPlane((req) =>
      req.type === AUTHENTICATE ? rejection("permissionDenied") : undefined,
    );
    await expect(authenticateIdTokenBindingSessionKey(ARGS)).rejects.toThrow(/permissionDenied/);
    expect(hasSessionKeypair()).toBe(false);
  });

  it("drops the key when the reply carries no token", async () => {
    installControlPlane((req) =>
      req.type === AUTHENTICATE ? seal(req, { session: OK_PAYLOAD.session }) : undefined,
    );
    await expect(authenticateIdTokenBindingSessionKey(ARGS)).rejects.toThrow(/no access token/);
    expect(hasSessionKeypair()).toBe(false);
  });

  it("drops the key when the request never arrives", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("Failed to fetch");
      }),
    );
    await expect(authenticateIdTokenBindingSessionKey(ARGS)).rejects.toThrow(/Failed to fetch/);
    expect(hasSessionKeypair()).toBe(false);
  });
});
