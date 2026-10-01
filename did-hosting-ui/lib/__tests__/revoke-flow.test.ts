/**
 * Revoking a passkey in the console: a re-authentication ceremony over
 * `auth/passkey/revoke/{start,finish}`, never a bare delete.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api, resetServiceInfo, type RevokePasskeyStartResponse } from "../api";
import { completeRevocation, startRevocation, RevocationError } from "../revoke-flow";
import { generateSessionKeypair } from "../session-key";
import {
  SERVER_INFO,
  installControlPlane,
  rejection,
  seal,
  stubStorage,
  tokenFor,
  type Sent,
} from "./fake-control-plane";

const TT = "https://trusttasks.org/spec/auth/passkey/revoke/";
const CALLER = "did:webvh:QmDana:example.com:dana";
const tasks = (sent: Sent[]) => sent.filter((s) => s.doc.type !== SERVER_INFO);

const UV_OPTIONS: RevokePasskeyStartResponse["uvOptions"] = {
  challenge: "cmV2b2tl",
  rpId: "control.example.com",
  userVerification: "required",
  allowCredentials: [{ type: "public-key", id: "b2xk" }],
};
const ASSERTION = {
  id: "b2xk",
  rawId: "b2xk",
  type: "public-key",
  response: { authenticatorData: "YQ", clientDataJSON: "Yw", signature: "cw" },
};

function start(extra: Record<string, unknown> = {}) {
  return {
    revocationId: "rvk_1",
    uvOptions: UV_OPTIONS,
    ...extra,
  };
}

beforeEach(async () => {
  resetServiceInfo();
  stubStorage({ webvh_token: tokenFor(CALLER, { session_id: "s" }), webvh_auth_method: "passkey" });
  await generateSessionKeypair();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("starting a revocation", () => {
  it("the caller's own: no subject in the payload", async () => {
    const sent = installControlPlane((req) => seal(req, start()));
    const s = await startRevocation("bmV3");
    expect(s.revocationId).toBe("rvk_1");
    const { doc } = tasks(sent)[0]!;
    expect(doc.type).toBe(`${TT}start/0.2`);
    expect(doc.payload).toEqual({ credentialId: "bmV3" });
    expect(doc.issuer).toBe(CALLER);
  });

  it("another subject's: the subject rides along, for an administrator", async () => {
    const sent = installControlPlane((req) => seal(req, start()));
    await startRevocation("bmV3", "did:example:dana");
    expect(tasks(sent)[0]!.doc.payload).toEqual({
      credentialId: "bmV3",
      subject: "did:example:dana",
    });
  });

  it("explains the declared refusals plainly", async () => {
    installControlPlane(() => rejection("auth/passkey/revoke/start:lastCredential"));
    await expect(startRevocation("bmV3")).rejects.toThrow(RevocationError);
    await expect(startRevocation("bmV3")).rejects.toThrow(/only sign-in passkey/);

    installControlPlane(() => rejection("auth/passkey/revoke/start:reauthUnavailable"));
    await expect(startRevocation("bmV3")).rejects.toThrow(/no passkey this console/);

    installControlPlane(() => rejection("auth/passkey/revoke/start:notAuthorized"));
    await expect(startRevocation("bmV3", "did:example:dana")).rejects.toThrow(/may not revoke/);

    installControlPlane(() => rejection("auth/passkey/revoke/start:credentialNotFound"));
    await expect(startRevocation("bmV3")).rejects.toThrow(/already gone/);
  });
});

describe("completing a revocation", () => {
  it("runs one WebAuthn assertion and sends it with the revocationId", async () => {
    const sent = installControlPlane((req) =>
      seal(req, {
        credentialId: "bmV3",
        subject: CALLER,
        purpose: "stepUp",
        revokedAt: "2026-09-25T10:21:00Z",
        remaining: 0,
      }),
    );
    const get = vi.fn(async () => ASSERTION);

    const done = await completeRevocation(start(), { get });

    expect(get).toHaveBeenCalledWith({ publicKey: UV_OPTIONS });
    expect(done).toEqual({
      credentialId: "bmV3",
      subject: CALLER,
      purpose: "stepUp",
      revokedAt: Date.parse("2026-09-25T10:21:00Z") / 1000,
      remaining: 0,
    });
    expect(tasks(sent)[0]!.doc.payload).toEqual({
      revocationId: "rvk_1",
      uvCredential: ASSERTION,
    });
  });

  it("explains the declared refusals plainly", async () => {
    const get = async () => ASSERTION;

    installControlPlane(() => rejection("auth/passkey/revoke/finish:revocationExpired"));
    await expect(completeRevocation(start(), { get })).rejects.toThrow(/timed out or was replaced/);

    installControlPlane(() => rejection("auth/passkey/revoke/finish:userVerificationFailed"));
    await expect(completeRevocation(start(), { get })).rejects.toThrow(/did not confirm/);

    installControlPlane(() => rejection("auth/passkey/revoke/finish:lastCredential"));
    await expect(completeRevocation(start(), { get })).rejects.toThrow(/only sign-in passkey/);

    installControlPlane(() => rejection("auth/passkey/revoke/finish:notAuthorized"));
    await expect(completeRevocation(start(), { get })).rejects.toThrow(/withdrawn/);
  });
});
