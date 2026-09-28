/**
 * Passkey enrolment in the console: issuing an invite, and redeeming one —
 * every call a Trust Task, the WebAuthn ceremony's data carried inside.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api, resetServiceInfo } from "../api";
import { completeRedemption, startRedemption, RedemptionError } from "../enrol-flow";
import { generateSessionKeypair } from "../session-key";
import {
  SERVER_INFO,
  SERVICE_DID,
  installControlPlane,
  rejection,
  seal,
  stubStorage,
  tokenFor,
  type Sent,
} from "./fake-control-plane";

const TT = "https://trusttasks.org/spec/auth/passkey/enroll/";
const ADMIN = "did:webvh:QmAdmin:example.com:admin";
const tasks = (sent: Sent[]) => sent.filter((s) => s.doc.type !== SERVER_INFO);

const OPTIONS = {
  challenge: "cmVnaXN0ZXI",
  rp: { id: "control.example.com", name: "DID Hosting Server" },
  user: { id: "dXNlcg", name: "did:example:carol", displayName: "did:example:carol" },
  pubKeyCredParams: [{ type: "public-key", alg: -7 }],
};
const UV_OPTIONS = {
  challenge: "dmVyaWZ5",
  rpId: "control.example.com",
  userVerification: "required",
  allowCredentials: [{ type: "public-key", id: "b2xk" }],
};
const ATTESTATION = {
  id: "bmV3",
  rawId: "bmV3",
  type: "public-key",
  response: { attestationObject: "YQ", clientDataJSON: "Yw" },
};
const ASSERTION = {
  id: "b2xk",
  rawId: "b2xk",
  type: "public-key",
  response: { authenticatorData: "YQ", clientDataJSON: "Yw", signature: "cw" },
};

function start(extra: Record<string, unknown> = {}) {
  return {
    enrollmentId: "enr_1",
    subject: "did:example:carol",
    purpose: "session" as const,
    options: OPTIONS,
    expiresAt: "2026-09-25T10:25:00Z",
    ...extra,
  };
}

beforeEach(() => {
  resetServiceInfo();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("issuing an invite", () => {
  beforeEach(async () => {
    stubStorage({ webvh_token: tokenFor(ADMIN, { session_id: "s" }), webvh_auth_method: "passkey" });
    await generateSessionKeypair();
  });

  it("is a signed invite/0.2, and hands back the link and the claim code apart", async () => {
    const sent = installControlPlane((req) =>
      seal(req, {
        invite: { token: "inv_tok", url: "https://control.example.com/enroll?token=inv_tok" },
        subject: "did:example:carol",
        purpose: "session",
        expiresAt: "2026-09-25T11:00:00Z",
        claimCode: "7KQ4-MX2P-9TDA",
      }),
    );
    const invite = await api.createInvite("did:example:carol", "owner");
    expect(invite).toEqual({
      inviteUrl: "https://control.example.com/enroll?token=inv_tok",
      claimCode: "7KQ4-MX2P-9TDA",
      subject: "did:example:carol",
      purpose: "session",
      expiresAt: Date.parse("2026-09-25T11:00:00Z") / 1000,
    });
    expect(invite.inviteUrl).not.toContain(invite.claimCode);
    const { doc } = tasks(sent)[0]!;
    expect(doc.type).toBe(`${TT}invite/0.2`);
    expect(doc.payload).toEqual({ subject: "did:example:carol", role: "owner" });
    expect(doc.issuer).toBe(ADMIN);
    expect(doc.proof).toBeDefined();
  });

  it("a step-up invite names its purpose and no role", async () => {
    const sent = installControlPlane((req) =>
      seal(req, {
        invite: { token: "inv_tok", url: "https://control.example.com/enroll?token=inv_tok" },
        subject: "did:example:carol",
        purpose: "stepUp",
        expiresAt: "2026-09-25T11:00:00Z",
        claimCode: "7KQ4-MX2P-9TDA",
      }),
    );
    await api.createInvite("did:example:carol", "owner", "stepUp");
    expect(tasks(sent)[0]!.doc.payload).toEqual({ subject: "did:example:carol", purpose: "stepUp" });
  });
});

describe("redeeming an invite", () => {
  beforeEach(() => {
    // A previous session in this browser must not ride along.
    stubStorage({ webvh_token: tokenFor("did:web:someone-else.example") });
  });

  it("presents both halves anonymously and unsigned, then binds the new passkey", async () => {
    const sent = installControlPlane((req) => {
      if (req.type === `${TT}redeem/start/0.1`) return seal(req, start());
      if (req.type === `${TT}redeem/finish/0.1`) {
        return seal(req, {
          credentialId: "bmV3",
          subject: "did:example:carol",
          purpose: "session",
          deviceLabel: "laptop",
          registeredAt: "2026-09-25T10:21:00Z",
        });
      }
      return undefined;
    });
    const create = vi.fn(async () => ATTESTATION);
    const get = vi.fn(async () => ASSERTION);

    const s = await startRedemption("inv_tok", " 7kq4-mx2p-9tda ");
    expect(s.subject).toBe("did:example:carol");
    const done = await completeRedemption(s, { create, get }, "laptop");

    expect(done.purpose).toBe("session");
    expect(get).not.toHaveBeenCalled();
    expect(create).toHaveBeenCalledWith({ publicKey: OPTIONS });
    const [first, second] = tasks(sent);
    for (const { doc, bearer } of [first!, second!]) {
      expect(doc.proof).toBeUndefined();
      expect(doc.issuer).toBeUndefined();
      expect(doc.recipient).toBe(SERVICE_DID);
      expect(bearer).toBeUndefined();
    }
    expect(first!.doc.payload).toEqual({ token: "inv_tok", claimCode: "7kq4-mx2p-9tda" });
    expect(second!.doc.payload).toEqual({
      enrollmentId: "enr_1",
      credential: ATTESTATION,
      deviceLabel: "laptop",
    });
  });

  it("proves an existing passkey first when the start asks, and sends it", async () => {
    const sent = installControlPlane((req) => {
      if (req.type === `${TT}redeem/start/0.1`) {
        return seal(req, start({ purpose: "stepUp", uvOptions: UV_OPTIONS }));
      }
      return seal(req, {
        credentialId: "bmV3",
        subject: "did:example:carol",
        purpose: "stepUp",
        registeredAt: "2026-09-25T10:21:00Z",
      });
    });
    const order: string[] = [];
    const create = vi.fn(async () => (order.push("create"), ATTESTATION));
    const get = vi.fn(async () => (order.push("get"), ASSERTION));

    await completeRedemption(await startRedemption("inv_tok", "CODE"), { create, get });

    expect(order).toEqual(["get", "create"]);
    expect(get).toHaveBeenCalledWith({ publicKey: UV_OPTIONS });
    expect(tasks(sent)[1]!.doc.payload).toEqual({
      enrollmentId: "enr_1",
      credential: ATTESTATION,
      uvCredential: ASSERTION,
    });
  });

  it("says plainly when the code is wrong, and when the invite is locked", async () => {
    installControlPlane(() => rejection("auth/passkey/enroll/redeem/start:inviteInvalid"));
    await expect(startRedemption("inv_tok", "WRONG")).rejects.toThrow(RedemptionError);
    await expect(startRedemption("inv_tok", "WRONG")).rejects.toThrow(/do not match an open invite/);

    installControlPlane(() => rejection("auth/passkey/enroll/redeem/start:tooManyAttempts"));
    await expect(startRedemption("inv_tok", "WRONG")).rejects.toThrow(/cancelled/);
  });

  it("asks for the claim code before sending anything", async () => {
    const sent = installControlPlane(() => undefined);
    await expect(startRedemption("inv_tok", "  ")).rejects.toThrow(/claim code/);
    await expect(startRedemption("", "CODE")).rejects.toThrow(/token/);
    expect(tasks(sent)).toHaveLength(0);
  });

  it("a finish refused for user verification is explained", async () => {
    installControlPlane((req) =>
      req.type === `${TT}redeem/start/0.1`
        ? seal(req, start({ uvOptions: UV_OPTIONS }))
        : rejection("auth/passkey/enroll/redeem/finish:userVerificationFailed"),
    );
    const s = await startRedemption("inv_tok", "CODE");
    await expect(
      completeRedemption(s, { create: async () => ATTESTATION, get: async () => ASSERTION }),
    ).rejects.toThrow(/existing passkey did not confirm/);
  });
});
