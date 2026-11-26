/**
 * Adding a passkey to yourself in the console: `auth/passkey/enroll/
 * {start,finish}/0.2`, signed as the caller, with no invite.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AddPasskeyError, completeAddPasskey, startAddPasskey } from "../add-passkey-flow";
import { resetServiceInfo, type EnrollStartResponse } from "../api";
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

const TT = "https://trusttasks.org/spec/auth/passkey/enroll/";
const CALLER = "did:example:admin-1";
const tasks = (sent: Sent[]) => sent.filter((s) => s.doc.type !== SERVER_INFO);

const OPTIONS: EnrollStartResponse["options"] = {
  challenge: "Y3JlYXRl",
  rp: { id: "control.example.com", name: "DID Hosting Server" },
  user: { id: "dXNlcg", name: "admin-1", displayName: "admin-1" },
  pubKeyCredParams: [{ type: "public-key", alg: -7 }],
};
const UV_OPTIONS: NonNullable<EnrollStartResponse["uvOptions"]> = {
  challenge: "dXY",
  rpId: "control.example.com",
  userVerification: "required",
  allowCredentials: [{ type: "public-key", id: "b2xk" }],
};
const ATTESTATION = {
  id: "bmV3",
  rawId: "bmV3",
  type: "public-key" as const,
  response: { attestationObject: "YQ", clientDataJSON: "Yw" },
};
const ASSERTION = {
  id: "b2xk",
  rawId: "b2xk",
  type: "public-key" as const,
  response: { authenticatorData: "YQ", clientDataJSON: "Yw", signature: "cw" },
};
const FINISHED = {
  credentialId: "bmV3",
  subject: CALLER,
  deviceLabel: "Backup key",
  registeredAt: "2026-11-26T10:00:00Z",
};

function start(extra: Partial<EnrollStartResponse> = {}): EnrollStartResponse {
  return { enrollmentId: "enr_1", options: OPTIONS, uvOptions: UV_OPTIONS, ...extra };
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

describe("starting to add a passkey", () => {
  it("is the caller's own enrolment, carrying only a trimmed label", async () => {
    const sent = installControlPlane((req) => seal(req, start()));
    const s = await startAddPasskey("  Backup key ");
    expect(s.enrollmentId).toBe("enr_1");
    const { doc } = tasks(sent)[0]!;
    expect(doc.type).toBe(`${TT}start/0.2`);
    expect(doc.issuer).toBe(CALLER);
    expect(doc.payload).toEqual({ deviceLabel: "Backup key" });
  });

  it("sends an empty payload when no label is given", async () => {
    const sent = installControlPlane((req) => seal(req, start()));
    await startAddPasskey("   ");
    expect(tasks(sent)[0]!.doc.payload).toEqual({});
  });

  it("explains the declared refusals plainly", async () => {
    installControlPlane(() => rejection("auth/passkey/enroll/start:maxCredentialsReached"));
    await expect(startAddPasskey()).rejects.toThrow(AddPasskeyError);
    await expect(startAddPasskey()).rejects.toThrow(/most passkeys/);

    installControlPlane(() => rejection("auth/passkey/enroll/start:reauthUnavailable"));
    await expect(startAddPasskey()).rejects.toThrow(/cannot re-verify/);

    installControlPlane(() => rejection("auth/passkey/enroll/start:enrollmentNotSupported"));
    await expect(startAddPasskey()).rejects.toThrow(/does not enrol/);
  });
});

describe("completing it", () => {
  it("proves an existing passkey first, then creates and binds the new one", async () => {
    const sent = installControlPlane((req) => seal(req, FINISHED));
    const order: string[] = [];
    const get = vi.fn(async () => (order.push("get"), ASSERTION));
    const create = vi.fn(async () => (order.push("create"), ATTESTATION));

    const done = await completeAddPasskey(start(), { get, create }, "Backup key");

    expect(order).toEqual(["get", "create"]);
    expect(get).toHaveBeenCalledWith({ publicKey: UV_OPTIONS });
    expect(create).toHaveBeenCalledWith({ publicKey: OPTIONS });
    expect(done).toEqual(FINISHED);
    const { doc } = tasks(sent)[0]!;
    expect(doc.type).toBe(`${TT}finish/0.2`);
    expect(doc.payload).toEqual({
      enrollmentId: "enr_1",
      credential: ATTESTATION,
      uvCredential: ASSERTION,
      deviceLabel: "Backup key",
    });
  });

  it("runs no user verification for a first passkey", async () => {
    const sent = installControlPlane((req) => seal(req, FINISHED));
    const get = vi.fn(async () => ASSERTION);
    const create = vi.fn(async () => ATTESTATION);

    await completeAddPasskey(start({ uvOptions: undefined }), { get, create });

    expect(get).not.toHaveBeenCalled();
    expect(tasks(sent)[0]!.doc.payload).toEqual({ enrollmentId: "enr_1", credential: ATTESTATION });
  });

  it("explains the refusals plainly", async () => {
    const ceremonies = { get: async () => ASSERTION, create: async () => ATTESTATION };

    installControlPlane(() => rejection("auth/passkey/enroll/finish:enrollmentExpired"));
    await expect(completeAddPasskey(start(), ceremonies)).rejects.toThrow(/timed out/);

    installControlPlane(() => rejection("auth/passkey/enroll/finish:subjectMismatch"));
    await expect(completeAddPasskey(start(), ceremonies)).rejects.toThrow(/session changed/);

    installControlPlane(() => rejection("auth/passkey/enroll/finish:attestationInvalid"));
    await expect(completeAddPasskey(start(), ceremonies)).rejects.toThrow(/already be registered/);

    installControlPlane(() => rejection("permissionDenied"));
    await expect(completeAddPasskey(start(), ceremonies)).rejects.toThrow(/did not confirm/);
  });
});
