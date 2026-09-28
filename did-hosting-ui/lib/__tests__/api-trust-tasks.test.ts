/**
 * The API layer over the Trust Task binding: what each call sends, how the
 * reply is checked, and how it is projected for the screens.
 *
 * The session key is the real one (WebCrypto Ed25519), so a passkey-style
 * session signs for real; the control plane is `fake-control-plane.ts`.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError, api, checkReply, resetServiceInfo } from "../api";
import { generateSessionKeypair } from "../session-key";
import { domainFromWire, logMetadataFromEntries } from "../wire";
import {
  SERVICE_DID,
  SERVER_INFO,
  installControlPlane,
  rejection,
  seal,
  stubStorage,
  tokenFor,
  type Doc,
  type Sent,
} from "./fake-control-plane";

const SUBJECT = "did:webvh:QmAdmin:example.com:admin";
const DM = "https://trusttasks.org/spec/did-management/";
const TOKEN = tokenFor(SUBJECT, { session_id: "sess-1" });

beforeEach(() => {
  resetServiceInfo();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

/** Only the documents that are not the `server/info` bootstrap. */
const tasks = (sent: Sent[]) => sent.filter((s) => s.doc.type !== SERVER_INFO);

// ---------------------------------------------------------------------------

describe("server/info", () => {
  beforeEach(() => {
    stubStorage({ webvh_token: TOKEN });
  });

  it("is sent anonymously — no bearer, no proof, no issuer — and cached", async () => {
    const sent = installControlPlane(() => undefined);

    const info = await api.serverInfo();
    await api.serverInfo();

    expect(info.serviceDid).toBe(SERVICE_DID);
    expect(sent).toHaveLength(1);
    const { doc, bearer } = sent[0]!;
    expect(bearer).toBeUndefined();
    expect(doc.proof).toBeUndefined();
    expect(doc.issuer).toBeUndefined();
    expect(doc.recipient).toBeUndefined();
  });

  it("refuses a reply not signed by the service DID it names", async () => {
    installControlPlane(
      () => undefined,
      (req) =>
        seal(
          req,
          { serviceDid: SERVICE_DID, agentNames: false, serviceNames: [] },
          {
            proof: {
              type: "DataIntegrityProof",
              cryptosuite: "eddsa-jcs-2022",
              verificationMethod: "did:web:attacker.example#key-1",
              proofPurpose: "authentication",
              proofValue: "zForged",
            },
          },
        ),
    );
    await expect(api.serverInfo()).rejects.toThrow(/not a key of/);
  });

  it("refuses an unsigned reply, and does not cache the failure", async () => {
    let unsigned = true;
    installControlPlane(
      () => undefined,
      (req) => {
        const reply = seal(req, { serviceDid: SERVICE_DID, agentNames: false, serviceNames: [] });
        if (unsigned) delete reply.proof;
        return reply;
      },
    );
    await expect(api.serverInfo()).rejects.toThrow(/unsigned/);
    unsigned = false;
    await expect(api.serverInfo()).resolves.toMatchObject({ serviceDid: SERVICE_DID });
  });
});

// ---------------------------------------------------------------------------

describe("checkReply", () => {
  const sent = { id: "urn:uuid:req", type: `${DM}did/list/0.1`, issuer: SUBJECT };
  const good = () => seal(sent, { records: [], total: 0 });

  it("accepts the service's signed answer to this request", () => {
    expect(() => checkReply(sent, good() as never, SERVICE_DID)).not.toThrow();
  });

  it.each([
    ["another task's response type", { type: `${DM}did/info/0.1#response` }, /unexpected type/],
    ["a reply to another request", { threadId: "urn:uuid:other" }, /does not answer/],
    ["another issuer", { issuer: "did:web:other.example" }, /not the service/],
    ["another recipient", { recipient: "did:web:someone.else" }, /addressed to/],
    ["no proof", { proof: undefined }, /unsigned/],
  ])("refuses %s", (_what, overrides, why) => {
    const reply = { ...good(), ...overrides };
    expect(() => checkReply(sent, reply as never, SERVICE_DID)).toThrow(why);
  });

  it.each([
    ["an assertionMethod proof", { proofPurpose: "assertionMethod" }, /proof purpose/],
    ["a key of another DID", { verificationMethod: "did:web:other.example#k" }, /not a key of/],
    ["another cryptosuite", { cryptosuite: "ecdsa-rdfc-2019" }, /eddsa-jcs-2022/],
    ["no signature", { proofValue: undefined }, /no signature/],
  ])("refuses %s", (_what, proofOverrides, why) => {
    const reply = good();
    reply.proof = { ...reply.proof, ...proofOverrides };
    expect(() => checkReply(sent, reply as never, SERVICE_DID)).toThrow(why);
  });

  it("is a 502, so it reads as the upstream's fault", () => {
    const reply = { ...good(), proof: undefined };
    expect(() => checkReply(sent, reply as never, SERVICE_DID)).toThrow(ApiError);
    try {
      checkReply(sent, reply as never, SERVICE_DID);
    } catch (e) {
      expect((e as ApiError).status).toBe(502);
    }
  });
});

// ---------------------------------------------------------------------------

describe("management calls (passkey session)", () => {
  let didKey: string;

  beforeEach(async () => {
    stubStorage({ webvh_token: TOKEN, webvh_auth_method: "passkey" });
    ({ didKey } = await generateSessionKeypair());
  });

  it("sends a signed did/list for the session subject, addressed to the service, and pages", async () => {
    const record = (m: string) => ({
      mnemonic: m,
      owner: SUBJECT,
      createdAt: "2026-01-02T03:04:05Z",
      updatedAt: "2026-01-02T03:04:06Z",
      versionCount: 2,
      didId: `did:webvh:Qm:example.com:${m}`,
      didUrl: `https://example.com/${m}/did.jsonl`,
      disabled: false,
      totalResolves: 7,
      ext: {
        "vnd.affinidi.webvh": { agentNames: [{ name: m, enabled: true, createdAt: 1 }] },
      },
    });
    const sent = installControlPlane((req) =>
      req.payload.offset
        ? seal(req, { records: [record("c")], total: 3 })
        : seal(req, { records: [record("a"), record("b")], total: 3 }),
    );

    const dids = await api.listDids();

    expect(dids.map((d) => d.mnemonic)).toEqual(["a", "b", "c"]);
    expect(dids[0]).toMatchObject({
      createdAt: Date.parse("2026-01-02T03:04:05Z") / 1000,
      totalResolves: 7,
      agentNames: [{ name: "a", enabled: true, createdAt: 1 }],
    });
    const [first, second] = tasks(sent);
    expect(first!.doc).toMatchObject({
      type: `${DM}did/list/0.1`,
      issuer: SUBJECT,
      recipient: SERVICE_DID,
      payload: { limit: 1000 },
      proof: {
        proofPurpose: "authentication",
        verificationMethod: expect.stringMatching(new RegExp(`^${didKey}#`)),
      },
    });
    expect(first!.bearer).toBe(`Bearer ${TOKEN}`);
    expect(second!.doc.payload).toEqual({ limit: 1000, offset: 2 });
  });

  it("refuses an unsigned reply to a management call", async () => {
    installControlPlane((req) => {
      const reply = seal(req, { entries: [], truncated: false });
      delete reply.proof;
      return reply;
    });
    await expect(api.listAcl()).rejects.toThrow(/unsigned/);
  });

  it("refuses a reply signed by a key that is not the service's", async () => {
    installControlPlane((req) =>
      seal(req, { entries: [], truncated: false }, { issuer: "did:web:attacker.example" }),
    );
    await expect(api.listAcl()).rejects.toThrow(/not the service/);
  });

  it("getDid reads the record and summarises the log", async () => {
    installControlPlane((req) => {
      if (req.type === `${DM}did/info/0.1`) {
        return seal(req, {
          record: {
            mnemonic: "m",
            owner: SUBJECT,
            createdAt: "2026-01-01T00:00:00Z",
            updatedAt: "2026-01-01T00:00:00Z",
            versionCount: 2,
          },
        });
      }
      return seal(req, {
        mnemonic: "m",
        method: "webvh",
        entries: [
          { versionId: "1-a", state: {}, parameters: { method: "did:webvh:1.0", portable: true } },
          { versionId: "2-b", state: {}, parameters: { ttl: 300 } },
        ],
      });
    });

    const detail = await api.getDid("m");

    expect(detail.log).toMatchObject({
      logEntryCount: 2,
      latestVersionId: "2-b",
      portable: true,
      ttl: 300,
      method: "did:webvh:1.0",
    });
  });

  it("getDid answers a slot with no published log with log: null", async () => {
    installControlPlane((req) =>
      req.type === `${DM}did/info/0.1`
        ? seal(req, {
            record: {
              mnemonic: "m",
              owner: SUBJECT,
              createdAt: "2026-01-01T00:00:00Z",
              updatedAt: "2026-01-01T00:00:00Z",
              versionCount: 0,
            },
          })
        : rejection("notFound"),
    );
    await expect(api.getDid("m")).resolves.toMatchObject({ mnemonic: "m", log: null });
  });

  it("rolls back exactly the last entry", async () => {
    const sent = installControlPlane((req) =>
      seal(req, {
        record: {
          mnemonic: "m",
          owner: SUBJECT,
          createdAt: "2026-01-01T00:00:00Z",
          updatedAt: "2026-01-01T00:00:00Z",
          versionCount: 2,
        },
        removedVersions: 1,
      }),
    );
    await api.rollbackDid("m", 3);
    expect(tasks(sent)[0]!.doc.payload).toEqual({ mnemonic: "m", targetVersion: 2 });
    await expect(api.rollbackDid("m", 1)).rejects.toThrow(/first log entry/);
  });

  it("maps a timeseries range onto the spec's names and back to epoch points", async () => {
    const sent = installControlPlane((req) =>
      seal(req, {
        range: "lastWeek",
        bucketSeconds: 3600,
        points: [{ at: "2026-01-01T00:00:00Z", resolves: 3, updates: 1 }],
      }),
    );
    const points = await api.getServerTimeseries("7d", "example.com");
    expect(tasks(sent)[0]!.doc.payload).toEqual({ range: "lastWeek", domain: "example.com" });
    expect(points).toEqual([
      { timestamp: Date.parse("2026-01-01T00:00:00Z") / 1000, resolves: 3, updates: 1 },
    ]);
  });

  it("lists invites by inviteId and never expects a token back", async () => {
    installControlPlane((req) =>
      seal(req, {
        invites: [
          {
            inviteId: "inv-1",
            subject: "did:web:new.example",
            purpose: "session",
            role: "owner",
            createdAt: "2026-01-01T00:00:00Z",
            expiresAt: "2026-01-02T00:00:00Z",
            expired: false,
          },
        ],
      }),
    );
    const { invites } = await api.listInvites();
    expect(invites).toEqual([
      {
        inviteId: "inv-1",
        did: "did:web:new.example",
        role: "owner",
        createdAt: Date.parse("2026-01-01T00:00:00Z") / 1000,
        expiresAt: Date.parse("2026-01-02T00:00:00Z") / 1000,
        expired: false,
      },
    ]);
  });

  it("updates an invite with only the members given", async () => {
    const invite = {
      inviteId: "inv-1",
      subject: "did:web:new.example",
      purpose: "session",
      role: "owner",
      createdAt: "2026-01-01T00:00:00Z",
      expiresAt: "2026-01-02T00:00:00Z",
      expired: false,
    };
    const sent = installControlPlane((req) => seal(req, { invite }));
    await api.updateInvite("inv-1", { role: undefined, extendBy: 60 });
    const [task] = tasks(sent);
    expect(task!.doc.payload).toEqual({ inviteId: "inv-1", extendBy: 60 });
  });

  it("a passkey session purges a domain without stepping up", async () => {
    const sent = installControlPlane((req) =>
      seal(req, { name: "old.example", purgedAt: "2026-01-01T00:00:00Z" }),
    );
    await api.deleteDomain("old.example", { purgeServers: true });
    expect(tasks(sent).map((s) => s.doc.payload)).toEqual([
      { name: "old.example", purgeServers: true },
    ]);
  });

  it("does not sign with a new key when the session key is gone", async () => {
    // A key the control plane never bound to this session would only be
    // refused; the user has to sign in again.
    const sessionKey = await import("../session-key");
    vi.spyOn(sessionKey, "hasSessionKeypair").mockReturnValue(false);
    vi.spyOn(sessionKey, "restoreSessionKeypair").mockResolvedValue();
    vi.stubGlobal("window", { dispatchEvent: vi.fn() });
    installControlPlane(() => undefined);
    await expect(api.listAcl()).rejects.toThrow(/sign in again/);
  });
});

// ---------------------------------------------------------------------------

describe("step-up (wallet session)", () => {
  function stubWallet(stepUpVta = vi.fn()) {
    vi.stubGlobal("window", {
      location: { origin: "https://console.example.com" },
      dispatchEvent: vi.fn(),
      vtaWallet: {
        signTrustTask: async ({ envelope }: { envelope: Doc }) => ({
          signedEnvelope: {
            ...envelope,
            proof: {
              type: "DataIntegrityProof",
              cryptosuite: "eddsa-jcs-2022",
              verificationMethod: `${SUBJECT}#key-1`,
              proofPurpose: "authentication",
              proofValue: "zWallet",
            },
          },
          holderDid: SUBJECT,
        }),
        stepUpVta,
      },
    });
    return stepUpVta;
  }

  it("steps up through the wallet when the purge asks for it, then purges", async () => {
    const store = stubStorage({
      webvh_token: TOKEN,
      webvh_refresh_token: "refresh-1",
      webvh_auth_method: "wallet",
    });
    const elevated = tokenFor(SUBJECT, { session_id: "sess-1", acr: "aal2" });
    const stepUpVta = stubWallet(
      vi.fn().mockResolvedValue({
        accessToken: elevated,
        refreshToken: "refresh-2",
        sessionId: "sess-1",
        holderDid: SUBJECT,
      }),
    );
    let purges = 0;
    const sent = installControlPlane((req) =>
      ++purges === 1
        ? rejection("stepUpRequired")
        : seal(req, { name: "old.example", purgedAt: "2026-01-01T00:00:00Z" }),
    );

    await api.deleteDomain("old.example");

    expect(stepUpVta).toHaveBeenCalledWith({
      baseUrl: "https://console.example.com/api",
      rpDid: SERVICE_DID,
      accessToken: TOKEN,
      refreshToken: "refresh-1",
      sessionId: "sess-1",
    });
    expect(store.get("webvh_token")).toBe(elevated);
    expect(store.get("webvh_refresh_token")).toBe("refresh-2");
    expect(tasks(sent)).toHaveLength(2);
    // The retried purge carries the stepped-up session.
    expect(tasks(sent)[1]!.bearer).toBe(`Bearer ${elevated}`);
  });

  it("says so when the session cannot step up", async () => {
    stubStorage({ webvh_token: TOKEN, webvh_refresh_token: "r", webvh_auth_method: "wallet" });
    vi.stubGlobal("window", {
      location: { origin: "https://console.example.com" },
      dispatchEvent: vi.fn(),
      vtaWallet: {
        signTrustTask: async ({ envelope }: { envelope: Doc }) => ({
          signedEnvelope: { ...envelope, proof: { proofValue: "z" } },
          holderDid: SUBJECT,
        }),
      },
    });
    installControlPlane(() => rejection("stepUpRequired"));
    await expect(api.deleteDomain("old.example")).rejects.toThrow(/stepped-up session/);
  });
});

// ---------------------------------------------------------------------------

describe("management calls (wallet session)", () => {
  function stubWallet() {
    const signTrustTask = vi.fn(async ({ envelope }: { envelope: Doc }) => ({
      signedEnvelope: {
        ...envelope,
        proof: {
          type: "DataIntegrityProof",
          cryptosuite: "eddsa-jcs-2022",
          verificationMethod: `${SUBJECT}#key-1`,
          proofPurpose: "authentication",
          proofValue: "zWallet",
        },
      },
      holderDid: SUBJECT,
    }));
    vi.stubGlobal("window", { dispatchEvent: vi.fn(), vtaWallet: { signTrustTask } });
    return signTrustTask;
  }

  it("signs with the session key the wallet login bound, without asking the wallet", async () => {
    stubStorage({ webvh_token: TOKEN, webvh_auth_method: "wallet" });
    const { didKey } = await generateSessionKeypair();
    const signTrustTask = stubWallet();
    const sent = installControlPlane((req) => seal(req, { entries: [], truncated: false }));

    await api.listAcl();

    expect(signTrustTask).not.toHaveBeenCalled();
    const { doc, bearer } = tasks(sent)[0]!;
    expect(doc).toMatchObject({
      issuer: SUBJECT,
      proof: {
        proofPurpose: "authentication",
        verificationMethod: `${didKey}#${didKey.slice("did:key:".length)}`,
      },
    });
    expect(bearer).toBe(`Bearer ${TOKEN}`);
  });

  it("signs out by revoking the session with the session key, then forgets it", async () => {
    const store = stubStorage({ webvh_token: TOKEN, webvh_auth_method: "wallet" });
    const { didKey } = await generateSessionKeypair();
    const signTrustTask = stubWallet();
    const sent = installControlPlane((req) => seal(req, { revokedCount: 1 }));

    await api.logout();

    expect(signTrustTask).not.toHaveBeenCalled();
    const { doc, bearer } = tasks(sent)[0]!;
    expect(doc).toMatchObject({
      type: "https://trusttasks.org/spec/auth/revoke-session/0.2",
      payload: { sessionId: "sess-1", reason: "logout" },
      proof: { verificationMethod: expect.stringMatching(new RegExp(`^${didKey}#`)) },
    });
    expect(bearer).toBe(`Bearer ${TOKEN}`);
    expect(store.get("webvh_token")).toBeUndefined();
    const sessionKey = await import("../session-key");
    expect(sessionKey.hasSessionKeypair()).toBe(false);
  });

  it("still signs out locally when the revoke fails", async () => {
    const store = stubStorage({ webvh_token: TOKEN, webvh_auth_method: "wallet" });
    await generateSessionKeypair();
    stubWallet();
    installControlPlane(() => rejection("internalError"));

    await api.logout();

    expect(store.get("webvh_token")).toBeUndefined();
  });

  it("signs through the wallet when the session bound no key", async () => {
    stubStorage({ webvh_token: TOKEN, webvh_auth_method: "wallet" });
    const sessionKey = await import("../session-key");
    sessionKey.clearSessionKeypair();
    vi.spyOn(sessionKey, "restoreSessionKeypair").mockResolvedValue();
    const signTrustTask = stubWallet();
    const sent = installControlPlane((req) => seal(req, { entries: [], truncated: false }));

    await api.listAcl();

    expect(signTrustTask).toHaveBeenCalledOnce();
    expect(tasks(sent)[0]!.doc.proof).toMatchObject({ verificationMethod: `${SUBJECT}#key-1` });
  });
});

// ---------------------------------------------------------------------------

describe("passkey login", () => {
  beforeEach(() => {
    stubStorage({});
  });

  it("opens the ceremony anonymously and unsigned", async () => {
    const sent = installControlPlane((req) =>
      seal(req, { authId: "auth-1", options: { challenge: "Y2hhbGxlbmdl" } }),
    );
    const start = await api.passkeyLoginStart();
    expect(start).toEqual({ authId: "auth-1", options: { challenge: "Y2hhbGxlbmdl" } });
    const { doc, bearer } = tasks(sent)[0]!;
    expect(doc).toMatchObject({ payload: { purpose: "login" }, recipient: SERVICE_DID });
    expect(doc.proof).toBeUndefined();
    expect(doc.issuer).toBeUndefined();
    expect(bearer).toBeUndefined();
  });

  it("finishes signed by a fresh session did:key as its own issuer, with no bearer", async () => {
    stubStorage({ webvh_token: tokenFor("did:web:previous.example") });
    const sent = installControlPlane((req) =>
      seal(req, {
        purpose: "login",
        session: {
          id: "s",
          subject: SUBJECT,
          issuedAt: "2026-01-01T00:00:00Z",
          expiresAt: "2026-01-02T00:00:00Z",
        },
        tokens: { accessToken: "a", refreshToken: "r", tokenType: "Bearer", expiresIn: 900 },
      }),
    );
    const credential = {
      id: "cred",
      rawId: "cred",
      type: "public-key" as const,
      response: { clientDataJSON: "c", authenticatorData: "a", signature: "s" },
    };

    const tokens = await api.passkeyLoginFinish("auth-1", credential);

    expect(tokens).toEqual({ accessToken: "a", refreshToken: "r" });
    const { doc, bearer } = tasks(sent)[0]!;
    expect(bearer).toBeUndefined();
    expect(doc.issuer).toMatch(/^did:key:z6Mk/);
    expect(doc.proof.verificationMethod).toBe(
      `${doc.issuer}#${String(doc.issuer).slice("did:key:".length)}`,
    );
  });

  it("refuses a login reply addressed to another key", async () => {
    installControlPlane((req) =>
      seal(
        req,
        {
          purpose: "login",
          session: { id: "s", subject: SUBJECT, issuedAt: "x", expiresAt: "y" },
          tokens: { accessToken: "a", tokenType: "Bearer", expiresIn: 900 },
        },
        { recipient: "did:key:z6MkSomeoneElse" },
      ),
    );
    await expect(
      api.passkeyLoginFinish("auth-1", {
        id: "c",
        rawId: "c",
        type: "public-key",
        response: { clientDataJSON: "c", authenticatorData: "a", signature: "s" },
      }),
    ).rejects.toThrow(/addressed to/);
  });
});

// ---------------------------------------------------------------------------

describe("wire projections", () => {
  it("reads webvh parameters cumulatively across the log", () => {
    const meta = logMetadataFromEntries([
      {
        versionId: "1",
        versionTime: "t1",
        state: {},
        parameters: {
          method: "did:webvh:1.0",
          nextKeyHashes: ["h"],
          witness: { threshold: 2, witnesses: [{ id: "w1" }, { id: "w2" }, { id: "w3" }] },
          watchers: ["https://w.example"],
        },
      },
      { versionId: "2", versionTime: "t2", state: {}, parameters: { nextKeyHashes: [] } },
      { versionId: "3", versionTime: "t3", state: {}, parameters: { deactivated: true } },
    ]);
    expect(meta).toEqual({
      logEntryCount: 3,
      latestVersionId: "3",
      latestVersionTime: "t3",
      method: "did:webvh:1.0",
      portable: false,
      preRotation: false,
      witnesses: true,
      witnessCount: 3,
      witnessThreshold: 2,
      watchers: true,
      watcherCount: 1,
      watcherUrls: ["https://w.example"],
      deactivated: true,
      ttl: null,
    });
    expect(logMetadataFromEntries([])).toBeNull();
  });

  it("reads a domain's host members from its extension", () => {
    const entry = domainFromWire({
      name: "example.com",
      status: "disabled",
      defaultDomain: false,
      createdAt: "2026-01-01T00:00:00Z",
      disabledAt: "2026-01-02T00:00:00Z",
      purgeAt: "2026-01-09T00:00:00Z",
      ext: {
        "vnd.affinidi.webvh": {
          scheme: "https",
          wellKnownEnabled: true,
          branding: { display_name: "Example", logo_url: null },
          watchers: ["https://w.example"],
          quota: { max_dids: 10 },
        },
      },
    });
    expect(entry).toMatchObject({
      name: "example.com",
      label: null,
      status: "disabled",
      wellKnownEnabled: true,
      branding: { displayName: "Example", logoUrl: null, primaryColor: null },
      watchers: ["https://w.example"],
      quota: { maxDids: 10, maxBytes: null },
      disabledAt: Date.parse("2026-01-02T00:00:00Z") / 1000,
      purgeAt: Date.parse("2026-01-09T00:00:00Z") / 1000,
    });
  });
});
