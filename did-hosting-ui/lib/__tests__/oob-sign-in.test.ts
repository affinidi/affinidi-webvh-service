/**
 * The wallet sign-in starter (`auth/oob/*`): trigger links, and the
 * controller's states against a scripted service.
 */

import { describe, expect, it } from "vitest";

import {
  buildTriggerLink,
  createSignIn,
  encodeFromParam,
  isUnavailable,
  renderQrSvg,
  shortCode,
  TRIGGER_LINK_MAX_BYTES,
  type SignInState,
  type StarterKeys,
} from "../oob-sign-in";

const DID = "did:webvh:QmSCIDabcdefghijklmnopqrstuvwxyz0123456789ABCD:dids.example.org";
const RID = "AAAAAAAAAAAAAAAAAAAAAA";

describe("trigger link", () => {
  it("has the C1 shape, with the path-form flow on the default host", () => {
    const link = buildTriggerLink({ from: DID, requestId: RID, exp: 1_800_000_000 });
    expect(link).toBe(
      `https://link.trustoverip.org/t#_from=${DID}&_id=${RID}&_exp=1800000000&_type=/vti/flow/sign-in/0.1`,
    );
    expect(link.length).toBeLessThanOrEqual(TRIGGER_LINK_MAX_BYTES);
  });

  it("uses the absolute flow URI on another link host", () => {
    const link = buildTriggerLink({ from: DID, requestId: RID, exp: 1, linkHost: "links.example.net" });
    expect(link).toContain("&_type=https://link.trustoverip.org/vti/flow/sign-in/0.1");
  });

  it("percent-encodes only & = # %", () => {
    expect(encodeFromParam("did:x:a&b=c#d%e:f/g")).toBe("did:x:a%26b%3Dc%23d%25e:f/g");
  });

  it("refuses a link host on the page's own domain (VTI-LNK-084)", () => {
    expect(() =>
      buildTriggerLink({ from: DID, requestId: RID, exp: 1, linkHost: "link.example.org", pageHost: "dids.example.org" }),
    ).toThrow(/same-domain-host/);
  });

  it("refuses did:key, bad handles, far expiries and over-long links", () => {
    expect(() => buildTriggerLink({ from: "did:key:z6Mkabc", requestId: RID, exp: 1 })).toThrow(/bad-from/);
    expect(() => buildTriggerLink({ from: DID, requestId: "short", exp: 1 })).toThrow(/bad-id/);
    expect(() => buildTriggerLink({ from: DID, requestId: RID, exp: 1000, nowSecs: 600 })).toThrow(/bad-exp/);
    expect(() => buildTriggerLink({ from: `${DID}:${"x".repeat(200)}`, requestId: RID, exp: 1 })).toThrow(/too-long/);
  });

  it("renders a QR through the supplied encoder with a 4-module quiet zone", () => {
    const svg = renderQrSvg("x", () => ({ size: 21, isDark: (r, c) => r === c }));
    expect(svg).toContain('viewBox="0 0 29 29"');
    expect(svg).toContain('width="116"');
    expect(svg).toContain("M4 4h1v1h-1z");
  });

  it("reads codes with or without the family prefix", () => {
    expect(shortCode("auth/oob/redeem:pending")).toBe("pending");
    expect(shortCode("pending")).toBe("pending");
  });
});

/** A document whose visibility the test controls. */
class FakeDocument extends EventTarget {
  visibilityState: "visible" | "hidden" = "visible";
  hide() {
    this.visibilityState = "hidden";
    this.dispatchEvent(new Event("visibilitychange"));
  }
}

const keys = (): StarterKeys & { cleared: number } => {
  const k = {
    cleared: 0,
    generate: async () => ({ didKey: "did:key:z6MkStarter" }),
    sign: async <T extends Record<string, unknown>>(doc: T) => ({ ...doc, proof: { proofValue: "z" } }) as T,
    clear: () => {
      k.cleared++;
    },
  };
  return k;
};

type Reply = { status: number; body: unknown };
const ok = (payload: unknown): Reply => ({ status: 200, body: { type: "x#response", payload } });
const err = (status: number, code: string, details?: unknown): Reply => ({
  status,
  body: { type: "https://trusttasks.org/spec/trust-task-error/0.5", payload: { code, message: code, details } },
});

/** A service that answers `request`, then each redeem from a script. */
function service(redeems: Reply[]) {
  const sent: Array<Record<string, unknown>> = [];
  const f = (async (_url: string, init: RequestInit) => {
    const doc = JSON.parse(String(init.body)) as Record<string, unknown>;
    sent.push(doc);
    let r: Reply;
    if (String(doc.type).endsWith("/request/0.1")) {
      r = ok({ requestId: RID, claimDeadline: Math.floor(Date.now() / 1000) + 120 });
    } else if (String(doc.type).endsWith("/cancel/0.1")) {
      r = ok({ status: "cancelled" });
    } else {
      r = redeems.shift() ?? err(409, "auth/oob/redeem:pending", { state: "pending" });
      if (redeems.length === 0 && r.status === 409) await new Promise((res) => setTimeout(res, 20));
    }
    return new Response(JSON.stringify(r.body), { status: r.status });
  }) as unknown as typeof fetch;
  return { f, sent };
}

async function until(get: () => SignInState, status: SignInState["status"]) {
  for (let i = 0; i < 200; i++) {
    if (get().status === status) return get();
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error(`never reached ${status}; at ${get().status}`);
}

describe("sign-in controller", () => {
  it("waits, shows the number, then asks Continue as …", async () => {
    const svc = service([
      err(409, "auth/oob/redeem:pending", { state: "claimed", matchNumber: "47" }),
      ok({ subject: "did:example:alice", displayName: "Alice", notAfter: 1_900_000_000, amr: ["did", "oob", "uv"] }),
    ]);
    let redeemed: Record<string, unknown> | undefined;
    const s = createSignIn({
      endpoint: "/api/trust-tasks",
      serviceDid: DID,
      fetch: svc.f,
      keys: keys(),
      document: new FakeDocument() as unknown as Document,
      pageHost: "dids.example.org",
      onRedeemed: (p) => (redeemed = p),
    });
    const seen: string[] = [];
    s.subscribe((st) => seen.push(st.status));
    await s.start();
    const confirm = await until(() => s.state, "confirm");
    expect(seen).toContain("waiting");
    expect(seen).toContain("claimed");
    expect(confirm).toMatchObject({ subject: "did:example:alice", displayName: "Alice" });
    expect((confirm as { notAfter: Date }).notAfter.getTime()).toBe(1_900_000_000_000);
    expect(redeemed?.amr).toEqual(["did", "oob", "uv"]);
    // Every document is from K_b to the service, at whole seconds.
    for (const d of svc.sent) {
      expect(d.issuer).toBe("did:key:z6MkStarter");
      expect(d.recipient).toBe(DID);
      expect(String(d.issuedAt)).toMatch(/:\d\dZ$/);
    }
    s.confirm();
    expect(s.state.status).toBe("signedIn");
    s.destroy();
  });

  it("hides the code when the tab is hidden, but keeps the request and polls on (C9)", async () => {
    const doc = new FakeDocument();
    const svc = service([
      err(409, "auth/oob/redeem:pending", { state: "pending" }),
      err(409, "auth/oob/redeem:pending", { state: "pending" }),
      ok({ subject: "did:example:alice", displayName: "Alice", notAfter: 1_900_000_000, amr: ["did"] }),
    ]);
    const s = createSignIn({ endpoint: "/e", serviceDid: DID, fetch: svc.f, keys: keys(), document: doc as unknown as Document, pageHost: "dids.example.org" });
    await s.start();
    await until(() => s.state, "waiting");
    doc.hide();
    expect(s.state).toMatchObject({ status: "waiting", codeVisible: false });
    await until(() => s.state, "confirm");
    expect(svc.sent.some((d) => String(d.type).endsWith("/cancel/0.1"))).toBe(false);
    s.destroy();
  });

  it("maps a cancelled request to cancelled and drops the key", async () => {
    const k = keys();
    const svc = service([err(409, "auth/oob/redeem:declined", { state: "cancelled" })]);
    const s = createSignIn({ endpoint: "/e", serviceDid: DID, fetch: svc.f, keys: k, document: new FakeDocument() as unknown as Document, pageHost: "dids.example.org" });
    await s.start();
    await until(() => s.state, "cancelled");
    expect(k.cleared).toBe(1);
  });

  it("maps an expired request to expired", async () => {
    const svc = service([err(409, "auth/oob:requestExpired", { state: "expired" })]);
    const s = createSignIn({ endpoint: "/e", serviceDid: DID, fetch: svc.f, keys: keys(), document: new FakeDocument() as unknown as Document, pageHost: "dids.example.org" });
    await s.start();
    await until(() => s.state, "expired");
  });

  it("cancel() tells the service", async () => {
    const svc = service([]);
    const s = createSignIn({ endpoint: "/e", serviceDid: DID, fetch: svc.f, keys: keys(), document: new FakeDocument() as unknown as Document, pageHost: "dids.example.org" });
    await s.start();
    await until(() => s.state, "waiting");
    await s.cancel();
    expect(s.state.status).toBe("cancelled");
    expect(svc.sent.some((d) => String(d.type).endsWith("/cancel/0.1"))).toBe(true);
  });

  it("reports a server without the sign-in as unavailable, so the page falls back", async () => {
    // A control plane with no service DID or public URL answers a plain 503.
    const f = (async () => new Response("wallet sign-in is not configured on this server", { status: 503 })) as unknown as typeof fetch;
    const s = createSignIn({ endpoint: "/e", serviceDid: DID, fetch: f, keys: keys(), document: new FakeDocument() as unknown as Document, pageHost: "dids.example.org" });
    await s.start();
    const st = await until(() => s.state, "error");
    expect(isUnavailable(st)).toBe(true);
  });

  it("does not treat an ordinary refusal as unavailable", () => {
    expect(isUnavailable({ status: "error", code: "auth/oob:rateLimited", message: "x" })).toBe(false);
    expect(isUnavailable({ status: "error", code: "timeout", message: "x" })).toBe(false);
    expect(isUnavailable({ status: "expired" })).toBe(false);
  });
});
