/**
 * A stand-in for the control plane's `POST /api/trust-tasks`, for the API
 * tests. It answers the way the real one does: a reply threaded to the
 * request, issued by the service DID, addressed back to the requester, with a
 * proof under a key of the service DID; errors as unsigned documents at the
 * status `status_for_code` maps their code to.
 *
 * The proof is shaped, not real — the console checks the binding, not the
 * signature bytes (see `trust-task.ts`).
 */

import { vi } from "vitest";

export const SERVICE_DID = "did:webvh:QmTest:control.example.com";
export const SERVER_INFO = "https://trusttasks.org/spec/did-management/server/info/0.1";
export const TT_ERROR = "https://trusttasks.org/spec/trust-task-error/0.3";

export type Doc = Record<string, any>;

/** An unsigned JWT carrying `claims` — all the UI reads from a token. */
export function tokenFor(sub: string, extra: Record<string, unknown> = {}): string {
  const b64url = (v: unknown) =>
    btoa(JSON.stringify(v)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${b64url({ alg: "none" })}.${b64url({ sub, ...extra })}.`;
}

/** The control plane's signed reply to `req`. `overrides` replace members
 *  after sealing, to forge a bad one. */
export function seal(req: Doc, payload: unknown, overrides: Doc = {}): Doc {
  return {
    id: `urn:uuid:${crypto.randomUUID()}`,
    threadId: req.id,
    type: `${req.type}#response`,
    issuer: SERVICE_DID,
    ...(req.issuer ? { recipient: req.issuer } : {}),
    issuedAt: new Date().toISOString(),
    payload,
    proof: {
      type: "DataIntegrityProof",
      cryptosuite: "eddsa-jcs-2022",
      verificationMethod: `${SERVICE_DID}#key-0`,
      proofPurpose: "authentication",
      created: new Date().toISOString(),
      proofValue: "z3FakeSignature",
    },
    ...overrides,
  };
}

/** A `trust-task-error` document. */
export function rejection(code: string, retryable = false): Doc {
  return {
    id: `urn:uuid:${crypto.randomUUID()}`,
    type: TT_ERROR,
    payload: { code, message: `${code} from test`, retryable },
  };
}

const STATUS_FOR_CODE: Record<string, number> = {
  permissionDenied: 403,
  notFound: 404,
  malformedRequest: 400,
  taskFailed: 422,
  unavailable: 503,
  internalError: 500,
};

export interface StubResponse {
  ok: boolean;
  status: number;
  statusText?: string;
  headers: Headers;
  json: () => Promise<unknown>;
  text: () => Promise<string>;
}

export function jsonResponse(body: unknown, status = 200): StubResponse {
  const text = JSON.stringify(body);
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? "OK" : "Error",
    headers: new Headers({ "content-type": "application/json" }),
    json: async () => body,
    text: async () => text,
  };
}

function asResponse(doc: Doc): StubResponse {
  if (typeof doc.type === "string" && doc.type.includes("/trust-task-error/")) {
    const status = STATUS_FOR_CODE[doc.payload?.code] ?? 422;
    return jsonResponse(doc, status);
  }
  return jsonResponse(doc);
}

export interface Sent {
  doc: Doc;
  /** The `Authorization` header, when one was sent. */
  bearer: string | undefined;
}

/** What the fake answers a request with: a reply document, or `undefined` for
 *  "not expected". */
export type Handler = (req: Doc) => Doc | undefined;

/**
 * Install the fake as `fetch`. `server/info` is answered for you (override it
 * by handling it); everything else goes to `handler`. Returns every document
 * sent, `server/info` included, in order.
 */
export function installControlPlane(handler: Handler, serverInfo?: Handler): Sent[] {
  const sent: Sent[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path: string, init?: RequestInit) => {
      if (path !== "/api/trust-tasks") throw new Error(`unexpected fetch: ${path}`);
      const doc = JSON.parse(String(init?.body ?? "{}")) as Doc;
      const headers = (init?.headers ?? {}) as Record<string, string>;
      sent.push({ doc, bearer: headers["Authorization"] });
      if (doc.type === SERVER_INFO) {
        const reply =
          serverInfo?.(doc) ??
          seal(doc, { serviceDid: SERVICE_DID, agentNames: true, serviceNames: [] });
        return asResponse(reply);
      }
      const reply = handler(doc);
      if (!reply) throw new Error(`unexpected task: ${doc.type}`);
      return asResponse(reply);
    }),
  );
  return sent;
}

/** A `localStorage` holding `entries`. */
export function stubStorage(entries: Record<string, string>): Map<string, string> {
  const store = new Map(Object.entries(entries));
  vi.stubGlobal("localStorage", {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => void store.set(k, v),
    removeItem: (k: string) => void store.delete(k),
  });
  return store;
}
