/**
 * Wallet sign-in started by a trigger link (`auth/oob/*`): the starter side.
 *
 * A stand-in for `@openvtc/rp-sdk/browser`'s `createSignIn` (contract C9),
 * with the same API, so the page can switch to the package once a version
 * with the `./browser` entry is published (0.2.0 on npm has none). Swap by
 * replacing this import; nothing else in the page should change.
 * TODO: replace with `@openvtc/rp-sdk/browser` once published.
 *
 * Differences from the reference that are deliberate, because contract C9 and
 * the `auth/oob/*` schemas fixed them after it was written:
 *  - `claimDeadline` and `notAfter` are integer epoch seconds only;
 *  - error codes are `auth/oob:*` / `auth/oob/<task>:*` (matched here on the
 *    part after the last `:`, so either spelling works);
 *  - `K_b` is this console's session key (`session-key.ts`), so after
 *    `redeem` the session's calls are signed with it without another step.
 *
 * The QR encoder is a pluggable {@link QrEncoder}. This UI has no QR library
 * in its dependencies, so none is bundled: without an encoder the page shows
 * the same `https` link as a button (same-device sign-in still works).
 *
 * Free of `react-native` so the test runner can reach it.
 */

import { clearSessionKeypair, generateSessionKeypair, signEnvelope } from "./session-key";

// ---- trigger links (VTI spec 07a, contract C1) --------------------------------

/** The shared link host (C1). Never on the page's own domain (VTI-LNK-084). */
export const DEFAULT_LINK_HOST = "link.trustoverip.org";
export const DEFAULT_LINK_PATH = "/t";
export const SIGN_IN_FLOW = "https://link.trustoverip.org/vti/flow/sign-in/0.1";
/** VTI-LNK-081: the longest link a level-M QR code may carry. */
export const TRIGGER_LINK_MAX_BYTES = 251;
/** VTI-LNK-100. */
export const SIGN_IN_MAX_LIFETIME_SECS = 300;

// TODO: replace with generated trust-tasks types
export const OOB_TYPES = {
  request: "https://trusttasks.org/spec/auth/oob/request/0.1",
  redeem: "https://trusttasks.org/spec/auth/oob/redeem/0.1",
  cancel: "https://trusttasks.org/spec/auth/oob/cancel/0.1",
} as const;

export class TriggerLinkError extends Error {
  constructor(
    readonly reason:
      | "bad-from"
      | "bad-id"
      | "bad-exp"
      | "bad-host"
      | "same-domain-host"
      | "non-ascii"
      | "too-long",
    message: string,
  ) {
    super(`trigger link refused (${reason}): ${message}`);
    this.name = "TriggerLinkError";
  }
}

/** Percent-encode `&`, `=`, `#` and `%` in `_from`, and nothing else (C1). */
export function encodeFromParam(from: string): string {
  return from.replace(/[&=#%]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0"));
}

/** Last two labels, or three under a two-letter ccTLD with a short second level. */
export function approximateRegistrableDomain(host: string): string {
  const labels = host.toLowerCase().replace(/\.$/, "").split(".");
  const n =
    labels.length >= 3 && labels[labels.length - 1]!.length === 2 && labels[labels.length - 2]!.length <= 3 ? 3 : 2;
  return labels.slice(-n).join(".");
}

export interface BuildTriggerLinkParams {
  from: string;
  requestId: string;
  /** Epoch seconds. */
  exp: number;
  linkHost?: string;
  linkPath?: string;
  /** Host of the page showing the link, for VTI-LNK-084. */
  pageHost?: string;
  nowSecs?: number;
}

/** Build `https://<host>/t#_from=…&_id=…&_exp=…&_type=…`, enforcing the producer rules. */
export function buildTriggerLink(p: BuildTriggerLinkParams): string {
  const linkHost = p.linkHost ?? DEFAULT_LINK_HOST;
  const linkPath = p.linkPath ?? DEFAULT_LINK_PATH;
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(linkHost)) {
    throw new TriggerLinkError("bad-host", `invalid link host ${linkHost}`);
  }
  if (p.pageHost && approximateRegistrableDomain(linkHost) === approximateRegistrableDomain(p.pageHost)) {
    throw new TriggerLinkError("same-domain-host", `link host ${linkHost} is on the page's own domain`);
  }
  if (!/^did:[a-z0-9]+:\S+$/.test(p.from) || p.from.startsWith("did:key:") || p.from.includes("/@")) {
    throw new TriggerLinkError("bad-from", "_from must be a DID that can list a SignInPortal service");
  }
  if (!/^[A-Za-z0-9_-]{22,43}$/.test(p.requestId)) {
    throw new TriggerLinkError("bad-id", "_id must be 16 to 32 bytes of unpadded base64url");
  }
  if (!Number.isSafeInteger(p.exp) || p.exp < 0) {
    throw new TriggerLinkError("bad-exp", "_exp must be integer epoch seconds");
  }
  if (p.nowSecs !== undefined && p.exp > p.nowSecs + SIGN_IN_MAX_LIFETIME_SECS) {
    throw new TriggerLinkError("bad-exp", `_exp is more than ${SIGN_IN_MAX_LIFETIME_SECS} s away`);
  }
  const flow = new URL(SIGN_IN_FLOW);
  // VTI-LNK-042: the path form when the flow is on the link's own host.
  const type = flow.host === linkHost ? flow.pathname : SIGN_IN_FLOW;
  const link =
    `https://${linkHost}${linkPath}#_from=${encodeFromParam(p.from)}` +
    `&_id=${p.requestId}&_exp=${p.exp}&_type=${type}`;
  if (!/^[\x21-\x7e]*$/.test(link)) throw new TriggerLinkError("non-ascii", "a trigger link must be ASCII");
  if (link.length > TRIGGER_LINK_MAX_BYTES) {
    throw new TriggerLinkError("too-long", `link is ${link.length} bytes; the level-M limit is ${TRIGGER_LINK_MAX_BYTES}`);
  }
  return link;
}

// ---- QR -----------------------------------------------------------------------

/** A QR symbol: a square of modules, `true` for dark. */
export interface QrMatrix {
  size: number;
  isDark(row: number, col: number): boolean;
}

/** Encodes ASCII text in byte mode at error-correction level M. */
export type QrEncoder = (text: string) => QrMatrix;

/**
 * The code as an SVG string: a quiet zone of at least 4 modules, at least 4
 * CSS px per module, dark on light, never inverted (C1).
 */
export function renderQrSvg(text: string, encoder: QrEncoder, moduleSize = 4): string {
  const quiet = 4;
  const px = Math.max(4, Math.floor(moduleSize));
  const m = encoder(text);
  let path = "";
  for (let r = 0; r < m.size; r++) {
    for (let c = 0; c < m.size; c++) if (m.isDark(r, c)) path += `M${c + quiet} ${r + quiet}h1v1h-1z`;
  }
  const units = m.size + 2 * quiet;
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Sign-in code" width="${units * px}" ` +
    `height="${units * px}" viewBox="0 0 ${units} ${units}" shape-rendering="crispEdges">` +
    `<rect width="${units}" height="${units}" fill="#ffffff"/><path d="${path}" fill="#000000"/></svg>`
  );
}

// ---- the starter ----------------------------------------------------------------

/** Everything the page needs to draw (same shape as the reference). */
export type SignInState =
  | { status: "idle" }
  | { status: "starting" }
  | { status: "waiting"; requestId: string; link: string; expiresAt: Date; codeVisible: boolean }
  | { status: "claimed"; requestId: string; matchNumber: string }
  | { status: "confirm"; subject: string; displayName?: string; notAfter?: Date }
  | { status: "signedIn"; subject: string; displayName?: string; notAfter?: Date }
  | { status: "declined" }
  | { status: "cancelled" }
  | { status: "expired" }
  | { status: "error"; code: string; message: string };

/** How `K_b` is made, used and dropped. Defaults to the console's session key. */
export interface StarterKeys {
  generate(): Promise<{ didKey: string }>;
  sign<T extends Record<string, unknown>>(doc: T): Promise<T>;
  clear(): void;
}

const sessionKeys: StarterKeys = {
  generate: () => generateSessionKeypair(),
  sign: (doc) => signEnvelope(doc as never),
  clear: () => clearSessionKeypair(),
};

export interface SignInOptions {
  /** The service's trust-task endpoint, e.g. `/api/trust-tasks`. */
  endpoint: string;
  /** The service DID: `recipient` of every document and `_from`. */
  serviceDid: string;
  /** Default `link.trustoverip.org`. */
  linkHost?: string;
  linkPath?: string;
  onStateChange?: (state: SignInState) => void;
  /**
   * The raw successful `redeem` payload, before the "Continue as …?" step.
   * Addition to the reference API: this service's session needs it (C9
   * conflict, see the control plane's `oob::http`).
   */
  onRedeemed?: (payload: Record<string, unknown>) => void;
  requestTimeoutMs?: number;
  pollTimeoutMs?: number;
  fetch?: typeof fetch;
  document?: Document;
  pageHost?: string;
  keys?: StarterKeys;
}

export class SignInError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "SignInError";
  }
}

type PostResult =
  | { ok: true; payload: Record<string, unknown> }
  | { ok: false; code: string; message: string; details?: Record<string, unknown> };

/** The last segment of an error code: `auth/oob/redeem:pending` → `pending`. */
export function shortCode(code: string): string {
  const i = code.lastIndexOf(":");
  return i < 0 ? code : code.slice(i + 1);
}

export function createSignIn(options: SignInOptions): SignInController {
  return new SignInController(options);
}

export class SignInController {
  private current: SignInState = { status: "idle" };
  private readonly listeners = new Set<(s: SignInState) => void>();
  private keyDid: string | null = null;
  private requestId: string | null = null;
  private run = 0;
  private poll: AbortController | null = null;
  private expiryTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly keys: StarterKeys;
  private readonly doc: Document | undefined;
  private readonly onVisibility = () => this.visibilityChanged();

  constructor(private readonly opts: SignInOptions) {
    this.keys = opts.keys ?? sessionKeys;
    this.doc = opts.document ?? (typeof document !== "undefined" ? document : undefined);
    if (opts.onStateChange) this.listeners.add(opts.onStateChange);
    this.doc?.addEventListener("visibilitychange", this.onVisibility);
  }

  get state(): SignInState {
    return this.current;
  }

  subscribe(listener: (s: SignInState) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /** "Show sign-in code": a fresh `K_b`, `auth/oob/request`, then the code. */
  async start(): Promise<void> {
    await this.abandon();
    const run = ++this.run;
    this.set({ status: "starting" });
    try {
      this.keyDid = (await this.keys.generate()).didKey;
      const res = await this.post(await this.signed(OOB_TYPES.request, { purpose: "login", mode: "scan" }), this.opts.requestTimeoutMs ?? 15_000);
      if (run !== this.run) return;
      if (!res.ok) throw new SignInError(res.code, res.message, res.details);
      const { requestId, claimDeadline } = res.payload as { requestId?: unknown; claimDeadline?: unknown };
      if (typeof requestId !== "string" || typeof claimDeadline !== "number" || !Number.isSafeInteger(claimDeadline)) {
        throw new SignInError("malformedResponse", "the service returned an unusable request");
      }
      const link = buildTriggerLink({
        from: this.opts.serviceDid,
        requestId,
        exp: claimDeadline,
        linkHost: this.opts.linkHost,
        linkPath: this.opts.linkPath,
        pageHost: this.opts.pageHost ?? (typeof location !== "undefined" ? location.hostname : undefined),
        nowSecs: Math.floor(Date.now() / 1000),
      });
      this.requestId = requestId;
      this.set({
        status: "waiting",
        requestId,
        link,
        expiresAt: new Date(claimDeadline * 1000),
        codeVisible: this.doc?.visibilityState !== "hidden",
      });
      this.expiryTimer = setTimeout(
        () => {
          if (run === this.run && this.current.status === "waiting") void this.finish("expired");
        },
        Math.max(0, claimDeadline * 1000 - Date.now()),
      );
      void this.pollLoop(run);
    } catch (e) {
      if (run !== this.run) return;
      this.dropKey();
      this.fail(e);
    }
  }

  /** Cancel the open request (`auth/oob/cancel`). */
  async cancel(): Promise<void> {
    if (this.current.status !== "waiting" && this.current.status !== "claimed") return;
    await this.abandon();
    this.set({ status: "cancelled" });
  }

  /** "Continue as …?": confirmed. */
  confirm(): void {
    if (this.current.status !== "confirm") return;
    const { subject, displayName, notAfter } = this.current;
    this.set({ status: "signedIn", subject, displayName, notAfter });
  }

  /** "Not me": sign out at once. */
  async notMe(): Promise<void> {
    await this.signOut();
  }

  /** Forget `K_b` and return to idle. The page ends its own session. */
  async signOut(): Promise<void> {
    this.run++;
    this.stopPolling();
    this.dropKey();
    this.requestId = null;
    this.set({ status: "idle" });
  }

  destroy(): void {
    this.run++;
    this.stopPolling();
    this.doc?.removeEventListener("visibilitychange", this.onVisibility);
    this.listeners.clear();
  }

  private async pollLoop(run: number): Promise<void> {
    let failures = 0;
    while (run === this.run && this.requestId) {
      const requestId = this.requestId;
      this.poll = new AbortController();
      let res: PostResult;
      try {
        res = await this.post(await this.signed(OOB_TYPES.redeem, { requestId }), this.opts.pollTimeoutMs ?? 35_000, this.poll.signal);
      } catch (e) {
        if (run !== this.run) return;
        if (++failures > 5) return this.fail(e);
        await sleep(Math.min(1000 * failures, 5000));
        continue;
      }
      if (run !== this.run) return;
      failures = 0;
      if (res.ok) {
        const body = res.payload;
        if (typeof body.subject !== "string") {
          return this.fail(new SignInError("malformedResponse", "redeem returned no subject"));
        }
        this.clearTimers();
        this.requestId = null;
        this.opts.onRedeemed?.(body);
        this.set({
          status: "confirm",
          subject: body.subject,
          displayName: typeof body.displayName === "string" ? body.displayName : undefined,
          notAfter: typeof body.notAfter === "number" ? new Date(body.notAfter * 1000) : undefined,
        });
        return;
      }
      switch (shortCode(res.code)) {
        case "pending": {
          const n = res.details?.matchNumber;
          if (typeof n === "string" && this.current.status === "waiting") {
            this.clearTimers();
            this.set({ status: "claimed", requestId, matchNumber: n });
          }
          continue;
        }
        case "rateLimited":
          await sleep(1000);
          continue;
        case "declined":
          return this.finish(res.details?.state === "cancelled" ? "cancelled" : "declined");
        case "requestExpired":
        case "requestNotFound":
          return this.finish("expired");
        default:
          return this.fail(new SignInError(res.code, res.message, res.details));
      }
    }
  }

  private async finish(status: "declined" | "cancelled" | "expired"): Promise<void> {
    this.run++;
    this.stopPolling();
    this.requestId = null;
    this.dropKey();
    this.set({ status });
  }

  private async abandon(): Promise<void> {
    this.run++;
    this.stopPolling();
    const requestId = this.requestId;
    this.requestId = null;
    if (requestId && this.keyDid) {
      try {
        await this.post(await this.signed(OOB_TYPES.cancel, { requestId }), this.opts.requestTimeoutMs ?? 15_000);
      } catch {
        // Best effort: the request expires on its own.
      }
    }
    this.dropKey();
  }

  /**
   * C9: on `visibilitychange` to hidden, hide the code but keep the request
   * and keep polling. On a phone, tapping the code opens the wallet and hides
   * this tab, and that sign-in must still complete.
   */
  private visibilityChanged(): void {
    if (this.current.status !== "waiting") return;
    if (this.doc?.visibilityState === "hidden" && this.current.codeVisible) {
      this.set({ ...this.current, codeVisible: false });
    }
  }

  private stopPolling(): void {
    this.poll?.abort();
    this.poll = null;
    this.clearTimers();
  }

  private clearTimers(): void {
    if (this.expiryTimer) clearTimeout(this.expiryTimer);
    this.expiryTimer = null;
  }

  private dropKey(): void {
    if (this.keyDid) this.keys.clear();
    this.keyDid = null;
  }

  private fail(e: unknown): void {
    this.run++;
    this.stopPolling();
    this.requestId = null;
    const code = e instanceof SignInError ? e.code : ((e as { name?: string })?.name ?? "error");
    this.set({ status: "error", code, message: e instanceof Error ? e.message : String(e) });
  }

  private set(state: SignInState): void {
    this.current = state;
    for (const l of [...this.listeners]) {
      try {
        l(state);
      } catch {
        // A listener's bug must not stop the flow.
      }
    }
  }

  private async signed<P>(type: string, payload: P): Promise<Record<string, unknown>> {
    return this.keys.sign({
      id: `urn:uuid:${crypto.randomUUID()}`,
      type,
      issuer: this.keyDid,
      recipient: this.opts.serviceDid,
      // Whole seconds: the service re-serialises `issuedAt` before hashing.
      issuedAt: `${new Date().toISOString().slice(0, 19)}Z`,
      payload,
    } as Record<string, unknown>);
  }

  private async post(doc: unknown, timeoutMs: number, signal?: AbortSignal): Promise<PostResult> {
    const f = this.opts.fetch ?? fetch;
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(new SignInError("timeout", "the service did not answer")), timeoutMs);
    const onAbort = () => ctl.abort(signal!.reason);
    signal?.addEventListener("abort", onAbort);
    try {
      const res = await f(this.opts.endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        credentials: "same-origin",
        cache: "no-store",
        referrerPolicy: "no-referrer",
        body: JSON.stringify(doc),
        signal: ctl.signal,
      });
      const body = (await res.json().catch(() => null)) as { type?: string; payload?: Record<string, unknown> } | null;
      const isError = !res.ok || (typeof body?.type === "string" && body.type.includes("/trust-task-error/"));
      if (!isError) return { ok: true, payload: body?.payload ?? {} };
      const p = body?.payload ?? {};
      return {
        ok: false,
        code: typeof p.code === "string" ? p.code : res.status === 429 ? "rateLimited" : `http${res.status}`,
        message: typeof p.message === "string" ? p.message : `${res.status} from the sign-in service`,
        ...(p.details && typeof p.details === "object" ? { details: p.details as Record<string, unknown> } : {}),
      };
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** The link host this console uses: `EXPO_PUBLIC_TRIGGER_LINK_HOST`, else the default. */
export function configuredLinkHost(): string {
  return process.env.EXPO_PUBLIC_TRIGGER_LINK_HOST || DEFAULT_LINK_HOST;
}
