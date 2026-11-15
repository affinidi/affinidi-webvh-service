/**
 * The JWT decoder and session renewal.
 *
 * Renewal goes through the Trust Task client, so its reply is held to the
 * same checks as every other: an unsigned or misaddressed reply does not
 * replace the session's tokens.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  decodeJwtPayload,
  getRefreshToken,
  getSessionId,
  getSessionSubjectDid,
  getToken,
  renewSessionNow,
} from "../session";
import { generateSessionKeypair, getSessionDidKey } from "../session-key";
import { resetServiceInfo } from "../trust-task";
import {
  SERVICE_DID,
  installControlPlane,
  seal,
  stubStorage,
  tokenFor,
} from "./fake-control-plane";

const REFRESH = "https://trusttasks.org/spec/auth/refresh/0.2";
const SUBJECT = "did:webvh:QmAdmin:example.com:admin";

/** base64url without padding, of UTF-8 bytes. */
function b64url(value: unknown): string {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  const binary = String.fromCharCode(...bytes);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

describe("decodeJwtPayload", () => {
  it("decodes base64url payloads that plain atob refuses", () => {
    // `?>` and `~~~` encode to `/` and `+` in base64, so the url-safe form
    // carries `_` and `-` — exactly what a raw `atob` choked on.
    const claims = { sub: "did:example:?>?>", role: "admin", note: "~~~", exp: 42 };
    const segment = b64url(claims);
    expect(segment).toMatch(/[-_]/);
    expect(decodeJwtPayload(`h.${segment}.s`)).toEqual(claims);
  });

  it("decodes non-ASCII claims as UTF-8", () => {
    const claims = { sub: "did:example:ünïcødé" };
    expect(decodeJwtPayload(`h.${b64url(claims)}.s`)).toEqual(claims);
  });

  it("returns null for anything that is not a JWT with an object payload", () => {
    expect(decodeJwtPayload(null)).toBeNull();
    expect(decodeJwtPayload("nodots")).toBeNull();
    expect(decodeJwtPayload("h.%%%.s")).toBeNull();
    expect(decodeJwtPayload(`h.${b64url([1, 2])}.s`)).toBeNull();
  });

  it("feeds the session getters", () => {
    stubStorage({ webvh_token: tokenFor(SUBJECT, { session_id: "sess-9" }) });
    expect(getSessionSubjectDid()).toBe(SUBJECT);
    expect(getSessionId()).toBe("sess-9");
  });
});

describe("renewSessionNow", () => {
  beforeEach(async () => {
    resetServiceInfo();
    stubStorage({
      webvh_token: tokenFor(SUBJECT, { session_id: "sess-1" }),
      webvh_refresh_token: "refresh-1",
      webvh_auth_method: "passkey",
    });
    await generateSessionKeypair();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("sends auth/refresh signed by the session key as itself, with no bearer", async () => {
    const next = tokenFor(SUBJECT, { session_id: "sess-1", acr: "aal2" });
    const sent = installControlPlane((req) =>
      req.type === REFRESH
        ? seal(req, {
            tokens: {
              accessToken: next,
              refreshToken: "refresh-2",
              tokenType: "Bearer",
              expiresIn: 900,
            },
          })
        : undefined,
    );

    await renewSessionNow();

    const doc = sent.find((s) => s.doc.type === REFRESH)!;
    expect(doc.bearer).toBeUndefined();
    expect(doc.doc.id).toMatch(/^urn:uuid:/);
    expect(doc.doc.issuer).toBe(getSessionDidKey());
    expect(doc.doc.recipient).toBe(SERVICE_DID);
    expect(doc.doc.payload).toEqual({ refreshToken: "refresh-1" });
    expect(getToken()).toBe(next);
    expect(getRefreshToken()).toBe("refresh-2");
  });

  it("keeps the old tokens when the reply is not the service's signed answer", async () => {
    const before = getToken();
    installControlPlane((req) =>
      req.type === REFRESH
        ? seal(
            req,
            {
              tokens: {
                accessToken: "forged",
                refreshToken: "x",
                tokenType: "Bearer",
                expiresIn: 1,
              },
            },
            { issuer: "did:example:someone-else" },
          )
        : undefined,
    );

    await expect(renewSessionNow()).rejects.toThrow(/not the service/);
    expect(getToken()).toBe(before);
    expect(getRefreshToken()).toBe("refresh-1");
  });
});
