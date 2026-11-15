/**
 * The pure helpers behind the console's guard, validation and error copy:
 * the route-guard decision, the `?next=` check, the server-mirroring form
 * validators, the rejection-code messages and the claim-code formatter.
 */

import { describe, expect, it } from "vitest";

import { formatClaimCode } from "../enrol-flow";
import { PASSKEY_CANCELLED, STEP_UP_GUIDANCE, errorMessage, isNotFound } from "../errors";
import { ApiError } from "../http";
import { loginHref, safeNextPath } from "../next-path";
import { guardDecision, isPublicRoute } from "../route-guard";
import { TrustTaskRejection } from "../trust-task";
import { aclSubjectError, didPathError, domainNameError, quotaError } from "../validation";

describe("guardDecision", () => {
  const base = { pathname: "/dids", restored: true, isAuthenticated: false, sessionExpired: false };
  it("shows the splash until the saved session has been looked for", () => {
    expect(guardDecision({ ...base, restored: false })).toBe("splash");
  });
  it("sends a signed-out visitor to sign in", () => {
    expect(guardDecision(base)).toBe("redirect");
  });
  it("keeps the screen under a prompt when the session expired", () => {
    expect(guardDecision({ ...base, sessionExpired: true })).toBe("expired");
  });
  it("renders for a session, and always for the public pages", () => {
    expect(guardDecision({ ...base, isAuthenticated: true })).toBe("render");
    expect(guardDecision({ ...base, pathname: "/login", restored: false })).toBe("render");
    expect(guardDecision({ ...base, pathname: "/enroll" })).toBe("render");
    expect(isPublicRoute("/loginx")).toBe(false);
  });
});

describe("safeNextPath", () => {
  it("accepts a same-origin path with its query", () => {
    expect(safeNextPath("/dids/alice")).toBe("/dids/alice");
    expect(safeNextPath("/dids?owner=did%3Aweb%3Ax")).toBe("/dids?owner=did%3Aweb%3Ax");
    expect(safeNextPath(["/acl"])).toBe("/acl");
  });
  it("refuses anything that could leave the origin", () => {
    for (const bad of [
      "//evil.example",
      "/\\evil.example",
      "https://evil.example/",
      "javascript:alert(1)",
      "evil.example",
      "/\t/evil.example",
      "",
      undefined,
      42,
    ]) {
      expect(safeNextPath(bad), String(bad)).toBeNull();
    }
  });
  it("never returns to the sign-in or enrolment pages", () => {
    expect(safeNextPath("/login?next=/x")).toBeNull();
    expect(safeNextPath("/enroll")).toBeNull();
  });
  it("builds the sign-in address", () => {
    expect(loginHref("/dids/a b")).toBe("/login?next=%2Fdids%2Fa%20b");
    expect(loginHref("/")).toBe("/login");
    expect(loginHref("//evil")).toBe("/login");
  });
});

describe("didPathError (the server's validate_custom_path)", () => {
  it("accepts what the server accepts", () => {
    for (const ok of ["", "alice", "people/staff/glenn", "a1-b2", "x".repeat(63)]) {
      expect(didPathError(ok), ok).toBeNull();
    }
  });
  it("refuses what the server refuses, saying why", () => {
    expect(didPathError("a")).toMatch(/2–63/);
    expect(didPathError("x".repeat(64))).toMatch(/2–63/);
    expect(didPathError("Alice")).toMatch(/lowercase/);
    expect(didPathError("al_ice")).toMatch(/lowercase/);
    expect(didPathError("-alice")).toMatch(/start and end/);
    expect(didPathError("alice/")).toMatch(/start or end/);
    expect(didPathError("ab//cd")).toMatch(/“\/\/”/);
    expect(didPathError("api/alice")).toMatch(/reserved/);
    expect(didPathError("people/api")).toBeNull();
    expect(didPathError(`${"ab/".repeat(85)}ab`)).toMatch(/255/);
  });
});

describe("domainNameError (the server's normalize_domain_name)", () => {
  it("accepts canonical names", () => {
    for (const ok of [
      "example.com",
      "tenant-a.example.com",
      "localhost:8534",
      "example.com/webvh-a",
    ]) {
      expect(domainNameError(ok), ok).toBeNull();
    }
  });
  it("refuses non-canonical or non-host input", () => {
    expect(domainNameError("Example.com")).toMatch(/lowercase/);
    expect(domainNameError(" example.com")).toMatch(/spaces/);
    expect(domainNameError("https://example.com")).toMatch(/without https/);
    expect(domainNameError("10.0.0.1")).toMatch(/IP address/);
    expect(domainNameError("exa mple.com")).toMatch(/letters, digits/);
    expect(domainNameError("example..com")).toMatch(/empty part/);
    expect(domainNameError("example.com:0")).toMatch(/port/);
    expect(domainNameError("example.com/A")).toMatch(/path/);
    expect(domainNameError("")).toMatch(/Enter a host/);
  });
});

describe("ACL form validation", () => {
  it("takes a DID or an agent name", () => {
    expect(aclSubjectError("did:web:example.com")).toBeNull();
    expect(aclSubjectError("did:webvh:QmScid:example.com:alice")).toBeNull();
    expect(aclSubjectError("example.com/@alice")).toBeNull();
    expect(aclSubjectError("")).toBeNull();
    expect(aclSubjectError("alice")).toMatch(/Enter a DID/);
    expect(aclSubjectError("did:web")).toMatch(/not a valid DID/);
    expect(aclSubjectError("example.com/@")).toMatch(/agent name/);
  });
  it("says inline when a quota is not a number", () => {
    expect(quotaError("")).toBeNull();
    expect(quotaError("1.5")).toBeNull();
    expect(quotaError("lots")).toMatch(/number/);
    expect(quotaError("1.5", { integer: true })).toMatch(/whole number/);
    expect(quotaError("-1", { integer: true })).toMatch(/whole number/);
  });
});

describe("errorMessage", () => {
  const rejection = (code: string, message?: string) =>
    new TrustTaskRejection(message ?? code, { code, message, retryable: false });

  it("maps rejection codes to sentences, keeping the server's detail", () => {
    expect(
      errorMessage(rejection("permissionDenied", "only Admin callers may enumerate the ACL")),
    ).toBe("You don't have permission to do this. (only Admin callers may enumerate the ACL)");
    expect(errorMessage(rejection("did-management:notFound"))).toMatch(/^Not found/);
    expect(errorMessage(rejection("unavailable"))).toMatch(/temporarily unavailable/);
    expect(errorMessage(rejection("stepUpRequired"))).toBe(STEP_UP_GUIDANCE);
    expect(errorMessage(rejection("permissionDenied", "step_up_required"))).toBe(STEP_UP_GUIDANCE);
  });
  it("passes an unknown code's own message through", () => {
    expect(errorMessage(rejection("e.p.did.path-invalid", "bad path"))).toBe("bad path");
  });
  it("says a dismissed passkey prompt was cancelled", () => {
    const e = Object.assign(new Error("NotAllowedError: …"), { name: "NotAllowedError" });
    expect(errorMessage(e)).toBe(PASSKEY_CANCELLED);
    expect(errorMessage(Object.assign(new Error("x"), { name: "AbortError" }))).toBe(
      PASSKEY_CANCELLED,
    );
  });
  it("explains transport failures in plain words", () => {
    expect(errorMessage(new TypeError("Failed to fetch"))).toMatch(/Could not reach/);
    expect(errorMessage(new ApiError(502, "refused the reply to https://x: bad proof"))).toMatch(
      /could not be verified/,
    );
    expect(errorMessage(new ApiError(401, ""))).toMatch(/session has ended/);
    expect(errorMessage("plain string")).toBe("plain string");
    expect(errorMessage(null, "fallback")).toBe("fallback");
  });
  it("recognises not-found", () => {
    expect(isNotFound(rejection("notFound"))).toBe(true);
    expect(isNotFound(new ApiError(404, "gone"))).toBe(true);
    expect(isNotFound(new Error("x"))).toBe(false);
  });
});

describe("formatClaimCode", () => {
  it("groups the code in fours, upper-cased, as it is typed", () => {
    expect(formatClaimCode("abcd")).toBe("ABCD");
    expect(formatClaimCode("abcde")).toBe("ABCD-E");
    expect(formatClaimCode("abcd efgh-ijkl")).toBe("ABCD-EFGH-IJKL");
    expect(formatClaimCode("ABCD-EFGH-IJKL-MNOP")).toBe("ABCD-EFGH-IJKL");
  });
});
