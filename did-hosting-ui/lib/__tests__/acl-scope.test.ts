/**
 * The ACL "Add Entry" domain-scope draft: wire round-tripping, validation,
 * and the fresh-Owner default the console now computes itself (`acl/grant`
 * no longer infers one server-side — see `defaultScopeForRole`'s doc).
 */

import { describe, expect, it } from "vitest";

import {
  DEFAULT_SCOPE_DRAFT,
  aclEntryToDraft,
  defaultScopeForRole,
  draftToScope,
  validateScopeDraft,
  type ScopeDraft,
} from "../acl-scope";
import type { AclEntry } from "../api";

const entry = (domains: AclEntry["domains"]): AclEntry => ({
  did: "did:web:alice.example",
  role: "owner",
  label: null,
  created_at: 0,
  max_total_size: null,
  max_did_count: null,
  domains,
});

describe("defaultScopeForRole", () => {
  it("scopes a fresh Owner to the system default domain", () => {
    expect(defaultScopeForRole("owner", "alpha.example")).toEqual({
      kind: "allowed_with_default",
      domains: ["alpha.example"],
      default: "alpha.example",
    });
  });

  it("falls back to All domains for Owner while no system default is configured", () => {
    expect(defaultScopeForRole("owner", null)).toEqual(DEFAULT_SCOPE_DRAFT);
  });

  it.each(["admin", "service"] as const)(
    "defaults %s to All domains even with a system default configured",
    (role) => {
      expect(defaultScopeForRole(role, "alpha.example")).toEqual(DEFAULT_SCOPE_DRAFT);
    },
  );
});

describe("draftToScope / aclEntryToDraft round-trip", () => {
  it("round-trips All domains", () => {
    const draft = aclEntryToDraft(entry({ kind: "all" }));
    expect(draft).toEqual({ kind: "all", domains: [], default: "" });
    expect(draftToScope(draft)).toEqual({ kind: "all" });
  });

  it("round-trips Allowed", () => {
    const draft = aclEntryToDraft(
      entry({ kind: "allowed", domains: ["a.example", "b.example"] }),
    );
    expect(draftToScope(draft)).toEqual({
      kind: "allowed",
      domains: ["a.example", "b.example"],
    });
  });

  it("round-trips AllowedWithDefault", () => {
    const draft = aclEntryToDraft(
      entry({
        kind: "allowed_with_default",
        domains: ["a.example", "b.example"],
        default: "b.example",
      }),
    );
    expect(draftToScope(draft)).toEqual({
      kind: "allowed_with_default",
      domains: ["a.example", "b.example"],
      default: "b.example",
    });
  });

  it("treats a missing `domains` (pre-v0.7 entry) as All", () => {
    expect(aclEntryToDraft(entry(null as never))).toEqual({
      kind: "all",
      domains: [],
      default: "",
    });
  });
});

describe("draftToScope omits an unset/invalid draft", () => {
  it.each<[string, ScopeDraft]>([
    ["Specific with no domain selected", { kind: "allowed", domains: [], default: "" }],
    [
      "Specific + default with no domain selected",
      { kind: "allowed_with_default", domains: [], default: "" },
    ],
    [
      "Specific + default with no default chosen",
      { kind: "allowed_with_default", domains: ["a.example"], default: "" },
    ],
  ])("%s", (_what, draft) => {
    expect(draftToScope(draft)).toBeUndefined();
  });
});

describe("validateScopeDraft", () => {
  it("accepts All domains unconditionally", () => {
    expect(validateScopeDraft({ kind: "all", domains: [], default: "" })).toBeNull();
  });

  it("requires at least one domain for Specific", () => {
    expect(validateScopeDraft({ kind: "allowed", domains: [], default: "" })).toMatch(
      /select at least one domain/i,
    );
  });

  it("requires a default for Specific + default", () => {
    expect(
      validateScopeDraft({ kind: "allowed_with_default", domains: ["a.example"], default: "" }),
    ).toMatch(/pick a default domain/i);
  });

  it("requires the default to be one of the selected domains", () => {
    expect(
      validateScopeDraft({
        kind: "allowed_with_default",
        domains: ["a.example"],
        default: "b.example",
      }),
    ).toMatch(/default must be one of the selected domains/i);
  });

  it("accepts a well-formed Specific + default draft", () => {
    expect(
      validateScopeDraft({
        kind: "allowed_with_default",
        domains: ["a.example", "b.example"],
        default: "a.example",
      }),
    ).toBeNull();
  });
});
