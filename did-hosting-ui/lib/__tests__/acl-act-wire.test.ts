/**
 * An ACL entry's domains are its AclEntry 0.2 `act` scope. Admin and Service
 * always act on every domain; an empty domain list is `none`, never an empty
 * `contexts`; and dropping a domain is a revoke narrowing, never a grant.
 */

import { describe, expect, it } from "vitest";

import { actNarrowing, actOf, domainsFromAct } from "../wire";

const ctx = (...contexts: string[]) => ({ scope: "contexts", contexts }) as never;

describe("actOf", () => {
  it("is all for Admin and Service whatever the domains say", () => {
    expect(actOf("admin", { kind: "allowed", domains: ["a.example"] })).toEqual({ scope: "all" });
    expect(actOf("service", { kind: "allowed", domains: [] })).toEqual({ scope: "all" });
  });

  it("states an Owner's domains as contexts, and none for an empty list", () => {
    expect(actOf("owner", { kind: "all" })).toEqual({ scope: "all" });
    expect(actOf("owner", { kind: "allowed", domains: ["a.example", "a.example"] })).toEqual(
      ctx("a.example"),
    );
    expect(actOf("metricsReader", { kind: "allowed", domains: [] })).toEqual({ scope: "none" });
  });
});

describe("domainsFromAct", () => {
  it("keeps the default only while it is one of the contexts", () => {
    expect(domainsFromAct(ctx("a.example", "b.example"), "b.example")).toEqual({
      kind: "allowed_with_default",
      domains: ["a.example", "b.example"],
      default: "b.example",
    });
    expect(domainsFromAct(ctx("a.example"), "z.example")).toEqual({
      kind: "allowed",
      domains: ["a.example"],
    });
    expect(domainsFromAct({ scope: "none" })).toEqual({ kind: "allowed", domains: [] });
    expect(domainsFromAct({ scope: "all" })).toEqual({ kind: "all" });
  });
});

describe("actNarrowing", () => {
  it("is null when nothing is dropped", () => {
    expect(actNarrowing(ctx("a.example"), { scope: "all" })).toBeNull();
    expect(actNarrowing(ctx("a.example"), ctx("a.example", "b.example"))).toBeNull();
    expect(actNarrowing({ scope: "none" }, ctx("a.example"))).toBeNull();
  });

  it("narrows to what is kept of the current scope", () => {
    expect(actNarrowing({ scope: "all" }, ctx("a.example"))).toEqual(ctx("a.example"));
    expect(actNarrowing(ctx("a.example", "b.example"), ctx("b.example", "c.example"))).toEqual(
      ctx("b.example"),
    );
    expect(actNarrowing(ctx("a.example"), ctx("c.example"))).toEqual({ scope: "none" });
    expect(actNarrowing(ctx("a.example"), { scope: "none" })).toEqual({ scope: "none" });
  });
});
