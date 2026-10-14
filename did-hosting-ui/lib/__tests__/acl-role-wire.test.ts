/**
 * ACL-entry role parsing from the wire. The counters-only `metricsReader`
 * role must round-trip: folding it into `owner` (as the generic invite
 * `role` parser does) would make the ACL edit form silently promote a
 * read-only credential to Owner on save.
 */

import { describe, expect, it } from "vitest";

import { aclEntryFromWire, inviteFromWire } from "../wire";

const invite = {
  inviteId: "inv-1",
  subject: "did:key:z6MkInvitee",
  purpose: "session",
  createdAt: "2024-01-01T00:00:00Z",
  expiresAt: "2024-01-02T00:00:00Z",
  expired: false,
};

const base = {
  subject: "did:key:z6MkSidecar",
  label: null,
  createdAt: "2024-01-01T00:00:00Z",
  ext: {},
};

describe("aclEntryFromWire role mapping", () => {
  it("preserves metricsReader and never promotes it to owner", () => {
    const entry = aclEntryFromWire({ ...base, role: "metricsReader" } as never);
    expect(entry.role).toBe("metricsReader");
  });

  it("keeps admin and service", () => {
    expect(aclEntryFromWire({ ...base, role: "admin" } as never).role).toBe(
      "admin",
    );
    expect(aclEntryFromWire({ ...base, role: "service" } as never).role).toBe(
      "service",
    );
  });

  it("falls back to owner for an unknown role", () => {
    const entry = aclEntryFromWire({ ...base, role: "superuser" } as never);
    expect(entry.role).toBe("owner");
  });
});

describe("inviteFromWire role mapping", () => {
  it("preserves the three invite roles", () => {
    for (const r of ["admin", "owner", "service"] as const) {
      expect(inviteFromWire({ ...invite, role: r } as never).role).toBe(r);
    }
  });

  it("preserves metricsReader rather than folding it into another role", () => {
    // Invites can no longer be created as metricsReader (server-refused), but a
    // stale/forged row must be shown as itself — not silently promoted to owner
    // nor mislabelled — so an unchanged save is refused server-side, never a
    // silent rewrite. Mirrors `aclRole` for ACL entries.
    expect(
      inviteFromWire({ ...invite, role: "metricsReader" } as never).role,
    ).toBe("metricsReader");
  });

  it("never promotes a genuinely unknown role to owner — falls back to service", () => {
    expect(inviteFromWire({ ...invite, role: "superuser" } as never).role).toBe(
      "service",
    );
  });
});
