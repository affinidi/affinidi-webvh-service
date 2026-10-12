/**
 * ACL-entry role parsing from the wire. The counters-only `metricsreader`
 * role must round-trip: folding it into `owner` (as the generic invite
 * `role` parser does) would make the ACL edit form silently promote a
 * read-only credential to Owner on save.
 */

import { describe, expect, it } from "vitest";

import { aclEntryFromWire } from "../wire";

const base = {
  subject: "did:key:z6MkSidecar",
  label: null,
  createdAt: "2024-01-01T00:00:00Z",
  ext: {},
};

describe("aclEntryFromWire role mapping", () => {
  it("preserves metricsreader and never promotes it to owner", () => {
    const entry = aclEntryFromWire({ ...base, role: "metricsreader" } as never);
    expect(entry.role).toBe("metricsreader");
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
