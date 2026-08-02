/**
 * Tests for `hasLogMovedPast` — the rule that decides whether a pinned,
 * awaiting-approval edit has been overtaken by a new log version.
 *
 * The asymmetry is the whole point and is what these tests pin down. A `true`
 * retires the outstanding approval, so every case where the answer is not
 * genuinely knowable must come back `false`: retiring a live approval on a
 * failed read strands the user, while a missed movement is corrected by the
 * next poll a few seconds later.
 */

import { describe, expect, it } from "vitest";

import { hasLogMovedPast } from "../pinned-edit";

const V1 = "1-QmUCALqzc8av1KeiCqXRaRDr71gWFmMAQ4Ji44bQdm2cgD";
const V2 = "2-QmXAXxpo1XAm3bAYNW4n11PfHM23TeByMAyauN16yngbdG";

describe("hasLogMovedPast", () => {
  it("reports movement when the log advanced past the pinned version", () => {
    // The reported bug: an agent-name bind pinned at v1 was applied
    // server-side, taking the log to v2, while the tab still showed v1 and
    // its re-submit could only ever fail with `concurrent update`.
    expect(hasLogMovedPast(V1, [{ versionId: V1 }, { versionId: V2 }])).toBe(true);
  });

  it("reports no movement while the log still sits on the pinned version", () => {
    expect(hasLogMovedPast(V1, [{ versionId: V1 }])).toBe(false);
  });

  it("compares against the newest entry, not merely the pinned one's presence", () => {
    // The pinned version is still in the log — it always is, the chain is
    // append-only. Only the tail decides.
    expect(
      hasLogMovedPast(V1, [{ versionId: V1 }, { versionId: V2 }, { versionId: "3-Qmzzz" }]),
    ).toBe(true);
  });

  it("treats an empty log as nothing observed, never as movement", () => {
    // A read that came back empty is a failed or racing read; retiring a live
    // approval on it would strand an approval the user is still waiting on.
    expect(hasLogMovedPast(V1, [])).toBe(false);
    expect(hasLogMovedPast(null, [])).toBe(false);
  });

  it("treats a tail entry with no versionId as nothing observed", () => {
    expect(hasLogMovedPast(V1, [{ versionId: V1 }, {}])).toBe(false);
    expect(hasLogMovedPast(V1, [{ versionId: V1 }, { versionId: null }])).toBe(false);
  });

  it("reports movement when a DID that had no log has since published one", () => {
    // Pinned `null` means the approval was requested before anything was
    // published; a first version really is the change landing.
    expect(hasLogMovedPast(null, [{ versionId: V1 }])).toBe(true);
  });
});
