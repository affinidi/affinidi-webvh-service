import { describe, expect, it } from "vitest";

import { orphanHint, ownerMismatchWarning } from "../delegation-guard";

const VTA = "did:webvh:QmWoJD:webvh.example:my-vta";
const OTHER = "did:webvh:QmOther:webvh.example:someone-else";

describe("ownerMismatchWarning", () => {
  it("says nothing when the DID belongs to the signed-in identity", () => {
    expect(ownerMismatchWarning(VTA, VTA)).toBeNull();
  });

  it("names the owner when it differs", () => {
    const msg = ownerMismatchWarning(OTHER, VTA);
    expect(msg).toContain(OTHER);
    expect(msg).toMatch(/update key/);
  });

  it("says nothing when either side is unknown", () => {
    // A warning the operator cannot act on is worse than none: they cannot tell
    // whether it means "wrong agent" or "the page has not loaded yet".
    expect(ownerMismatchWarning(null, VTA)).toBeNull();
    expect(ownerMismatchWarning(VTA, null)).toBeNull();
    expect(ownerMismatchWarning(undefined, undefined)).toBeNull();
  });
});

describe("orphanHint", () => {
  // The exact string a VTA sends for this, via `UpdateDidWebvhError::NotFound`
  // → `AppError::NotFound` → `RejectReason::TaskFailed`.
  const VTA_NOT_FOUND =
    "task failed: not found: did not found: SCID did:webvh:Qmc33:webvh.example:attract-case not found";

  it("recognises the agent's not-found rejection and names the fix", () => {
    const hint = orphanHint("taskFailed", VTA_NOT_FOUND);
    expect(hint).toMatch(/no record of this DID/);
    expect(hint).toContain("dids reconcile");
  });

  it("works without a code — the bridge flattens the rejection to a message", () => {
    // By the time this reaches the page the extension has turned the typed
    // error into a plain string, so a code-only match would never fire.
    expect(orphanHint(undefined, VTA_NOT_FOUND)).not.toBeNull();
  });

  it("accepts the snake_case spelling of the code", () => {
    expect(orphanHint("task_failed", VTA_NOT_FOUND)).not.toBeNull();
  });

  it("leaves an unrelated failure alone", () => {
    // Advice that does not apply is worse than no advice: it sends the operator
    // to reconcile a DID that is present and failing for another reason.
    expect(orphanHint("taskFailed", "task failed: publish error: host returned 503")).toBeNull();
    expect(orphanHint("permissionDenied", "permission denied: not an admin")).toBeNull();
    expect(orphanHint(undefined, undefined)).toBeNull();
  });

  it("does not fire on a not-found from a code that means something else", () => {
    expect(orphanHint("proofInvalid", "proof invalid: verification method not found")).toBeNull();
  });
});
