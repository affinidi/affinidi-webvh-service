import { describe, expect, it } from "vitest";

import type { AclEntry } from "../api";
import { errorMessage } from "../errors";
import { isLastAdmin } from "../last-admin";
import { TrustTaskRejection } from "../trust-task";

const e = (did: string, role: AclEntry["role"]): AclEntry => ({
  did,
  role,
  label: null,
  created_at: 0,
  max_total_size: null,
  max_did_count: null,
});

describe("isLastAdmin", () => {
  it("is true only for the one remaining admin", () => {
    const one = [e("did:example:a", "admin"), e("did:example:o", "owner")];
    expect(isLastAdmin(one, "did:example:a")).toBe(true);
    expect(isLastAdmin(one, "did:example:o")).toBe(false);

    const two = [...one, e("did:example:b", "admin")];
    expect(isLastAdmin(two, "did:example:a")).toBe(false);
    expect(isLastAdmin([], "did:example:a")).toBe(false);
  });
});

describe("the refusal, worded", () => {
  it("says what to do instead", () => {
    const message = "this revocation would leave the maintainer with no Admin entries";
    const refusal = new TrustTaskRejection(message, {
      code: "acl/revoke:lastAuthorityProtected",
      message,
      retryable: false,
    } as never);
    expect(errorMessage(refusal)).toMatch(/last administrator.*Add another administrator/);
  });
});
