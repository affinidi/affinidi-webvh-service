import { describe, expect, it } from "vitest";

import { furtherAliases, isDidWebs, planWebsEdit } from "../webs-edit";

const AID = "EN7G2PZkzjb3TTWBrG3-oE5-A71XwLeX4et38jeh0C-a";
const DID = `did:webs:webvh.example:sedi-vtc:${AID}`;
const IMPLIED = [DID, `did:web:webvh.example:sedi-vtc:${AID}`, `did:keri:${AID}`];
const doc = (aka: string[]) => ({ id: DID, alsoKnownAs: aka, service: [{ id: "#didcomm" }] });

describe("isDidWebs", () => {
  it("tells did:webs from did:webvh and did:web", () => {
    expect(isDidWebs(DID)).toBe(true);
    expect(isDidWebs("did:webvh:Qm:webvh.example:x")).toBe(false);
    expect(isDidWebs("did:web:webvh.example")).toBe(false);
    expect(isDidWebs(null)).toBe(false);
  });
});

describe("furtherAliases", () => {
  it("drops the aliases the agent adds itself", () => {
    expect(furtherAliases(DID, [...IMPLIED, "did:example:me"])).toEqual(["did:example:me"]);
  });
});

describe("planWebsEdit", () => {
  it("sends an alias change as the further aliases only", () => {
    const plan = planWebsEdit(DID, doc(IMPLIED), doc([...IMPLIED, "did:example:me"]));
    expect(plan).toEqual({ kind: "aliases", alsoKnownAs: ["did:example:me"] });
  });

  it("sends an empty list to withdraw every further alias", () => {
    const plan = planWebsEdit(DID, doc([...IMPLIED, "did:example:me"]), doc(IMPLIED));
    expect(plan).toEqual({ kind: "aliases", alsoKnownAs: [] });
  });

  it("ignores key order when deciding whether anything else changed", () => {
    const cur = { alsoKnownAs: IMPLIED, a: 1, b: { x: 1, y: 2 } };
    const next = { b: { y: 2, x: 1 }, a: 1, alsoKnownAs: [...IMPLIED, "did:example:me"] };
    expect(planWebsEdit(DID, cur, next).kind).toBe("aliases");
  });

  it("refuses an edit outside alsoKnownAs, since the document comes from the KEL", () => {
    const next = { ...doc(IMPLIED), service: [] };
    const plan = planWebsEdit(DID, doc(IMPLIED), next);
    expect(plan.kind).toBe("refused");
    if (plan.kind === "refused") expect(plan.reason).toMatch(/key event log/);
  });

  it("refuses an agent name, which the task cannot carry", () => {
    const plan = planWebsEdit(DID, doc(IMPLIED), doc([...IMPLIED, "https://webvh.example/@sedi"]));
    expect(plan.kind).toBe("refused");
    if (plan.kind === "refused") expect(plan.reason).toContain("https://webvh.example/@sedi");
  });

  it("refuses an edit that changes nothing", () => {
    expect(planWebsEdit(DID, doc(IMPLIED), doc([...IMPLIED].reverse())).kind).toBe("refused");
  });
});
