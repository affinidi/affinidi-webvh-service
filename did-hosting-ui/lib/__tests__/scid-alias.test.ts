import { describe, expect, it } from "vitest";

import {
  SYSTEM_OWNER,
  scidAliasConfirm,
  scidAliasFromExt,
  scidAliasView,
  type ScidAliasState,
} from "../scid-alias";
import { didRecordFromWire } from "../wire";

const URL = "did:scid:vh:1:QmXa7Rk2?src=dids.example.org/alice";
const at = (status: ScidAliasState["status"]): ScidAliasState => ({ didUrl: URL, status });
const VTA = "did:webvh:QmVta:vta.example";

describe("did:scid alias state", () => {
  it("reads the control plane's report off the host extension", () => {
    expect(scidAliasFromExt({ scidAlias: { didUrl: URL, status: "stale" } })).toEqual(at("stale"));
    expect(scidAliasFromExt({})).toBeNull();
    expect(scidAliasFromExt({ scidAlias: { didUrl: URL, status: "maybe" } })).toBeNull();
    expect(scidAliasFromExt({ scidAlias: { didUrl: "did:web:x", status: "listed" } })).toBeNull();
  });

  it("carries it onto the record from did/info", () => {
    const rec = didRecordFromWire({
      mnemonic: "alice",
      owner: VTA,
      createdAt: "1970-01-01T00:00:01Z",
      updatedAt: "1970-01-01T00:00:01Z",
      versionCount: 1,
      ext: { "vnd.affinidi.webvh": { scidAlias: { didUrl: URL, status: "listed" } } },
    } as never);
    expect(rec.scidAlias).toEqual(at("listed"));
  });

  it("offers the change that fits each state when the agent can be asked", () => {
    const view = (status: ScidAliasState["status"]) =>
      scidAliasView({ alias: at(status), owner: VTA, canDelegate: true, preRotation: false });
    expect(view("listed").actions).toEqual([{ label: "Remove alias", scidAlsoKnownAs: false }]);
    expect(view("notListed").actions).toEqual([{ label: "List alias", scidAlsoKnownAs: true }]);
    expect(view("stale").actions).toEqual([
      { label: "List for current location", scidAlsoKnownAs: true },
      { label: "Remove alias", scidAlsoKnownAs: false },
    ]);
    expect(view("stale").summary).toMatch(/old location/);
    expect(view("listed").readOnlyReason).toBeNull();
  });

  it("warns that the entry rotates the update key, naming pre-rotation", () => {
    const plain = scidAliasView({ alias: at("notListed"), owner: VTA, canDelegate: true, preRotation: false });
    expect(plain.warning).toMatch(/rotates the DID's update key/);
    expect(plain.warning).not.toMatch(/pre-rotation/);
    const pre = scidAliasView({ alias: at("notListed"), owner: VTA, canDelegate: true, preRotation: true });
    expect(pre.warning).toMatch(/next pre-committed key \(this log uses pre-rotation\)/);
  });

  it("is read-only without the wallet relay, pointing at the controller", () => {
    const v = scidAliasView({ alias: at("listed"), owner: VTA, canDelegate: false, preRotation: true });
    expect(v.actions).toEqual([]);
    expect(v.warning).toBeNull();
    expect(v.readOnlyReason).toMatch(/pnm or the browser-plugin console/);
    expect(v.readOnlyReason).toMatch(/vta\/webvh\/dids\/update\/1\.1/);
  });

  it("points a service DID at the offline CLI", () => {
    const v = scidAliasView({ alias: at("notListed"), owner: SYSTEM_OWNER, canDelegate: true, preRotation: false });
    expect(v.actions).toEqual([]);
    expect(v.readOnlyReason).toMatch(/identity-scid-alias/);
  });

  it("says what each action does to the subject", () => {
    expect(scidAliasConfirm(at("notListed"), { label: "List alias", scidAlsoKnownAs: true })).toContain(URL);
    expect(scidAliasConfirm(at("listed"), { label: "Remove alias", scidAlsoKnownAs: false })).toMatch(
      /separate identities/,
    );
  });
});
