import { describe, expect, it } from "vitest";

import { parseScid, scidAliasesOf, scidHost } from "../did-scid";
import { extractDidHost } from "../domain";
import { compactDid } from "../did-table";
import { isHostNamedServiceContact } from "../oob-sign-in";

const SCID = "QmXa7Rk2ZpLwT9vNc4HbYe1Jd8sMfU3qGo6PtVnEyKiBhW";

describe("did:scid helpers", () => {
  it("parses the DID and its src locator", () => {
    expect(parseScid(`did:scid:vh:1:${SCID}?src=dids.example.org/farm-auth#key-1`)).toEqual({
      scid: SCID,
      src: "dids.example.org/farm-auth",
    });
    expect(parseScid(`did:scid:vh:1:${SCID}`)).toEqual({ scid: SCID, src: null });
    expect(parseScid(`did:webvh:${SCID}:dids.example.org`)).toBeNull();
    expect(parseScid(`did:scid:vh:1:${SCID}?src=a.example&x=1`)).toBeNull();
  });

  it("finds the host only in src", () => {
    expect(scidHost(`did:scid:vh:1:${SCID}?src=dids.example.org/farm-auth`)).toBe("dids.example.org");
    expect(scidHost(`did:scid:vh:1:${SCID}?src=localhost%3A8534/x`)).toBe("localhost:8534");
    expect(scidHost(`did:scid:vh:1:${SCID}`)).toBeNull();
    expect(extractDidHost(`did:scid:vh:1:${SCID}?src=https://dids.example.org`)).toBe("dids.example.org");
    // The webvh and web cases are unchanged.
    expect(extractDidHost(`did:webvh:${SCID}:dids.example.org:a`)).toBe("dids.example.org");
  });

  it("compacts a did:scid to its SCID head", () => {
    expect(compactDid(`did:scid:vh:1:${SCID}`)).toBe("did:scid:vh:1:QmXa7Rk2ZpLw…");
    expect(compactDid(`did:scid:vh:1:${SCID}?src=dids.example.org/farm-auth`)).toBe(
      "did:scid:vh:1:QmXa7Rk2ZpLw…?src=…farm-auth",
    );
  });

  it("lists a hosted log's own did:scid aliases only", () => {
    const webvh = `did:webvh:${SCID}:dids.example.org:farm-auth`;
    const own = `did:scid:vh:1:${SCID}?src=dids.example.org/farm-auth`;
    expect(
      scidAliasesOf(webvh, [own, "did:scid:vh:1:QmOther?src=x.example", "https://dids.example.org/@farm"]),
    ).toEqual([own]);
    expect(scidAliasesOf(webvh, undefined)).toEqual([]);
  });

  it("qualifies a did:scid contact only with src (VTI-LNK-119)", () => {
    expect(isHostNamedServiceContact(`did:scid:vh:1:${SCID}?src=dids.example.org`)).toBe(true);
    expect(isHostNamedServiceContact(`did:scid:vh:1:${SCID}`)).toBe(false);
  });
});
