### Fixed — Editing a did:webs DID from the UI no longer fails with "SCID … not found"

The DID detail page sent every delegated edit as `vta/webvh/dids/update`. A VTA keeps its did:webs DIDs in a separate store, so it answered `not found`, and the page then suggested the DID had been orphaned. Edits to a did:webs DID now go through `vta/webs/dids/update/0.1`. That task can change only the DID aliases in `alsoKnownAs`, so the page explains and stops any other document change, as well as agent-name bind, park and resume, before asking the agent.
