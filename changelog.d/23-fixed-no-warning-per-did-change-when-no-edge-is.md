### Fixed — no warning per DID change when no edge is registered

"DID sync: no active servers in registry" (and its delete counterpart) was
logged at warn on every DID change whenever no edge was active, which for a
daemon is always. With no edge registered it is now logged at debug. With
edges registered but none active, so the change reaches none of them, it is
a warning at most once every 5 minutes.
