### Changed — the console pages and searches the DID list on the server

The DID list no longer reads every DID before it shows any. It asks
`did/list` for 50 at a time, filtered to the pinned domain and to the search
box by the control plane (name, DID or agent name), with **Load more** for
the next page; sorting applies to the DIDs loaded. The dashboard's
pinned-domain cards read that domain's totals with one `stats/get` instead of
listing every DID (the update count is now the real number of updates), and
granting access by agent name looks the one name up instead of listing every
DID. A DID's page reads its log once per load rather than twice, and the
usage chart (with its charting library, most of the console's script) loads
only on the pages that show it.
