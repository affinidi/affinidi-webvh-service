### Fixed — the HTTPS listener classifies a passkey ceremony without a full parse

`POST /api/trust-tasks` decides whether a request opens an invite redemption
or a passkey login (to apply its per-address limit) before the per-type size
limit runs. It used to parse every body, up to the route's largest limit, as
a whole Trust Task document to decide. It now looks only at the body's length
first (a body over those ceremonies' 64 KiB limit cannot be one and is refused
later by the size limit, before any parse), and otherwise reads only the
top-level `type`. A body over 64 KiB that is refused before dispatch is
answered with an unrouted error document instead of one addressed to it. A
redemption or login body that names the ceremony's `type` but is otherwise
malformed now counts against the per-address limit.
