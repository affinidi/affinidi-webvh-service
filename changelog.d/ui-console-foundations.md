### Fixed — the console checks session renewal and proxied wallet sign-in replies, and reads JWT claims as base64url

Renewing a session (`auth/refresh`) and the VTA-proxied wallet sign-in
(`auth/authenticate/0.3`) were sent with a raw `fetch` and their replies used
unchecked; both now go through the console's Trust Task client, so a reply must
be the control plane's signed answer to that request before its tokens are
kept. The access token's claims are decoded in one place, as base64url with
padding restored, so a claim whose encoding contains `-` or `_` no longer hides
the admin navigation or stops renewal.

### Fixed — copying in the console says when it failed

Every copy button (invite link and claim code, DIDs, agent names) now reports
"Copy failed — select and copy manually" when the browser refuses the
clipboard — on a plain-HTTP deployment, or with the permission denied — and
shows the value as selectable text, instead of failing silently.

### Changed — the console is keyboard- and screen-reader-usable, and meets WCAG AA contrast

Buttons, pickers, inputs and dialogs are shared primitives with roles, names,
state (`checked`, `expanded`, `busy`, `disabled`), a visible focus ring, and
Enter/Space activation; inputs are labelled, page and card titles are
headings, forms submit on Enter, and status is spelled out rather than shown by
colour alone. Tertiary text and filled buttons now meet the 4.5:1 contrast
ratio.

### Changed — the console caches and shares its reads

Screens read through one small cache that deduplicates requests, shows held
data while it refreshes, polls only while the page is visible, ignores a late
answer for a view the operator has moved off (a quick usage-chart range switch
no longer shows the previous range), and refreshes what a change touched.
Editing an ACL entry sends only what changed. The settings page no longer
re-renders every second for every viewer.
