### Changed — the console signs out in every tab, and takes the invite token out of the address bar

- Signing out (or a session ending on a `401`) in one tab now signs out every
  other tab of the console that holds the same session, through a
  `BroadcastChannel`. Before, another tab kept its in-memory token and session
  key until its next request was refused.
- The enrolment page reads the invite token once, then removes it from the
  address bar and the current history entry (`history.replaceState`), so it
  is not left on screen, in history or in a bookmark. The page also asks the
  browser to send no `Referer` (`<meta name="referrer">`), in addition to the
  `Referrer-Policy: no-referrer` the control plane and daemon already send.
- The comment on where the console keeps its tokens now says what protects
  them. IndexedDB is not a boundary against a script on the origin; the
  non-extractable session key is, together with the control plane requiring a
  proof on every task that acts.
- The UI's npm `overrides` use caret ranges at the locked majors (`minimatch
  ^11.0.4`, `postcss ^8.5.10`, `@xmldom/xmldom ^0.9.12`, `uuid ^11.1.1`, `ws
  ^8.20.1`, `shell-quote ^1.8.4`, `glob ^14.0.2`) instead of open-ended `>=`
  ranges, so a lockfile regeneration cannot jump a major. The lockfile is
  unchanged.

### Changed — enrolment invite links carry the token in the fragment

Invite links (`auth/passkey/enroll/invite` responses and the operator CLI)
are now `{base}/enroll#token=…` instead of `{base}/enroll?token=…`. A browser
never sends the fragment, so the token no longer reaches the web host's
request line, its access logs or a `Referer`. The claim code is still sent
separately, as before.

Behaviour change (R3.6): the link format changes. The enrolment page reads
the fragment first and still accepts `?token=`, so links issued before this
release keep working until they expire. A client that parses the invite
`url` itself should read the token from the fragment, or use the response's
`invite.token` member.
