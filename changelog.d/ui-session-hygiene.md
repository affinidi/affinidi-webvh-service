### Changed — the console signs out in every tab, and takes the invite token out of the address bar

- Signing out (or a session ending on a `401`) in one tab now signs out every
  other tab of the console that holds the same session, through a
  `BroadcastChannel`. Before, another tab kept its in-memory token and session
  key until its next request was refused.
- The enrolment page reads the invite token from `/enroll?token=…` once and
  then removes it from the address bar and the current history entry
  (`history.replaceState`), so it is not left on screen, in history or in a
  bookmark.
- The comment on where the console keeps its tokens now says what protects
  them. IndexedDB is not a boundary against a script on the origin; the
  non-extractable session key is, together with the control plane requiring a
  proof on every task that acts.
- The UI's npm `overrides` use caret ranges at the locked majors (`minimatch
  ^11.0.4`, `postcss ^8.5.10`, `@xmldom/xmldom ^0.9.12`, `uuid ^11.1.1`, `ws
  ^8.20.1`, `shell-quote ^1.8.4`, `glob ^14.0.2`) instead of open-ended `>=`
  ranges, so a lockfile regeneration cannot jump a major. The lockfile is
  unchanged.
