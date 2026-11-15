### Changed — the console confirms destructive actions in its own dialog, and removing an owner says what happens to their DIDs

Every destructive action in the management console — deleting a DID, rolling
back its last entry, purging or deleting a domain, purging a domain on one
server, retiring an identity generation, revoking a passkey or an invite —
now asks in an in-app dialog with a title, an explicitly labelled action and
focus on Cancel, instead of the browser's `confirm()` (which a browser can
silently suppress). Deleting a DID and purging or deleting a domain also need
the name typed first.

Removing an access entry is one dialog with three choices: remove access only,
remove access and delete the DIDs the account owns (listed, and confirmed by
typing), or cancel. Deleting shows each DID's progress; if any fails, the
access entry is kept and the failures are listed with a retry. Success and
failure notices appear as in-app messages rather than `alert()`.

### Changed — the console keeps your place and your work when you sign in or your session ends

One route guard now covers every page: a reload shows a splash while the
saved session is restored (no more flash of "Please log in"), a signed-out
visitor is sent to the sign-in page and brought back to the page they asked
for (`/login?next=…`, honoured only for a path on the console's own origin),
and a session that expires mid-task shows a "Session expired — sign in again"
banner over the page, with sign-in in a dialog, so whatever was typed on the
page is still there afterwards.

### Fixed — failed loads in the console no longer look like empty data

The DID list, dashboard, access control, invites, settings, servers and
domains pages show a failed read as an error with a Retry button instead of
"no DIDs", "no invites" or nothing at all. A DID path that does not exist (or
is not yours) shows "DID not found" with no delete or rollback buttons. Panels
that refresh on a timer say when they were last updated and that refreshing is
failing. Rejection codes (`permissionDenied`, `notFound`, `unavailable`,
`stepUpRequired`, …), cancelled passkey prompts and unverifiable replies are
described in plain words, in one place.

### Changed — console forms validate inline and the console explains itself

- Creating a DID checks the path against the control plane's own rules as you
  type and keeps Create disabled while the path is invalid, taken or still
  being checked; success says what to do next. "Create root DID" reserves the
  root of the selected domain and explains what it is.
- The access form checks the DID or agent name and the quota numbers inline,
  and each role has a one-line description. Creating a domain checks the host
  name the way the control plane will.
- A small "?" explains protocol terms (witness, watcher, portable,
  pre-rotation, TTL, alsoKnownAs, step-up passkeys, domain scope).
- Copy says "control plane" rather than "the daemon", names
  `did-hosting-server` correctly, and uses one verb, "Sign in", throughout.
  The older wallet sign-ins are described in plain language with a
  "What is this?" disclosure.
- When a session needs a step-up the browser cannot provide, the message says
  exactly what to do.

### Added — suspend and resume a DID, set its statistics detail, and edit a domain's label from the console

The DID page gains Suspend / Resume (`did/set-state`) and a statistics-detail
picker (`stats/set-resolution`); the domains page can add or change a domain's
label (`domain/update`).

### Changed — the DID page offers document editing only when it can be published, and shows parameters read-only

Without a wallet that can relay to the DID's agent, the document editor is not
offered (it could not sign anything) and the page says how updates are made
instead; the "Copy to Upload" button, which discarded the edit, is gone. The
parameters card is read-only, with a "Copy parameters JSON" action.

### Changed — the Access page and the dashboard fit an owner's account

The Access nav item and page are administrator-only, as the control plane
already enforced. An owner's dashboard shows their DIDs per domain.

### Removed — the console's native (iOS / Android) targets

The management console is web-only: the `android` / `ios` scripts, the native
blocks in `app.json` and the unused `App.tsx` are gone, and the app declares
its dark appearance. Under 700px wide the navigation folds into a menu and the
DID list shows cards instead of a sideways-scrolling table.
