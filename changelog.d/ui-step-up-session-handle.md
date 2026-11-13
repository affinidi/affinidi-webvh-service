### Breaking — a wallet step-up in the console no longer hands the wallet the session's tokens

The console used to step a wallet session up by giving the wallet browser
extension the session's access token and refresh token
(`window.vtaWallet.stepUpVta`); the wallet then opened the step-up, sent its
decision and renewed the session itself. Now the console keeps both tokens:

1. The console opens the step-up itself: `auth/step-up/start/0.2`, signed by
   the session key bound at login. The control plane answers with its signed
   `auth/step-up/approve-request/0.5`, a single-use challenge bound to this
   session and its subject that lapses on its own (300 seconds).
2. The wallet is handed that approve-request and the service DID, nothing
   else (`window.vtaWallet.approveStepUpRequest({ rpDid, approveRequest })`).
   It verifies the request, asks the user, and returns its
   `auth/step-up/approve-response/0.7`, signed as the subject
   (`assertionMethod`); a session key may never sign an approval.
3. The console checks that the decision answers this challenge for this
   session, and sends it as signed.
4. The console renews the session with `auth/refresh/0.2`, signed by the
   session key with the refresh token it holds, so the new tokens carry
   `aal2`.

The control plane is unchanged: it already accepted a session-key-signed
`auth/step-up/start` for the session's own subject, and an approval only by
the subject's own key.

Behaviour change (R3.6): a wallet that offers only `stepUpVta` can no longer
step a console session up. The console says the action needs a stepped-up
session, and never falls back to handing the tokens over. A passkey session is
unaffected (it is `aal2` from login).

### Removed — the "Show flow visualization (demo)" option on the login page

The VTA-proxied sign-in under "Using an older wallet?" no longer offers a
flow visualization. The checkbox, its stored preference
(`didhosting:proxyLoginViz` in `localStorage`, no longer read), the modal
that showed the decoded sign-in token and the code that decoded it for
display are gone. The proxied sign-in itself is unchanged and goes straight to
the dashboard.
