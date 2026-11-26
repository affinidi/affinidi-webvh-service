### Added — add a backup passkey from the console's Settings page

The "My Passkeys" card on Settings now has an **Add passkey** button, with an
optional label. It runs `auth/passkey/enroll/{start,finish}/0.2` for the
signed-in subject: if you already hold a sign-in passkey, the browser first
asks you to confirm with it, then creates the new one. Before, the control
plane supported this but the console never offered it, and an invite to a
subject that already has a passkey is refused, so an enrolled administrator
had no way in the console to add a second authenticator. An administrator still
cannot add a passkey for someone else; that remains an invite.
