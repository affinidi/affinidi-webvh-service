### Fixed — an operator's CLI invite enrolls the first administrator again

Since invites began to be honored only while their issuer is still an
administrator, an invite made with the operator's `invite` subcommand was
refused at the last step of enrollment with "the administrator who issued this
invite no longer holds that standing": its recorded issuer is the operator, not
an ACL entry, so the lookup never found one. A fresh deployment could not enroll
its first administrator's passkey. A CLI invite rests on store access, so its
redemption no longer looks the issuer up in the ACL. Invites issued by an
administrator are checked as before. A refused invite is spent; issue a new one
after upgrading.
