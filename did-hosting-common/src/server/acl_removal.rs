//! What goes when a subject's ACL entry is removed.
//!
//! An ACL entry is what every session of its subject, and every enrolment
//! invite issued for or by it, rests on. Removing the entry, by `acl/revoke`
//! or by the operator's `acl remove`, ends the subject's sessions and
//! withdraws those invites, so neither a live session nor a later redemption
//! carries on as the member it no longer is.

use crate::server::auth::session::{self, SessionFate, SettledSessions};
use crate::server::error::AppError;
use crate::server::store::KeyspaceHandle;

/// End every session of `subject` and withdraw the enrolment invites issued
/// for it or by it, from the sessions keyspace `sessions`. Returns the
/// sessions ended and how many invites were withdrawn.
pub async fn withdraw_removed_member(
    sessions: &KeyspaceHandle,
    subject: &str,
) -> Result<(SettledSessions, usize), AppError> {
    let settled = session::settle_subject_sessions(sessions, subject, |_| SessionFate::End).await?;
    let withdrawn = withdraw_invites_for(sessions, subject).await?;
    Ok((settled, withdrawn))
}

/// Withdraw every enrolment invite issued for `subject`, or by it. Returns
/// how many were withdrawn.
#[cfg(feature = "passkey")]
pub async fn withdraw_invites_for(
    sessions: &KeyspaceHandle,
    subject: &str,
) -> Result<usize, AppError> {
    use crate::server::passkey::invite;
    let same = |did: &str| crate::scid::same_reference(did, subject);
    let mut withdrawn = 0;
    for pending in invite::list(sessions).await? {
        if (same(&pending.subject) || same(&pending.issued_by))
            && invite::revoke(sessions, &pending.invite_id, "acl/revoke").await?
        {
            withdrawn += 1;
        }
    }
    Ok(withdrawn)
}

/// Without the `passkey` feature there are no invites to withdraw.
#[cfg(not(feature = "passkey"))]
pub async fn withdraw_invites_for(
    _sessions: &KeyspaceHandle,
    _subject: &str,
) -> Result<usize, AppError> {
    Ok(0)
}
