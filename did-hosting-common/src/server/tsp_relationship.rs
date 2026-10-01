//! Inbound TSP relationship handling — the **answering arm** of the Rev 3
//! relationship lifecycle, shared by every node that runs a TSP listener
//! (`WebvhTspHandler` on the control plane, `ServerTspHandler` on the edge) so
//! both answer identically.
//!
//! ## Why this exists
//!
//! Under TSP Rev 3 **§7.2.2** a receiver drops any *application* message from a
//! VID it holds no relationship with. A relationship is admitted the moment the
//! receiver *records* an inbound relationship-forming invite, which the
//! messaging-service framework does before it calls
//! [`TspHandler::handle_control`]. What the framework does **not** do is answer
//! it: completing the handshake — sending the accept that moves the peer from
//! `InviteReceived` back to `Bidirectional` and restores *our own* ability to
//! send (`can_send()` is `Bidirectional`-only) — is the application's job. This
//! module is that completion.
//!
//! Without it, `affinidi-tsp` 0.2.1's recovery transition
//! (`Bidirectional + ReceiveInvite → InviteReceived`) is only half a mechanism:
//! a peer that lost its half re-invites, our side transitions to
//! `InviteReceived`, and — with no answer — `can_send()` goes **false**,
//! turning "the peer drops our frames" into "we can no longer send to the peer"
//! (see `docs/tsp-transport.md`). Answering is what makes the re-invite repair
//! the relationship instead of breaking it further.
//!
//! ## Why we accept from any framework-authenticated sender
//!
//! Forming a relationship grants **no authorization**; it only lets us decrypt
//! a peer's frames. Every trust task the peer then sends is still authorized at
//! the *task* layer (`trust_tasks::dispatch_*`, keyed on the framework-
//! authenticated sender VID), which refuses an unauthorized op with a named
//! `trust-task-error` the peer's application can read.
//!
//! Gating the *invite* on the ACL instead would be redundant *and* actively
//! harmful: §3.6 lets a peer send its invite and its first application message
//! together, so refusing the invite makes §7.2.2 silently drop that payload —
//! and the refusal (an `XRFD` control message) is never surfaced to the peer's
//! application. The gate would manufacture exactly the silence it was meant to
//! prevent. So authorization stays at the layer that can answer with a named
//! error; relationship acceptance does not.

use affinidi_messaging_didcomm_service::HandlerContext;
use affinidi_tsp::message::control::{ControlMessage, ControlType};
use tracing::{debug, info, warn};

/// What an inbound control message asks of us. Split out from the effectful
/// [`answer_inbound_control`] so the routing rule — *an invite is the only
/// control message we answer* — is a pure function the tests can pin without a
/// live mediator.
#[derive(Debug, PartialEq, Eq)]
enum ControlAction {
    /// A relationship-forming invite: send the accept that completes it.
    Accept,
    /// An accept or a cancel: the framework has already recorded the state
    /// transition and there is nothing for us to send in reply.
    RecordOnly,
}

fn classify(control_type: ControlType) -> ControlAction {
    match control_type {
        ControlType::RelationshipFormingInvite => ControlAction::Accept,
        // Accept: the peer completed an invite *we* sent — the framework
        // recorded the `Bidirectional` transition, so there is nothing to
        // answer.
        // Cancel: §7.3 asks for a cancel in return, but we hold no
        // outbound-cancel policy; a later re-invite (ours at connect, or the
        // peer's) re-establishes. Record-only for both.
        ControlType::RelationshipFormingAccept | ControlType::RelationshipCancel => {
            ControlAction::RecordOnly
        }
    }
}

/// Answer an inbound TSP control message: accept a relationship-forming invite
/// from any framework-authenticated sender, and no-op the rest. Call this from
/// a [`affinidi_messaging_didcomm_service::TspHandler::handle_control`] impl.
///
/// Never returns an error: a failed accept is logged and swallowed, because
/// `handle_control` has no reply channel (the framework already recorded the
/// relationship) and the peer's next re-invite, or our own connect-time
/// re-invite, is the retry.
pub async fn answer_inbound_control(
    ctx: &HandlerContext,
    control: &ControlMessage,
    sender_vid: &str,
    thread_digest: [u8; 32],
) {
    match classify(control.control_type) {
        ControlAction::Accept => match ctx
            .atm
            .tsp()
            .accept_relationship(&ctx.profile, sender_vid, thread_digest)
            .await
        {
            Ok(state) => info!(
                sender = %sender_vid,
                ?state,
                "accepted inbound TSP relationship invite"
            ),
            Err(e) => warn!(
                sender = %sender_vid,
                error = %e,
                "failed to accept inbound TSP relationship invite"
            ),
        },
        ControlAction::RecordOnly => debug!(
            sender = %sender_vid,
            control_type = ?control.control_type,
            "recorded inbound TSP control message (no reply needed)"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one invariant this arm must hold: an invite is answered, an accept
    /// or a cancel is not. Answering an accept would re-open a completed
    /// handshake; answering a cancel would fight a teardown.
    #[test]
    fn only_an_invite_is_answered() {
        assert_eq!(
            classify(ControlType::RelationshipFormingInvite),
            ControlAction::Accept
        );
        assert_eq!(
            classify(ControlType::RelationshipFormingAccept),
            ControlAction::RecordOnly
        );
        assert_eq!(
            classify(ControlType::RelationshipCancel),
            ControlAction::RecordOnly
        );
    }
}
