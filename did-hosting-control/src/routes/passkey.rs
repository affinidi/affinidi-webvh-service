//! Passkey (WebAuthn) enrollment and login routes.
//!
//! These route handlers delegate to the generic implementations in
//! `did-hosting-common/src/server/passkey/routes.rs` via the `PasskeyState` trait.

pub use did_hosting_common::server::passkey::routes::create_invite;
pub use did_hosting_common::server::passkey::routes::enroll_finish;
pub use did_hosting_common::server::passkey::routes::enroll_start;
pub use did_hosting_common::server::passkey::routes::list_invites;
pub use did_hosting_common::server::passkey::routes::login_finish;
pub use did_hosting_common::server::passkey::routes::login_start;
pub use did_hosting_common::server::passkey::routes::revoke_invite;
pub use did_hosting_common::server::passkey::routes::update_invite;
