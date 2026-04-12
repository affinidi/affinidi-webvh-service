//! Passkey (WebAuthn) enrollment and login routes.
//!
//! These route handlers delegate to the generic implementations in
//! `webvh-common/src/server/passkey/routes.rs` via the `PasskeyState` trait.

pub use affinidi_webvh_common::server::passkey::routes::create_invite;
pub use affinidi_webvh_common::server::passkey::routes::enroll_finish;
pub use affinidi_webvh_common::server::passkey::routes::enroll_start;
pub use affinidi_webvh_common::server::passkey::routes::login_finish;
pub use affinidi_webvh_common::server::passkey::routes::login_start;
