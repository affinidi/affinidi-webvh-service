//! The demo step-up gate. Passkey enrolment and login are Trust Tasks
//! (`crate::control_tasks::auth`), not REST.

pub use did_hosting_common::server::passkey::routes::step_up_check;
