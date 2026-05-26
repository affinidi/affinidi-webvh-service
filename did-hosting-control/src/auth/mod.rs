// Re-export from did-hosting-common shared server infrastructure
pub mod backend;
pub mod jwt {
    pub use did_hosting_common::server::auth::jwt::*;
}

pub mod session {
    pub use did_hosting_common::server::auth::session::*;
}

pub mod extractor {
    pub use did_hosting_common::server::auth::extractor::*;
}

pub use backend::DidHostingControlAuthBackend;
pub use extractor::{AdminAuth, AuthClaims, ServiceAuth, StepUpAuth};
