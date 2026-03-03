// Re-export from webvh-common shared server infrastructure
pub mod jwt {
    pub use affinidi_webvh_common::server::auth::jwt::*;
}

pub mod session {
    pub use affinidi_webvh_common::server::auth::session::*;
}

pub mod extractor {
    pub use affinidi_webvh_common::server::auth::extractor::*;
}

pub use extractor::{AdminAuth, AuthClaims};
