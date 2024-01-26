use std::sync::Arc;

use axum::extract::FromRef;

use crate::{
    api::activity::HeartBeatMemoryStore, auth::secured_access::SecuredAccessTokenStorage,
    RegisterLimiter, TestaustimeState,
};

impl FromRef<TestaustimeState> for Arc<HeartBeatMemoryStore> {
    fn from_ref(input: &TestaustimeState) -> Self {
        Arc::clone(&input.heartbeat_store)
    }
}

impl FromRef<TestaustimeState> for Arc<SecuredAccessTokenStorage> {
    fn from_ref(input: &TestaustimeState) -> Self {
        Arc::clone(&input.secured_access_storage)
    }
}

impl FromRef<TestaustimeState> for Arc<RegisterLimiter> {
    fn from_ref(input: &TestaustimeState) -> Self {
        Arc::clone(&input.register_limiter)
    }
}
