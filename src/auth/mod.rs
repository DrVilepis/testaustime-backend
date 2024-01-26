pub mod secured_access;

use std::{
    mem,
    sync::Arc,
    task::{Context, Poll},
};

use axum::extract::Request;
use futures_util::future::BoxFuture;
use tower::{Layer, Service};

use crate::{database::DatabaseWrapper, models::UserIdentity, TestaustimeState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authentication {
    NoAuth,
    AuthToken(UserIdentity),
    SecuredAuthToken(UserIdentity),
}

#[derive(Clone)]
pub struct AuthMiddleware {
    pub state: TestaustimeState,
}

#[derive(Clone)]
pub struct AuthMiddlewareService<S> {
    inner: S,
    state: TestaustimeState,
}

impl<S> Layer<S> for AuthMiddleware {
    type Service = AuthMiddlewareService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthMiddlewareService {
            inner,
            state: self.state.clone(),
        }
    }
}

impl<S, B> Service<Request<B>> for AuthMiddlewareService<S>
where
    S: Service<Request<B>> + Clone + 'static,
    S::Future: Send + 'static,
    S: Send + 'static,
    B: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        let db = DatabaseWrapper::from(&self.state.database);
        let secured_access_storage = Arc::clone(&self.state.secured_access_storage);
        let auth = req.headers().get("Authorization").cloned();

        let clone = self.inner.clone();
        let mut inner = mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let auth = if let Some(auth) = auth {
                if let Some(token) = auth.to_str().unwrap().trim().strip_prefix("Bearer ") {
                    if let Ok(secured_access_instance) = secured_access_storage.get(token).clone() {
                        let user = db
                            .get_user_by_id(secured_access_instance.user_id)
                            .await
                            .unwrap();

                        Authentication::SecuredAuthToken(user)
                    } else if let Ok(user_identity) = db.get_user_by_token(token.to_string()).await
                    {
                        Authentication::AuthToken(user_identity)
                    } else {
                        Authentication::NoAuth
                    }
                } else {
                    Authentication::NoAuth
                }
            } else {
                Authentication::NoAuth
            };

            req.extensions_mut().insert(auth);

            let resp = inner.call(req).await?;

            Ok(resp)
        })
    }
}
