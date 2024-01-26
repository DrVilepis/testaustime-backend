use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use axum::{
    async_trait,
    extract::{ConnectInfo, FromRequestParts, State},
    response::IntoResponse,
    Json,
};
use http::{header::FORWARDED, request::Parts, HeaderMap, StatusCode};

use crate::{
    auth::{secured_access::SecuredAccessTokenStorage, Authentication},
    database::DatabaseWrapper,
    error::TimeError,
    models::{SecuredAccessTokenResponse, SelfUser, UserId, UserIdentity},
    requests::*,
    RegisterLimiter,
};

#[async_trait]
impl<S> FromRequestParts<S> for UserId {
    type Rejection = TimeError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let auth = parts.extensions.get::<Authentication>().cloned().unwrap();

        if let Authentication::AuthToken(user) = auth {
            Ok(UserId { id: user.id })
        } else {
            Err(TimeError::Unauthorized)
        }
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for UserIdentity {
    type Rejection = TimeError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth = parts.extensions.get::<Authentication>().cloned().unwrap();

        if let Authentication::AuthToken(user) = auth {
            Ok(user)
        } else {
            Err(TimeError::Unauthorized)
        }
    }
}

pub struct SecuredUserIdentity {
    pub identity: UserIdentity,
}

#[async_trait]
impl<S> FromRequestParts<S> for SecuredUserIdentity {
    type Rejection = TimeError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth = parts.extensions.get::<Authentication>().cloned().unwrap();

        if let Authentication::SecuredAuthToken(user) = auth {
            Ok(SecuredUserIdentity { identity: user })
        } else {
            Err(TimeError::UnauthroizedSecuredAccess)
        }
    }
}

pub struct UserIdentityOptional {
    pub identity: Option<UserIdentity>,
}

#[async_trait]
impl<S> FromRequestParts<S> for UserIdentityOptional
where
    S: Send + Sync,
{
    type Rejection = TimeError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let auth = parts.extensions.get::<Authentication>().cloned().unwrap();

        if let Authentication::AuthToken(user) = auth {
            Ok(UserIdentityOptional {
                identity: Some(user),
            })
        } else {
            Ok(UserIdentityOptional { identity: None })
        }
    }
}

pub async fn login(
    db: DatabaseWrapper,
    data: Json<RegisterRequest>,
) -> Result<impl IntoResponse, TimeError> {
    if data.password.len() > 128 {
        return Err(TimeError::InvalidLength(
            "Password cannot be longer than 128 characters".to_string(),
        ));
    }
    match db
        .verify_user_password(&data.username, &data.password)
        .await
    {
        Ok(Some(user)) => Ok(Json(SelfUser::from(user))),
        _ => Err(TimeError::InvalidCredentials),
    }
}

pub async fn get_secured_access_token(
    State(secured_access_storage): State<Arc<SecuredAccessTokenStorage>>,
    db: DatabaseWrapper,
    data: Json<RegisterRequest>,
) -> Result<impl IntoResponse, TimeError> {
    if data.password.len() > 128 {
        return Err(TimeError::InvalidLength(
            "Password cannot be longer than 128 characters".to_string(),
        ));
    }

    match db
        .verify_user_password(&data.username, &data.password)
        .await
    {
        Ok(Some(user)) => Ok(Json(SecuredAccessTokenResponse {
            token: secured_access_storage.create_token(user.id),
        })),
        _ => Err(TimeError::InvalidCredentials),
    }
}

pub async fn regenerate(
    user: SecuredUserIdentity,
    db: DatabaseWrapper,
) -> Result<impl IntoResponse, TimeError> {
    db.regenerate_token(user.identity.id)
        .await
        .inspect_err(|e| error!("{}", e))
        .map(|token| {
            let token = json!({ "token": token });
            Json(token)
        })
}

pub async fn register(
    State(rls): State<Arc<RegisterLimiter>>,
    ConnectInfo(conn_info): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    db: DatabaseWrapper,
    data: Json<RegisterRequest>,
) -> Result<impl IntoResponse, TimeError> {
    if data.password.len() < 8 || data.password.len() > 128 {
        return Err(TimeError::InvalidLength(
            "Password has to be between 8 and 128 characters long".to_string(),
        ));
    }
    if !super::VALID_NAME_REGEX.is_match(&data.username) {
        return Err(TimeError::BadUsername);
    }

    let username = data.username.clone();
    if db.get_user_by_name(username).await.is_ok() {
        return Err(TimeError::UserExists);
    }

    let ip = if rls.limit_by_peer_ip {
        conn_info.ip()
    } else {
        let header = headers
            .get("x-forwarded-for")
            .or_else(|| headers.get(FORWARDED));

        header
            .and_then(|ip| ip.to_str().ok().and_then(|ip| ip.parse::<IpAddr>().ok()))
            .unwrap_or(conn_info.ip())
    };

    if let Some(res) = rls.storage.get(&ip.to_string()) {
        if chrono::Local::now()
            .naive_local()
            .signed_duration_since(*res)
            < chrono::Duration::days(1)
        {
            return Err(TimeError::TooManyRegisters);
        }
    }

    let res = db
        .new_testaustime_user(&data.username, &data.password)
        .await?;

    rls.storage
        .insert(ip.to_string(), chrono::Local::now().naive_local());

    Ok(Json(res))
}

pub async fn changeusername(
    user: SecuredUserIdentity,
    db: DatabaseWrapper,
    data: Json<UsernameChangeRequest>,
) -> Result<impl IntoResponse, TimeError> {
    if data.new.len() < 2 || data.new.len() > 32 {
        return Err(TimeError::InvalidLength(
            "Username is not between 2 and 32 chars".to_string(),
        ));
    }
    if !super::VALID_NAME_REGEX.is_match(&data.new) {
        return Err(TimeError::BadUsername);
    }

    let username = data.new.clone();
    if db.get_user_by_name(username).await.is_ok() {
        return Err(TimeError::UserExists);
    }

    let user = db.get_user_by_id(user.identity.id).await?;
    db.change_username(user.id, data.new.clone()).await?;
    Ok(StatusCode::OK)
}

pub async fn changepassword(
    user: UserIdentity,
    db: DatabaseWrapper,
    data: Json<PasswordChangeRequest>,
) -> Result<impl IntoResponse, TimeError> {
    if data.new.len() < 8 || data.new.len() > 128 {
        return Err(TimeError::InvalidLength(
            "Password has to be between 8 and 128 characters long".to_string(),
        ));
    }
    let old = data.old.to_owned();
    let tuser = db.get_testaustime_user_by_id(user.id).await?;
    let k = db.verify_user_password(&user.username, &old).await?;
    if k.is_some() || tuser.password.iter().all(|n| *n == 0) {
        db.change_password(user.id, &data.new).await?;
        Ok(StatusCode::OK)
    } else {
        Err(TimeError::Unauthorized)
    }
}
