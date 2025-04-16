use axum::{response::IntoResponse, Json};
use http::StatusCode;
use serde_derive::Deserialize;

use crate::{api::auth::SecuredUserIdentity, database::DatabaseWrapper, error::TimeError};

#[derive(Deserialize)]
pub struct Settings {
    public_profile: Option<bool>,
}

pub async fn change_settings(
    userid: SecuredUserIdentity,
    db: DatabaseWrapper,
    settings: Json<Settings>,
) -> Result<impl IntoResponse, TimeError> {
    if let Some(public_profile) = settings.public_profile {
        db.change_visibility(userid.identity.id, public_profile)
            .await?;
    };

    Ok(StatusCode::OK)
}
