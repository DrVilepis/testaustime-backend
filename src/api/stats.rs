use axum::response::IntoResponse;
use serde_derive::Serialize;

use crate::{database::DatabaseWrapper, error::TimeError};

#[derive(Serialize)]
struct Stats {
    pub user_count: u64,
    pub coding_time: u64,
}

pub async fn stats(db: DatabaseWrapper) -> Result<impl IntoResponse, TimeError> {
    let user_count = db.get_total_user_count().await?;
    let coding_time = db.get_total_coding_time().await?;

    Ok(axum::Json(Stats {
        user_count,
        coding_time,
    }))
}
