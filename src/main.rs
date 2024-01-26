#![feature(lazy_cell, addr_parse_ascii, async_closure)]

mod api;
mod auth;
mod database;
mod error;
mod models;
mod ratelimiter;
mod requests;
mod schema;
mod state;
mod utils;

#[cfg(test)]
mod tests;

use std::{net::SocketAddr, num::NonZeroU32, sync::Arc};

use api::activity::HeartBeatMemoryStore;
use auth::{secured_access::SecuredAccessTokenStorage, AuthMiddleware};
use axum::{
    routing::{delete, get, post},
    Router,
};
use chrono::NaiveDateTime;
use dashmap::DashMap;
use database::Database;
use governor::{Quota, RateLimiter};
use ratelimiter::TestaustimeRateLimiter;
use serde_derive::Deserialize;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

#[macro_use]
extern crate tracing;

#[macro_use]
extern crate axum;

#[macro_use]
extern crate diesel;

#[macro_use]
extern crate serde_json;

#[derive(Debug, Deserialize)]
pub struct TimeConfig {
    pub bypass_token: String,
    pub ratelimit_by_peer_ip: bool,
    pub max_requests_per_min: usize,
    pub address: String,
    pub database_url: String,
    pub allowed_origin: String,
}

pub struct RegisterLimiter {
    pub limit_by_peer_ip: bool,
    pub storage: DashMap<String, NaiveDateTime>,
}

#[derive(Clone)]
pub struct TestaustimeState {
    database: Arc<Database>,
    heartbeat_store: Arc<HeartBeatMemoryStore>,
    secured_access_storage: Arc<SecuredAccessTokenStorage>,
    register_limiter: Arc<RegisterLimiter>,
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    tracing_subscriber::fmt::init();

    let config: TimeConfig =
        toml::from_str(&std::fs::read_to_string("settings.toml").expect("Missing settings.toml"))
            .expect("Invalid Toml in settings.toml");

    let database = Arc::new(Database::new(config.database_url));

    let register_limiter = Arc::new(RegisterLimiter {
        limit_by_peer_ip: config.ratelimit_by_peer_ip,
        storage: DashMap::new(),
    });

    let ratelimiter = Arc::new(
        RateLimiter::keyed(Quota::per_minute(
            NonZeroU32::new(config.max_requests_per_min as u32).unwrap(),
        ))
        .with_middleware(),
    );

    let heartbeat_store = Arc::new(HeartBeatMemoryStore::new());

    let secured_access_storage = Arc::new(SecuredAccessTokenStorage::new());

    let state = TestaustimeState {
        secured_access_storage,
        heartbeat_store,
        database,
        register_limiter,
    };

    let auth = AuthMiddleware {
        state: state.clone(),
    };

    let router = Router::new()
        .route("/health", get(api::health))
        .route("/auth/register", post(api::auth::register))
        .nest("/", {
            let router = Router::new()
                .nest("/activity", {
                    Router::new()
                        .route("/update", post(api::activity::update))
                        .route("/delete", delete(api::activity::delete))
                        .route("/flush", post(api::activity::flush))
                        .route("/rename", post(api::activity::rename_project))
                })
                .route("/auth/login", post(api::auth::login))
                .route("/auth/regenerate", post(api::auth::regenerate))
                .route("/auth/changeusername", post(api::auth::changeusername))
                .route("/auth/changepassword", post(api::auth::changepassword))
                .route(
                    "/auth/securedaccess",
                    post(api::auth::get_secured_access_token),
                )
                .route("/account/settings", post(api::account::change_settings))
                .route("/friends/add", post(api::friends::add_friend))
                .route("/friends/list", get(api::friends::get_friends))
                .route(
                    "/friends/regenerate",
                    get(api::friends::regenerate_friend_code),
                )
                .route("/friends/remove", delete(api::friends::remove))
                .route("/users/@me", get(api::users::my_profile))
                .route("/users/@me/delete", delete(api::users::delete_user))
                .route("/users/@me/leaderboards", get(api::users::my_leaderboards))
                .route(
                    "/users/:username/activity/data",
                    get(api::users::get_activities),
                )
                .route(
                    "/users/:username/activity/current",
                    get(api::users::get_current_activity),
                )
                .route(
                    "/users/:username/activity/summary",
                    get(api::users::get_activity_summary),
                )
                .route(
                    "/leaderboards/create",
                    post(api::leaderboards::create_leaderboard),
                )
                .route(
                    "/leaderboards/:name",
                    get(api::leaderboards::get_leaderboard),
                )
                .route(
                    "/leaderboards/join",
                    post(api::leaderboards::join_leaderboard),
                )
                .route(
                    "/leaderboards/:name/leave",
                    post(api::leaderboards::leave_leaderboard),
                )
                .route(
                    "/leaderboards/:name",
                    delete(api::leaderboards::delete_leaderboard),
                )
                .route(
                    "/leaderboards/:name/promote",
                    post(api::leaderboards::promote_member),
                )
                .route(
                    "/leaderboards/:name/demote",
                    post(api::leaderboards::demote_member),
                )
                .route(
                    "/leaderboards/:name/kick",
                    post(api::leaderboards::kick_member),
                )
                .route(
                    "/leaderboards/:name/regenerate",
                    post(api::leaderboards::regenerate_invite),
                )
                .route("/search/users", get(api::search::search_public_users))
                .route("/stats", get(api::stats::stats));

            #[cfg(feature = "testausid")]
            let router = router.route("/auth/callback", get(api::oauth::callback));

            router
                .layer(
                    ServiceBuilder::new()
                        .layer(TestaustimeRateLimiter {
                            limiter: ratelimiter,
                            use_peer_addr: config.ratelimit_by_peer_ip,
                            bypass_token: config.bypass_token,
                        })
                        .layer(auth),
                )
                .layer(TraceLayer::new_for_http())
        })
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(config.address).await.unwrap();

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
