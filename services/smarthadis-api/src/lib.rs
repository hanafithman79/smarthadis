pub mod auth;
pub mod config;
pub mod db;
pub mod routes;

use sqlx::PgPool;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub jwt_secret: String,
    pub jwt_ttl_seconds: i64,
}
