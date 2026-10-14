use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde_json::json;

use crate::AppState;

pub async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    match sqlx::query("SELECT 1").execute(&state.pool).await {
        Ok(_) => (StatusCode::OK, Json(json!({"status": "ok"}))),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "db_unavailable"})),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::super::app;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn healthz_returns_200_when_db_is_reachable() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to the rust_svc connection string for this test");
        let pool = crate::db::create_pool(&database_url)
            .await
            .expect("pool should connect");
        let state = crate::AppState {
            pool,
            jwt_secret: "test-secret-at-least-32-characters-long".to_string(),
            jwt_ttl_seconds: 43200,
        };
        let app = app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
