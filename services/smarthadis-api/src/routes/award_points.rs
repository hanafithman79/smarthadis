use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::middleware;
use crate::AppState;

const MAX_AWARD: i32 = 500;

#[derive(Debug, Deserialize)]
pub struct AwardPointsRequest {
    pub murid_id: i64,
    pub amount: i32,
}

/// Lets a teacher award points (mata) to a student in one of their
/// assigned classes. Authorization and the write happen in a single
/// atomic UPDATE (via EXISTS against guru_class) rather than a separate
/// SELECT-then-UPDATE, so there's no TOCTOU window between checking
/// ownership and applying the change.
pub async fn award_points(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<AwardPointsRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let claims = middleware::require_session(&jar, &state.jwt_secret)?;
    middleware::require_role(&claims, "role_teacher")?;
    let teacher_id: i64 = claims.sub.parse().map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid session"})),
        )
    })?;

    if body.amount <= 0 || body.amount > MAX_AWARD {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("amount must be between 1 and {MAX_AWARD}")})),
        ));
    }

    let new_mata: Option<i32> = sqlx::query_scalar(
        "UPDATE murid m SET mata = mata + $1 \
         WHERE m.id = $2 \
           AND EXISTS (SELECT 1 FROM guru_class gc WHERE gc.kelas_id = m.kelas_id AND gc.account_id = $3) \
         RETURNING m.mata",
    )
    .bind(body.amount)
    .bind(body.murid_id)
    .bind(teacher_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| {
        eprintln!("award_points: update failed: {e}");
        internal_error()
    })?;

    match new_mata {
        Some(mata) => Ok(Json(json!({"ok": true, "mata": mata}))),
        None => Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "student is not in one of your assigned classes"})),
        )),
    }
}

fn internal_error() -> (StatusCode, Json<Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "server error"})),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_state() -> AppState {
        AppState {
            pool: sqlx::PgPool::connect_lazy(&std::env::var("TEST_DATABASE_URL").expect(
                "set TEST_DATABASE_URL to the rust_svc connection string for this test",
            ))
            .expect("lazy pool construction cannot fail"),
            jwt_secret: "test-secret-at-least-32-characters-long".to_string(),
            jwt_ttl_seconds: 43200,
        }
    }

    fn cleanup_database_url() -> String {
        std::env::var("TEST_SETUP_DATABASE_URL").expect(
            "set TEST_SETUP_DATABASE_URL to the smarthadis40apps owner connection string, used only to manage test fixtures",
        )
    }

    fn suffix() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .to_string()
    }

    async fn create_test_teacher() -> i64 {
        let pool = sqlx::PgPool::connect_lazy(&std::env::var("TEST_DATABASE_URL").expect(
            "set TEST_DATABASE_URL to the rust_svc connection string for this test",
        ))
        .expect("lazy pool construction cannot fail");
        let mut tx = crate::auth::session::begin_with_role(&pool, "role_admin")
            .await
            .expect("should begin with role_admin");
        crate::auth::session::set_jwt_claims(&mut tx, r#"{"role":"role_admin","sub":"1"}"#)
            .await
            .expect("should set claims");
        let email = format!("award-points-test-{}@smarthadis-rust-test.invalid", suffix());
        let row: (Value,) = sqlx::query_as("SELECT admin_create_account($1, $2, $3)")
            .bind(&email)
            .bind("Award Points Test Teacher")
            .bind("teacher")
            .fetch_one(&mut *tx)
            .await
            .expect("admin_create_account should succeed");
        tx.commit().await.expect("commit should succeed");
        row.0["account_id"].as_i64().expect("account_id present")
    }

    async fn create_test_murid(kelas_id: i64, starting_mata: i32) -> i64 {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        let s = suffix();
        let kod = format!("TEST-KOD-{s}");
        sqlx::query_scalar(
            "INSERT INTO murid (kelas_id, nama, kod, mata) VALUES ($1, 'Award Points Test Murid', $2, $3) RETURNING id",
        )
        .bind(kelas_id)
        .bind(&kod)
        .bind(starting_mata)
        .fetch_one(&pool)
        .await
        .expect("insert should succeed")
    }

    async fn assign_class(teacher_id: i64, kelas_id: i64) {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        sqlx::query("INSERT INTO guru_class (account_id, kelas_id) VALUES ($1, $2)")
            .bind(teacher_id)
            .bind(kelas_id)
            .execute(&pool)
            .await
            .expect("insert should succeed");
    }

    async fn cleanup_teacher(teacher_id: i64) {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        sqlx::query("DELETE FROM account WHERE id = $1")
            .bind(teacher_id)
            .execute(&pool)
            .await
            .expect("cleanup delete should succeed");
    }

    async fn cleanup_murid(murid_id: i64) {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        sqlx::query("DELETE FROM murid WHERE id = $1")
            .bind(murid_id)
            .execute(&pool)
            .await
            .expect("cleanup delete should succeed");
    }

    async fn current_mata(murid_id: i64) -> i32 {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        sqlx::query_scalar("SELECT mata FROM murid WHERE id = $1")
            .bind(murid_id)
            .fetch_one(&pool)
            .await
            .expect("select should succeed")
    }

    async fn post_award_points(cookie: Option<String>, body: Value) -> axum::response::Response {
        let app = super::super::app(test_state());
        let mut builder = Request::builder()
            .method("POST")
            .uri("/award-points")
            .header("content-type", "application/json");
        if let Some(c) = cookie {
            builder = builder.header("cookie", c);
        }
        app.oneshot(builder.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn fails_without_a_session() {
        let response = post_award_points(None, json!({"murid_id": 1, "amount": 10})).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn fails_for_non_teacher_role() {
        let secret = "test-secret-at-least-32-characters-long";
        let token = crate::auth::jwt::issue(secret, 1, "role_parent", "p@example.com", 3600);
        let response = post_award_points(
            Some(format!("session={token}")),
            json!({"murid_id": 1, "amount": 10}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn fails_when_student_is_not_in_the_teacher_s_classes() {
        let teacher_id = create_test_teacher().await;
        assign_class(teacher_id, 4).await;
        let murid_id = create_test_murid(3, 100).await;
        let secret = "test-secret-at-least-32-characters-long";
        let token = crate::auth::jwt::issue(secret, teacher_id, "role_teacher", "t@example.com", 3600);

        let response = post_award_points(
            Some(format!("session={token}")),
            json!({"murid_id": murid_id, "amount": 10}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(current_mata(murid_id).await, 100, "mata must be unchanged");

        cleanup_murid(murid_id).await;
        cleanup_teacher(teacher_id).await;
    }

    #[tokio::test]
    async fn fails_for_zero_or_negative_amount() {
        let teacher_id = create_test_teacher().await;
        assign_class(teacher_id, 3).await;
        let murid_id = create_test_murid(3, 100).await;
        let secret = "test-secret-at-least-32-characters-long";
        let token = crate::auth::jwt::issue(secret, teacher_id, "role_teacher", "t@example.com", 3600);

        let zero = post_award_points(
            Some(format!("session={token}")),
            json!({"murid_id": murid_id, "amount": 0}),
        )
        .await;
        assert_eq!(zero.status(), StatusCode::BAD_REQUEST);

        let negative = post_award_points(
            Some(format!("session={token}")),
            json!({"murid_id": murid_id, "amount": -5}),
        )
        .await;
        assert_eq!(negative.status(), StatusCode::BAD_REQUEST);
        assert_eq!(current_mata(murid_id).await, 100, "mata must be unchanged");

        cleanup_murid(murid_id).await;
        cleanup_teacher(teacher_id).await;
    }

    #[tokio::test]
    async fn fails_for_amount_over_the_max() {
        let teacher_id = create_test_teacher().await;
        assign_class(teacher_id, 3).await;
        let murid_id = create_test_murid(3, 100).await;
        let secret = "test-secret-at-least-32-characters-long";
        let token = crate::auth::jwt::issue(secret, teacher_id, "role_teacher", "t@example.com", 3600);

        let response = post_award_points(
            Some(format!("session={token}")),
            json!({"murid_id": murid_id, "amount": MAX_AWARD + 1}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(current_mata(murid_id).await, 100);

        cleanup_murid(murid_id).await;
        cleanup_teacher(teacher_id).await;
    }

    #[tokio::test]
    async fn adds_the_amount_to_the_student_s_existing_total() {
        let teacher_id = create_test_teacher().await;
        assign_class(teacher_id, 3).await;
        let murid_id = create_test_murid(3, 100).await;
        let secret = "test-secret-at-least-32-characters-long";
        let token = crate::auth::jwt::issue(secret, teacher_id, "role_teacher", "t@example.com", 3600);

        let response = post_award_points(
            Some(format!("session={token}")),
            json!({"murid_id": murid_id, "amount": 15}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["mata"], 115);
        assert_eq!(current_mata(murid_id).await, 115);

        cleanup_murid(murid_id).await;
        cleanup_teacher(teacher_id).await;
    }
}
