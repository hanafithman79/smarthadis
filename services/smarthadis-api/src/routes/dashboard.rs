use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde_json::{json, Value};

use crate::auth::middleware;
use crate::AppState;

pub async fn dashboard(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let claims = middleware::require_session(&jar, &state.jwt_secret)?;
    middleware::require_role(&claims, "role_teacher")?;

    let teacher_id: i64 = claims.sub.parse().map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid session"})),
        )
    })?;

    // claims.email holds whatever identifier the teacher logged in with
    // (could be their IC, not necessarily their name) — look up the real
    // name fresh rather than trust the JWT for display purposes.
    let nama: String = sqlx::query_scalar("SELECT nama FROM account WHERE id = $1")
        .bind(teacher_id)
        .fetch_one(&state.pool)
        .await
        .map_err(|e| {
            eprintln!("dashboard: nama lookup failed: {e}");
            internal_error()
        })?;

    let kod_gurus: Vec<String> = sqlx::query_scalar(
        "SELECT kelas.kod_guru FROM guru_class JOIN kelas ON kelas.id = guru_class.kelas_id WHERE guru_class.account_id = $1",
    )
    .bind(teacher_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|e| {
        eprintln!("dashboard: class lookup failed: {e}");
        internal_error()
    })?;

    let mut classes = Vec::with_capacity(kod_gurus.len());
    for kod_guru in kod_gurus {
        let result: Value = sqlx::query_scalar("SELECT sh_dashboard($1)")
            .bind(&kod_guru)
            .fetch_one(&state.pool)
            .await
            .map_err(|e| {
                eprintln!("dashboard: sh_dashboard failed for {kod_guru}: {e}");
                internal_error()
            })?;
        classes.push(result);
    }

    Ok(Json(json!({"nama": nama, "classes": classes})))
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

    /// Creates a real, active test teacher account via admin_create_account
    /// (same bootstrap pattern as routes/auth.rs and routes/admin.rs's
    /// tests) and returns its account id.
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
        let email = format!(
            "dashboard-test-{}@smarthadis-rust-test.invalid",
            suffix()
        );
        let row: (Value,) = sqlx::query_as("SELECT admin_create_account($1, $2, $3)")
            .bind(&email)
            .bind("Dashboard Test Teacher")
            .bind("teacher")
            .fetch_one(&mut *tx)
            .await
            .expect("admin_create_account should succeed");
        tx.commit().await.expect("commit should succeed");
        row.0["account_id"].as_i64().expect("account_id present")
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

    fn suffix() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .to_string()
    }

    async fn get_dashboard(cookie: Option<String>) -> axum::response::Response {
        let app = super::super::app(test_state());
        let mut builder = Request::builder().method("GET").uri("/dashboard");
        if let Some(c) = cookie {
            builder = builder.header("cookie", c);
        }
        app.oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn dashboard_fails_without_session() {
        let response = get_dashboard(None).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn dashboard_fails_for_non_teacher_role() {
        let secret = "test-secret-at-least-32-characters-long";
        let token = crate::auth::jwt::issue(secret, 1, "role_parent", "p@example.com", 3600);
        let response = get_dashboard(Some(format!("session={token}"))).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn dashboard_fails_for_admin_role() {
        // The spec lists role_admin -> 403 explicitly, distinct from
        // role_parent above — require_role rejects by exact string match,
        // so this pins that "admin" isn't accidentally treated as
        // "teacher-or-higher".
        let secret = "test-secret-at-least-32-characters-long";
        let token = crate::auth::jwt::issue(secret, 1, "role_admin", "a@example.com", 3600);
        let response = get_dashboard(Some(format!("session={token}"))).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn dashboard_fails_cleanly_for_malformed_sub_claim() {
        // jwt::issue always produces a numeric sub (it takes i64), so a
        // malformed one can only be constructed by hand — proves
        // claims.sub.parse::<i64>() is actually reached and handled with a
        // clean 401, not an unwrap panic, for a token that otherwise
        // verifies correctly (right secret, right role, not expired).
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        let secret = "test-secret-at-least-32-characters-long";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let token = encode(
            &Header::new(Algorithm::HS256),
            &serde_json::json!({
                "sub": "not-a-number",
                "role": "role_teacher",
                "email": "t@example.com",
                "iat": now,
                "exp": now + 3600,
            }),
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("encoding well-formed JSON cannot fail");

        let response = get_dashboard(Some(format!("session={token}"))).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn dashboard_includes_the_teacher_s_own_name() {
        let teacher_id = create_test_teacher().await;
        let secret = "test-secret-at-least-32-characters-long";
        let token = crate::auth::jwt::issue(
            secret,
            teacher_id,
            "role_teacher",
            "t@example.com",
            3600,
        );
        let response = get_dashboard(Some(format!("session={token}"))).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["nama"], "Dashboard Test Teacher");
        cleanup_teacher(teacher_id).await;
    }

    #[tokio::test]
    async fn dashboard_returns_empty_list_with_zero_assigned_classes() {
        let teacher_id = create_test_teacher().await;
        let secret = "test-secret-at-least-32-characters-long";
        let token = crate::auth::jwt::issue(
            secret,
            teacher_id,
            "role_teacher",
            "t@example.com",
            3600,
        );
        let response = get_dashboard(Some(format!("session={token}"))).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["classes"], json!([]));
        cleanup_teacher(teacher_id).await;
    }

    #[tokio::test]
    async fn dashboard_returns_one_entry_per_assigned_class() {
        let teacher_id = create_test_teacher().await;
        assign_class(teacher_id, 3).await;
        assign_class(teacher_id, 4).await;
        let secret = "test-secret-at-least-32-characters-long";
        let token = crate::auth::jwt::issue(
            secret,
            teacher_id,
            "role_teacher",
            "t@example.com",
            3600,
        );
        let response = get_dashboard(Some(format!("session={token}"))).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        let classes = parsed["classes"].as_array().expect("classes should be an array");
        assert_eq!(classes.len(), 2);
        for class in classes {
            assert_eq!(class["ok"], true);
            assert!(class["kelas"].is_object());
        }
        cleanup_teacher(teacher_id).await;
    }
}
