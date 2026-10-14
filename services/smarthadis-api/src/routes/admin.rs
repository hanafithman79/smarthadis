use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::auth::{jwt, middleware, session};
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct CreateAccountRequest {
    pub email: String,
    pub nama: String,
    pub role: String,
}

#[derive(Debug, Serialize)]
pub struct CreateAccountResponse {
    pub ok: bool,
    pub account_id: i64,
    pub temp_password: String,
}

pub async fn create_account(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<CreateAccountRequest>,
) -> Result<Json<CreateAccountResponse>, (StatusCode, Json<Value>)> {
    let claims = middleware::require_session(&jar, &state.jwt_secret)?;
    middleware::require_role(&claims, "role_admin")?;

    let claims_json = json!({"role": claims.role, "sub": claims.sub}).to_string();

    let mut tx = session::begin_with_role(&state.pool, "role_admin")
        .await
        .map_err(|e| {
            eprintln!("create_account: begin_with_role failed: {e}");
            internal_error()
        })?;
    session::set_jwt_claims(&mut tx, &claims_json)
        .await
        .map_err(|e| {
            eprintln!("create_account: set_jwt_claims failed: {e}");
            internal_error()
        })?;

    let row: (Value,) = sqlx::query_as("SELECT admin_create_account($1, $2, $3)")
        .bind(&body.email)
        .bind(&body.nama)
        .bind(&body.role)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_create_account_error)?;

    tx.commit().await.map_err(|e| {
        eprintln!("create_account: commit failed: {e}");
        internal_error()
    })?;

    let account_id = row.0["account_id"]
        .as_i64()
        .ok_or_else(internal_error)?;
    let temp_password = row.0["temp_password"]
        .as_str()
        .ok_or_else(internal_error)?
        .to_string();

    Ok(Json(CreateAccountResponse {
        ok: true,
        account_id,
        temp_password,
    }))
}

/// Maps admin_create_account's SQLSTATE codes to the right HTTP status,
/// instead of collapsing every failure (including a disabled admin's
/// caller check and a duplicate email) into a generic 500.
fn map_create_account_error(err: sqlx::Error) -> (StatusCode, Json<Value>) {
    if let Some(db_err) = err.as_database_error() {
        match db_err.code().as_deref() {
            // admin_create_account's own caller-aktif / role check
            // (migrations/004_review_fixes.sql) raises this explicitly.
            Some("42501") => {
                return (StatusCode::FORBIDDEN, Json(json!({"error": "forbidden"})))
            }
            // account_email_lower_key unique violation.
            Some("23505") => {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({"error": "an account with that email already exists"})),
                )
            }
            // plpgsql's default RAISE EXCEPTION code, used by
            // admin_create_account's `invalid role: %` check.
            Some("P0001") => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "invalid role"})),
                )
            }
            _ => {}
        }
    }
    eprintln!("create_account: admin_create_account query failed: {err}");
    internal_error()
}

fn internal_error() -> (StatusCode, Json<Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "account creation failed"})),
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
            "set TEST_SETUP_DATABASE_URL to the smarthadis40apps owner connection string, used only to clean up test fixtures",
        )
    }

    async fn cleanup_account_by_email(email: &str) {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        sqlx::query("DELETE FROM account WHERE email = $1")
            .bind(email)
            .execute(&pool)
            .await
            .expect("cleanup delete should succeed");
    }

    /// Looks up a real active admin account id rather than assuming id 1 is
    /// one — admin_create_account can only be bootstrapped by an existing
    /// active admin, so at least one must already exist, but which id that
    /// is shouldn't be hardcoded in tests.
    async fn active_admin_account_id() -> i64 {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        let (id,): (i64,) =
            sqlx::query_as("SELECT id FROM account WHERE role = 'admin' AND aktif = true LIMIT 1")
                .fetch_one(&pool)
                .await
                .expect("at least one active admin account must exist for these tests to run");
        id
    }

    /// Creates a real, active test admin account via admin_create_account,
    /// bootstrapped by the pre-existing active admin, and returns its id.
    /// Uses the rust_svc pool (not the owner) — only rust_svc is a member
    /// of role_admin, so only it can SET ROLE into it.
    async fn create_test_admin_account() -> (i64, String) {
        let pool = sqlx::PgPool::connect_lazy(&std::env::var("TEST_DATABASE_URL").expect(
            "set TEST_DATABASE_URL to the rust_svc connection string for this test",
        ))
        .expect("lazy pool construction cannot fail");
        let mut tx = session::begin_with_role(&pool, "role_admin")
            .await
            .expect("should begin with role_admin");
        session::set_jwt_claims(&mut tx, r#"{"role":"role_admin","sub":"1"}"#)
            .await
            .expect("should set claims");
        let email = format!(
            "disabled-admin-test-{}@smarthadis-rust-test.invalid",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let row: (Value,) = sqlx::query_as("SELECT admin_create_account($1, $2, $3)")
            .bind(&email)
            .bind("Disabled Admin Test")
            .bind("admin")
            .fetch_one(&mut *tx)
            .await
            .expect("admin_create_account should succeed");
        tx.commit().await.expect("commit should succeed");
        let account_id = row.0["account_id"].as_i64().expect("account_id present");
        (account_id, email)
    }

    async fn deactivate_account(account_id: i64) {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        sqlx::query("UPDATE account SET aktif = false WHERE id = $1")
            .bind(account_id)
            .execute(&pool)
            .await
            .expect("deactivate should succeed");
    }

    async fn cleanup_account_by_id(account_id: i64) {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        sqlx::query("DELETE FROM account WHERE id = $1")
            .bind(account_id)
            .execute(&pool)
            .await
            .expect("cleanup delete should succeed");
    }

    #[tokio::test]
    async fn create_account_fails_for_disabled_admin_caller() {
        // Proves the real caller claims (not fabricated ones) reach
        // admin_create_account's own aktif check, and that the resulting
        // 42501 maps to 403, not a generic 500.
        let (disabled_admin_id, _disabled_admin_email) = create_test_admin_account().await;
        deactivate_account(disabled_admin_id).await;

        let state = test_state();
        let cookie = admin_session_cookie(&state, disabled_admin_id);
        let target_email = format!(
            "should-not-be-created-{}@smarthadis-rust-test.invalid",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let app = super::super::app(state);

        let body = json!({
            "email": target_email,
            "nama": "Should Not Exist",
            "role": "teacher"
        })
        .to_string();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/accounts")
                    .header("content-type", "application/json")
                    .header("cookie", cookie)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM account WHERE email = $1")
            .bind(&target_email)
            .fetch_one(&pool)
            .await
            .expect("count query should succeed");
        assert_eq!(count, 0, "no account should have been created");

        cleanup_account_by_id(disabled_admin_id).await;
    }

    fn admin_session_cookie(state: &AppState, admin_id: i64) -> String {
        let token = jwt::issue(
            &state.jwt_secret,
            admin_id,
            "role_admin",
            "admin@example.com",
            3600,
        );
        format!("session={token}")
    }

    #[tokio::test]
    async fn create_account_fails_without_role_admin_session() {
        let state = test_state();
        let app = super::super::app(state);

        let body = json!({
            "email": "no-session-test@smarthadis-rust-test.invalid",
            "nama": "No Session",
            "role": "teacher"
        })
        .to_string();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/accounts")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn create_account_fails_with_non_admin_role() {
        let state = test_state();
        let token = jwt::issue(&state.jwt_secret, 1, "role_teacher", "t@example.com", 3600);
        let app = super::super::app(state);

        let body = json!({
            "email": "wrong-role-test@smarthadis-rust-test.invalid",
            "nama": "Wrong Role",
            "role": "teacher"
        })
        .to_string();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/accounts")
                    .header("content-type", "application/json")
                    .header("cookie", format!("session={token}"))
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn create_account_succeeds_with_role_admin_session() {
        let state = test_state();
        let admin_id = active_admin_account_id().await;
        let cookie = admin_session_cookie(&state, admin_id);
        let email = format!(
            "admin-route-test-{}@smarthadis-rust-test.invalid",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let app = super::super::app(state);

        let body = json!({
            "email": email,
            "nama": "Route Test Teacher",
            "role": "teacher"
        })
        .to_string();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/accounts")
                    .header("content-type", "application/json")
                    .header("cookie", cookie)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(parsed["ok"], true);
        assert!(parsed["account_id"].as_i64().is_some());
        assert!(parsed["temp_password"].as_str().is_some());

        cleanup_account_by_email(&email).await;
    }
}
