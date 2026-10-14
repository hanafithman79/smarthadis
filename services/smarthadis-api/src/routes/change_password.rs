use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::{middleware, password};
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub ic: Option<String>,
    pub old_password: String,
    pub new_password: String,
}

pub async fn change_password(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if exceeds_bcrypt_limit(&body.old_password)
        || exceeds_bcrypt_limit(&body.new_password)
        || body.new_password.is_empty()
    {
        return Err(invalid_credentials());
    }

    match &body.ic {
        Some(ic) => change_student_password(&state, ic, &body.old_password, &body.new_password).await,
        None => change_teacher_password(&state, &jar, &body.old_password, &body.new_password).await,
    }
}

async fn change_student_password(
    state: &AppState,
    ic: &str,
    old_password: &str,
    new_password: &str,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let normalized_ic: String = ic.chars().filter(char::is_ascii_digit).collect();

    #[derive(sqlx::FromRow)]
    struct Row {
        password_hash: Option<String>,
    }

    // Filtered by `ic`, never `id`: rust_svc has no SELECT grant on
    // murid.id (confirmed live — see this plan's Task 1 ledger entry), so
    // an UPDATE ... WHERE id = $n would fail with "permission denied for
    // table murid" even though password_hash/must_change_password are
    // correctly granted. `ic` is already an rust_svc-readable column.
    let murid = sqlx::query_as::<_, Row>("SELECT password_hash FROM murid WHERE ic = $1")
        .bind(&normalized_ic)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| {
            eprintln!("change_password: murid lookup failed: {e}");
            invalid_credentials()
        })?;

    let hash_to_check = murid
        .as_ref()
        .and_then(|m| m.password_hash.clone())
        .unwrap_or_else(|| password::DUMMY_HASH.to_string());

    let old_password_owned = old_password.to_string();
    let password_ok = tokio::task::spawn_blocking(move || {
        password::verify_password(&old_password_owned, &hash_to_check)
    })
    .await
    .unwrap_or(false);

    match murid {
        Some(m) if m.password_hash.is_some() && password_ok => {}
        _ => return Err(invalid_credentials()),
    }

    // bcrypt costs ~300ms of CPU — run it off the async runtime's worker
    // threads, same reason as every other hash_password/verify_password
    // call in this codebase (see routes/auth.rs).
    let new_password_owned = new_password.to_string();
    let new_hash = tokio::task::spawn_blocking(move || password::hash_password(&new_password_owned))
        .await
        .expect("hashing task should not panic")
        .map_err(|e| {
            eprintln!("change_password: hashing failed: {e}");
            invalid_credentials()
        })?;

    sqlx::query("UPDATE murid SET password_hash = $1, must_change_password = false WHERE ic = $2")
        .bind(&new_hash)
        .bind(&normalized_ic)
        .execute(&state.pool)
        .await
        .map_err(|e| {
            eprintln!("change_password: murid update failed: {e}");
            invalid_credentials()
        })?;

    Ok(Json(json!({"ok": true})))
}

async fn change_teacher_password(
    state: &AppState,
    jar: &CookieJar,
    old_password: &str,
    new_password: &str,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let claims = middleware::require_session(jar, &state.jwt_secret)?;
    let account_id: i64 = claims.sub.parse().map_err(|_| invalid_credentials())?;

    #[derive(sqlx::FromRow)]
    struct Row {
        password_hash: Option<String>,
    }

    let account = sqlx::query_as::<_, Row>("SELECT password_hash FROM account WHERE id = $1")
        .bind(account_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| {
            eprintln!("change_password: account lookup failed: {e}");
            invalid_credentials()
        })?;

    let hash_to_check = account
        .as_ref()
        .and_then(|a| a.password_hash.clone())
        .unwrap_or_else(|| password::DUMMY_HASH.to_string());

    let old_password_owned = old_password.to_string();
    let password_ok = tokio::task::spawn_blocking(move || {
        password::verify_password(&old_password_owned, &hash_to_check)
    })
    .await
    .unwrap_or(false);

    match account {
        Some(a) if a.password_hash.is_some() && password_ok => {}
        _ => return Err(invalid_credentials()),
    }

    let new_password_owned = new_password.to_string();
    let new_hash = tokio::task::spawn_blocking(move || password::hash_password(&new_password_owned))
        .await
        .expect("hashing task should not panic")
        .map_err(|e| {
            eprintln!("change_password: hashing failed: {e}");
            invalid_credentials()
        })?;

    sqlx::query("UPDATE account SET password_hash = $1, must_change_password = false WHERE id = $2")
        .bind(&new_hash)
        .bind(account_id)
        .execute(&state.pool)
        .await
        .map_err(|e| {
            eprintln!("change_password: account update failed: {e}");
            invalid_credentials()
        })?;

    Ok(Json(json!({"ok": true})))
}

fn invalid_credentials() -> (StatusCode, Json<Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "invalid credentials"})),
    )
}

fn exceeds_bcrypt_limit(password: &str) -> bool {
    password.as_bytes().len() > 72
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

    async fn create_test_murid_with_password(raw_password: &str) -> (i64, String) {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        let s = suffix();
        let ic = format!("9{s}");
        let kod = format!("TEST-KOD-{s}");
        let hash = password::hash_password(raw_password).expect("hash should succeed");
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO murid (kelas_id, nama, kod, ic, password_hash, must_change_password) VALUES (3, 'Test Murid', $1, $2, $3, true) RETURNING id",
        )
        .bind(&kod)
        .bind(&ic)
        .bind(&hash)
        .fetch_one(&pool)
        .await
        .expect("insert should succeed");
        (id, ic)
    }

    async fn cleanup_murid(id: i64) {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        sqlx::query("DELETE FROM murid WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .expect("cleanup delete should succeed");
    }

    async fn murid_password_state(id: i64) -> (String, bool) {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        sqlx::query_as("SELECT password_hash, must_change_password FROM murid WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("select should succeed")
    }

    async fn create_test_account_with_password(role: &str, raw_password: &str) -> i64 {
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
        let email = format!("change-pw-test-{}@smarthadis-rust-test.invalid", suffix());
        let row: (Value,) = sqlx::query_as("SELECT admin_create_account($1, $2, $3)")
            .bind(&email)
            .bind("Change PW Test")
            .bind(role)
            .fetch_one(&mut *tx)
            .await
            .expect("admin_create_account should succeed");
        tx.commit().await.expect("commit should succeed");
        let account_id = row.0["account_id"].as_i64().expect("account_id present");

        let pool2 = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        let hash = password::hash_password(raw_password).expect("hash should succeed");
        sqlx::query("UPDATE account SET password_hash = $1, must_change_password = true WHERE id = $2")
            .bind(&hash)
            .bind(account_id)
            .execute(&pool2)
            .await
            .expect("set password should succeed");
        account_id
    }

    async fn cleanup_account(account_id: i64) {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        sqlx::query("DELETE FROM account WHERE id = $1")
            .bind(account_id)
            .execute(&pool)
            .await
            .expect("cleanup delete should succeed");
    }

    async fn account_password_state(account_id: i64) -> (String, bool) {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        sqlx::query_as("SELECT password_hash, must_change_password FROM account WHERE id = $1")
            .bind(account_id)
            .fetch_one(&pool)
            .await
            .expect("select should succeed")
    }

    async fn post_change_password(cookie: Option<String>, body: Value) -> axum::response::Response {
        let app = super::super::app(test_state());
        let mut builder = Request::builder()
            .method("POST")
            .uri("/change-password")
            .header("content-type", "application/json");
        if let Some(c) = cookie {
            builder = builder.header("cookie", c);
        }
        app.oneshot(builder.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn student_wrong_old_password_is_rejected() {
        let (id, ic) = create_test_murid_with_password("correct-horse-battery").await;
        let response = post_change_password(
            None,
            json!({"ic": ic, "old_password": "wrong", "new_password": "new-pw-123"}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        cleanup_murid(id).await;
    }

    #[tokio::test]
    async fn student_unknown_ic_gets_identical_response_to_wrong_password() {
        let response_unknown = post_change_password(
            None,
            json!({"ic": "TOTALLY-UNKNOWN-IC-XYZ", "old_password": "whatever", "new_password": "new-pw-123"}),
        )
        .await;
        let status_unknown = response_unknown.status();
        let body_unknown = axum::body::to_bytes(response_unknown.into_body(), usize::MAX)
            .await
            .unwrap();

        let (id, ic) = create_test_murid_with_password("correct-horse-battery").await;
        let response_wrong = post_change_password(
            None,
            json!({"ic": ic, "old_password": "wrong", "new_password": "new-pw-123"}),
        )
        .await;
        let status_wrong = response_wrong.status();
        let body_wrong = axum::body::to_bytes(response_wrong.into_body(), usize::MAX)
            .await
            .unwrap();

        assert_eq!(status_unknown, status_wrong);
        assert_eq!(body_unknown, body_wrong);
        cleanup_murid(id).await;
    }

    #[tokio::test]
    async fn student_correct_old_password_updates_hash_and_clears_flag() {
        let (id, ic) = create_test_murid_with_password("correct-horse-battery").await;
        let response = post_change_password(
            None,
            json!({"ic": &ic, "old_password": "correct-horse-battery", "new_password": "new-correct-horse"}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let (new_hash, must_change) = murid_password_state(id).await;
        assert!(password::verify_password("new-correct-horse", &new_hash));
        assert!(!password::verify_password("correct-horse-battery", &new_hash));
        assert!(!must_change);
        cleanup_murid(id).await;
    }

    #[tokio::test]
    async fn teacher_requires_a_session() {
        let response = post_change_password(
            None,
            json!({"old_password": "whatever", "new_password": "new-pw-123"}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn teacher_wrong_old_password_is_rejected() {
        let account_id = create_test_account_with_password("teacher", "correct-horse-battery").await;
        let secret = "test-secret-at-least-32-characters-long";
        let token = crate::auth::jwt::issue(secret, account_id, "role_teacher", "t@example.com", 3600);
        let response = post_change_password(
            Some(format!("session={token}")),
            json!({"old_password": "wrong", "new_password": "new-pw-123"}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        cleanup_account(account_id).await;
    }

    #[tokio::test]
    async fn teacher_correct_old_password_updates_hash_and_clears_flag() {
        let account_id = create_test_account_with_password("teacher", "correct-horse-battery").await;
        let secret = "test-secret-at-least-32-characters-long";
        let token = crate::auth::jwt::issue(secret, account_id, "role_teacher", "t@example.com", 3600);
        let response = post_change_password(
            Some(format!("session={token}")),
            json!({"old_password": "correct-horse-battery", "new_password": "new-correct-horse"}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let (new_hash, must_change) = account_password_state(account_id).await;
        assert!(password::verify_password("new-correct-horse", &new_hash));
        assert!(!must_change);
        cleanup_account(account_id).await;
    }

    #[tokio::test]
    async fn ic_field_present_always_takes_the_student_path_even_with_a_valid_teacher_cookie() {
        // Disambiguation rule: "ic" present in the body always means the
        // student path, regardless of any session cookie also attached.
        // A request with both must be rejected as the (wrong) student
        // credentials, not silently treated as the teacher's own
        // change-password request.
        let account_id = create_test_account_with_password("teacher", "teacher-pw-123").await;
        let secret = "test-secret-at-least-32-characters-long";
        let token = crate::auth::jwt::issue(secret, account_id, "role_teacher", "t@example.com", 3600);

        let response = post_change_password(
            Some(format!("session={token}")),
            json!({"ic": "TOTALLY-UNKNOWN-IC-XYZ", "old_password": "teacher-pw-123", "new_password": "new-pw-123"}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // The teacher's own password must be untouched by this request.
        let (_hash, must_change) = account_password_state(account_id).await;
        assert!(must_change);
        cleanup_account(account_id).await;
    }
}
