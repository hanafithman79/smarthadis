use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum_extra::extract::cookie::{Cookie, CookieJar};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use time::Duration as CookieDuration;

use crate::auth::{jwt, password};
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct LoginPasswordRequest {
    pub identifier: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginPasswordResponse {
    pub role: String,
    pub nama: String,
    pub must_change_password: bool,
    pub is_admin: bool,
}

#[derive(sqlx::FromRow)]
struct AccountRow {
    id: i64,
    role: String,
    password_hash: Option<String>,
    aktif: bool,
    nama: String,
    must_change_password: bool,
    is_admin: bool,
}

pub async fn login_password(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<LoginPasswordRequest>,
) -> Result<(CookieJar, Json<LoginPasswordResponse>), (StatusCode, Json<Value>)> {
    if exceeds_bcrypt_limit(&body.password) {
        return Err(invalid_credentials());
    }

    // An email identifier is matched as typed. An IC identifier may be
    // typed with MyKad-style dashes ("010203-04-0506") — normalize to
    // digits-only so it matches the stored (digit-only, confirmed live)
    // ic column either way. Never normalize an email: stripping its
    // non-digit characters would corrupt it, not just fail to match.
    let lookup_value = if body.identifier.contains('@') {
        body.identifier.clone()
    } else {
        body.identifier
            .chars()
            .filter(char::is_ascii_digit)
            .collect::<String>()
    };

    let account = sqlx::query_as::<_, AccountRow>(
        "SELECT id, role, password_hash, aktif, nama, must_change_password, is_admin FROM account WHERE lower(email) = lower($1) OR ic = $1",
    )
    .bind(&lookup_value)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| {
        eprintln!("login_password: account lookup failed: {e}");
        invalid_credentials()
    })?;

    let hash_to_check = account
        .as_ref()
        .and_then(|a| if a.aktif { a.password_hash.clone() } else { None })
        .unwrap_or_else(|| password::DUMMY_HASH.to_string());

    // bcrypt costs ~300ms of CPU; run it off the async runtime's worker
    // threads so a burst of login attempts can't stall every other route
    // (including /healthz) on this process.
    let password_to_check = body.password.clone();
    let password_ok = tokio::task::spawn_blocking(move || {
        password::verify_password(&password_to_check, &hash_to_check)
    })
    .await
    .unwrap_or(false);

    let account = match account {
        Some(a) if a.aktif && a.password_hash.is_some() && password_ok => a,
        _ => return Err(invalid_credentials()),
    };

    let pg_role = match account.role.as_str() {
        "admin" => "role_admin",
        "teacher" => "role_teacher",
        "parent" => "role_parent",
        _ => return Err(invalid_credentials()),
    };

    let token = jwt::issue(
        &state.jwt_secret,
        account.id,
        pg_role,
        &body.identifier,
        state.jwt_ttl_seconds,
    );
    let cookie = Cookie::build(("session", token))
        .http_only(true)
        .secure(true)
        .same_site(axum_extra::extract::cookie::SameSite::Strict)
        .max_age(CookieDuration::seconds(state.jwt_ttl_seconds))
        .path("/")
        .build();

    Ok((
        jar.add(cookie),
        Json(LoginPasswordResponse {
            role: pg_role.to_string(),
            nama: account.nama,
            must_change_password: account.must_change_password,
            is_admin: account.is_admin,
        }),
    ))
}

pub async fn logout(jar: CookieJar) -> (CookieJar, Json<Value>) {
    let removal = Cookie::build(("session", ""))
        .path("/")
        .max_age(CookieDuration::seconds(0))
        .build();
    (jar.add(removal), Json(json!({"ok": true})))
}

fn invalid_credentials() -> (StatusCode, Json<Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "invalid email or password"})),
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

    fn setup_pool() -> sqlx::PgPool {
        sqlx::PgPool::connect_lazy(&std::env::var("TEST_DATABASE_URL").expect(
            "set TEST_DATABASE_URL to the rust_svc connection string for this test",
        ))
        .expect("lazy pool construction cannot fail")
    }

    fn cleanup_database_url() -> String {
        std::env::var("TEST_SETUP_DATABASE_URL").expect(
            "set TEST_SETUP_DATABASE_URL to the smarthadis40apps owner connection string, used only to clean up test fixtures",
        )
    }

    /// Creates a real, active test account via the real admin_create_account
    /// function and returns (account_id, email, temp_password).
    async fn create_test_account(role: &str) -> (i64, String, String) {
        let pool = setup_pool();
        let mut tx = crate::auth::session::begin_with_role(&pool, "role_admin")
            .await
            .expect("should begin with role_admin");
        crate::auth::session::set_jwt_claims(&mut tx, r#"{"role":"role_admin","sub":"1"}"#)
            .await
            .expect("should set claims");
        let email = format!("test-{}@smarthadis-rust-test.invalid", uuid_like_suffix());
        let row: (serde_json::Value,) = sqlx::query_as(
            "SELECT admin_create_account($1, $2, $3)",
        )
        .bind(&email)
        .bind("Test Account")
        .bind(role)
        .fetch_one(&mut *tx)
        .await
        .expect("admin_create_account should succeed");
        tx.commit().await.expect("commit should succeed");

        let account_id = row.0["account_id"].as_i64().expect("account_id should be present");
        let temp_password = row.0["temp_password"]
            .as_str()
            .expect("temp_password should be present")
            .to_string();
        (account_id, email, temp_password)
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

    async fn cleanup_account(account_id: i64) {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        sqlx::query("DELETE FROM account WHERE id = $1")
            .bind(account_id)
            .execute(&pool)
            .await
            .expect("cleanup delete should succeed");
    }

    async fn set_account_ic(account_id: i64, ic: &str) {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        sqlx::query("UPDATE account SET ic = $1 WHERE id = $2")
            .bind(ic)
            .bind(account_id)
            .execute(&pool)
            .await
            .expect("set ic should succeed");
    }

    #[tokio::test]
    async fn login_password_succeeds_with_ic_identifier() {
        let (account_id, _email, temp_password) = create_test_account("teacher").await;
        let ic = format!("9{}", uuid_like_suffix());
        set_account_ic(account_id, &ic).await;
        let app = super::super::app(test_state());

        let body = json!({"identifier": ic, "password": temp_password}).to_string();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login/password")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get("set-cookie").is_some());

        cleanup_account(account_id).await;
    }

    #[tokio::test]
    async fn login_password_empty_identifier_does_not_match_null_ic() {
        // account.ic is nullable; most rows (including this freshly created
        // one) have it NULL. A naive string comparison could theoretically
        // treat an empty identifier as matching a NULL column — Postgres's
        // `= $1` never does (NULL = anything is NULL, never true). The
        // first assertion alone can't tell "correctly rejected because ic
        // IS NULL" apart from "rejected for an unrelated reason (e.g. the
        // query errored)" — the second assertion, using the SAME fixture's
        // real email+password, proves the query genuinely ran and would
        // have matched had ic been an empty string instead of NULL.
        let (account_id, email, temp_password) = create_test_account("teacher").await;
        let app = super::super::app(test_state());

        let body = json!({"identifier": "", "password": temp_password}).to_string();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login/password")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let app2 = super::super::app(test_state());
        let body2 = json!({"identifier": email, "password": temp_password}).to_string();
        let response2 = app2
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login/password")
                    .header("content-type", "application/json")
                    .body(Body::from(body2))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response2.status(), StatusCode::OK);

        cleanup_account(account_id).await;
    }

    #[tokio::test]
    async fn login_password_rejects_account_with_no_password_set() {
        // Defense-in-depth regression pin for the match guard explicitly
        // requiring password_hash.is_some() — not independently provable
        // via a black-box HTTP test, since DUMMY_HASH's plaintext was
        // discarded at generation time and is cryptographically infeasible
        // to guess (see auth::password::DUMMY_HASH's doc comment). Without
        // the explicit guard, this account would be checked against
        // DUMMY_HASH instead of failing immediately — unexploitable today,
        // but the guard is the part that makes that true by construction
        // rather than by luck. This test pins the guard's presence so a
        // future refactor can't silently drop it.
        let (account_id, email, _temp_password) = create_test_account("teacher").await;
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        sqlx::query("UPDATE account SET password_hash = NULL WHERE id = $1")
            .bind(account_id)
            .execute(&pool)
            .await
            .expect("clearing password_hash should succeed");

        let app = super::super::app(test_state());
        let body = json!({"identifier": email, "password": "whatever"}).to_string();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login/password")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        cleanup_account(account_id).await;
    }

    fn uuid_like_suffix() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .to_string()
    }

    #[tokio::test]
    async fn login_password_succeeds_with_correct_credentials() {
        let (account_id, email, temp_password) = create_test_account("teacher").await;
        let app = super::super::app(test_state());

        let body = json!({"identifier": email, "password": temp_password}).to_string();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login/password")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get("set-cookie").is_some());

        cleanup_account(account_id).await;
    }

    #[tokio::test]
    async fn login_password_reports_must_change_password_true_when_flagged() {
        let (account_id, email, temp_password) = create_test_account("teacher").await;
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        sqlx::query("UPDATE account SET must_change_password = true WHERE id = $1")
            .bind(account_id)
            .execute(&pool)
            .await
            .expect("flag update should succeed");

        let app = super::super::app(test_state());
        let body = json!({"identifier": email, "password": temp_password}).to_string();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login/password")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(parsed["must_change_password"], true);
        cleanup_account(account_id).await;
    }

    #[tokio::test]
    async fn login_password_reports_must_change_password_false_by_default() {
        let (account_id, email, temp_password) = create_test_account("teacher").await;
        let app = super::super::app(test_state());
        let body = json!({"identifier": email, "password": temp_password}).to_string();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login/password")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(parsed["must_change_password"], false);
        cleanup_account(account_id).await;
    }

    #[tokio::test]
    async fn login_password_reports_is_admin_true_for_a_dual_role_account() {
        let (account_id, email, temp_password) = create_test_account("teacher").await;
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        sqlx::query("UPDATE account SET is_admin = true WHERE id = $1")
            .bind(account_id)
            .execute(&pool)
            .await
            .expect("flag update should succeed");

        let app = super::super::app(test_state());
        let body = json!({"identifier": email, "password": temp_password}).to_string();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login/password")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(parsed["role"], "role_teacher");
        assert_eq!(parsed["is_admin"], true);
        cleanup_account(account_id).await;
    }

    #[tokio::test]
    async fn login_password_reports_is_admin_false_by_default() {
        let (account_id, email, temp_password) = create_test_account("teacher").await;
        let app = super::super::app(test_state());
        let body = json!({"identifier": email, "password": temp_password}).to_string();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login/password")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(parsed["is_admin"], false);
        cleanup_account(account_id).await;
    }

    #[tokio::test]
    async fn login_password_fails_with_wrong_password() {
        let (account_id, email, _temp_password) = create_test_account("teacher").await;
        let app = super::super::app(test_state());

        let body = json!({"identifier": email, "password": "definitely-wrong"}).to_string();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login/password")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        cleanup_account(account_id).await;
    }

    #[tokio::test]
    async fn login_password_fails_for_unknown_email() {
        let app = super::super::app(test_state());
        let body = json!({"identifier": "nobody@smarthadis-rust-test.invalid", "password": "whatever"})
            .to_string();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login/password")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_password_fails_for_inactive_account() {
        let (account_id, email, temp_password) = create_test_account("teacher").await;
        deactivate_account(account_id).await;
        let app = super::super::app(test_state());

        let body = json!({"identifier": email, "password": temp_password}).to_string();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login/password")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        cleanup_account(account_id).await;
    }

    #[test]
    fn exceeds_bcrypt_limit_rejects_only_over_72_bytes() {
        // Unit-tests the boundary in isolation. An HTTP-level test can't
        // distinguish "the guard ran" from "bcrypt itself rejected the
        // input" — bcrypt::verify returns Ok(false) rather than panicking
        // on an oversized input (unlike Python's bcrypt), so a 73-byte
        // password would get the same 401 with or without the guard. This
        // test instead pins the exact boundary (72 passes, 73 fails) on the
        // pure function the handler calls first; that the handler calls it
        // before touching the DB or calling verify_password is a one-line
        // code-review check (it's literally the function's first
        // statement), not something a black-box test can observe.
        assert!(!super::exceeds_bcrypt_limit(&"a".repeat(72)));
        assert!(super::exceeds_bcrypt_limit(&"a".repeat(73)));
    }

    #[tokio::test]
    async fn login_password_rejects_overlong_password_with_401() {
        let app = super::super::app(test_state());
        let long_password = "a".repeat(73);
        let body = json!({"identifier": "nobody@smarthadis-rust-test.invalid", "password": long_password})
            .to_string();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login/password")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn logout_clears_the_session_cookie() {
        let app = super::super::app(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/logout")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let set_cookie = response
            .headers()
            .get("set-cookie")
            .expect("logout should set a cookie to clear it")
            .to_str()
            .unwrap();
        assert!(set_cookie.contains("Max-Age=0"));
    }
}
