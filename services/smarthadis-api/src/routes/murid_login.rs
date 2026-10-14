use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::password;
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct MuridLoginRequest {
    pub ic: String,
    pub password: String,
}

#[derive(sqlx::FromRow)]
struct MuridRow {
    kod: String,
    password_hash: Option<String>,
    must_change_password: bool,
}

pub async fn login_murid(
    State(state): State<AppState>,
    Json(body): Json<MuridLoginRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if exceeds_bcrypt_limit(&body.password) {
        return Err(invalid_credentials());
    }

    // IC numbers are stored as 12 contiguous digits (confirmed live:
    // murid.nric/ic and guru.ic are both digit-only), but a MyKad shows
    // them with dashes ("010203-04-0506") — strip anything that isn't a
    // digit so both forms reach the same stored value.
    let normalized_ic: String = body.ic.chars().filter(char::is_ascii_digit).collect();

    let murid = sqlx::query_as::<_, MuridRow>(
        "SELECT kod, password_hash, must_change_password FROM murid WHERE ic = $1",
    )
        .bind(&normalized_ic)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| {
            eprintln!("login_murid: murid lookup failed: {e}");
            invalid_credentials()
        })?;

    let hash_to_check = murid
        .as_ref()
        .and_then(|m| m.password_hash.clone())
        .unwrap_or_else(|| password::DUMMY_HASH.to_string());

    let password_to_check = body.password.clone();
    let password_ok = tokio::task::spawn_blocking(move || {
        password::verify_password(&password_to_check, &hash_to_check)
    })
    .await
    .unwrap_or(false);

    let murid = match murid {
        Some(m) if m.password_hash.is_some() && password_ok => m,
        _ => return Err(invalid_credentials()),
    };

    let must_change_password = murid.must_change_password;
    let result: Value = sqlx::query_scalar("SELECT sh_masuk($1)")
        .bind(&murid.kod)
        .fetch_one(&state.pool)
        .await
        .map_err(|e| {
            eprintln!("login_murid: sh_masuk failed: {e}");
            invalid_credentials()
        })?;
    let mut result = result;
    if let Value::Object(ref mut map) = result {
        map.insert("must_change_password".to_string(), json!(must_change_password));
    }
    Ok(Json(result))
}

fn invalid_credentials() -> (StatusCode, Json<Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "invalid ic or password"})),
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

    /// Creates a disposable murid row under the real demo kelas (id=3),
    /// with no password_hash set — returns (id, ic).
    async fn create_test_murid_without_password() -> (i64, String) {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        let s = suffix();
        let ic = format!("9{s}");
        let kod = format!("TEST-KOD-{s}");
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO murid (kelas_id, nama, kod, ic) VALUES (3, 'Test Murid', $1, $2) RETURNING id",
        )
        .bind(&kod)
        .bind(&ic)
        .fetch_one(&pool)
        .await
        .expect("insert should succeed");
        (id, ic)
    }

    /// Creates a disposable murid row under the real demo kelas (id=3),
    /// with a real password_hash set — returns (id, ic, kod).
    async fn create_test_murid_with_password(raw_password: &str) -> (i64, String, String) {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        let s = suffix();
        let ic = format!("9{s}");
        let kod = format!("TEST-KOD-{s}");
        let hash = password::hash_password(raw_password).expect("hash should succeed");
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO murid (kelas_id, nama, kod, ic, password_hash) VALUES (3, 'Test Murid', $1, $2, $3) RETURNING id",
        )
        .bind(&kod)
        .bind(&ic)
        .bind(&hash)
        .fetch_one(&pool)
        .await
        .expect("insert should succeed");
        (id, ic, kod)
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

    async fn post_login(ic: &str, password: &str) -> axum::response::Response {
        let app = super::super::app(test_state());
        app.oneshot(
            Request::builder()
                .method("POST")
                .uri("/login/murid")
                .header("content-type", "application/json")
                .body(Body::from(json!({"ic": ic, "password": password}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn login_murid_fails_for_unknown_ic() {
        let response = post_login("TOTALLY-UNKNOWN-IC-XYZ", "whatever").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_murid_unknown_ic_and_no_password_set_are_indistinguishable() {
        let (id, ic_no_password) = create_test_murid_without_password().await;

        let response_unknown = post_login("TOTALLY-UNKNOWN-IC-ABC", "whatever").await;
        let status_unknown = response_unknown.status();
        let body_unknown = axum::body::to_bytes(response_unknown.into_body(), usize::MAX)
            .await
            .unwrap();

        let response_no_password = post_login(&ic_no_password, "whatever").await;
        let status_no_password = response_no_password.status();
        let body_no_password = axum::body::to_bytes(response_no_password.into_body(), usize::MAX)
            .await
            .unwrap();

        assert_eq!(status_unknown, status_no_password);
        assert_eq!(body_unknown, body_no_password);

        cleanup_murid(id).await;
    }

    #[tokio::test]
    async fn login_murid_fails_with_wrong_password() {
        let (id, ic, _kod) = create_test_murid_with_password("correct-horse-battery").await;
        let response = post_login(&ic, "definitely-wrong").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        cleanup_murid(id).await;
    }

    #[tokio::test]
    async fn login_murid_succeeds_with_correct_credentials() {
        let (id, ic, kod) = create_test_murid_with_password("correct-horse-battery").await;
        let response = post_login(&ic, "correct-horse-battery").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["ok"], true);
        // Proves the real sh_masuk response for THIS student came back, not
        // just that some object-shaped body did — matches kod (the field
        // the handler actually passes through) and nama (the fixture's
        // known value). A full second call to sh_masuk to byte-compare
        // isn't used here: sh_masuk mutates akhir_guna/streak/misi on every
        // call, so a second invocation observes different starting state
        // than the first and isn't guaranteed byte-identical even when
        // both are correct.
        assert_eq!(parsed["murid"]["kod"], kod);
        assert_eq!(parsed["murid"]["nama"], "Test Murid");
        cleanup_murid(id).await;
    }

    #[tokio::test]
    async fn login_murid_reports_must_change_password_true_when_flagged() {
        let (id, ic, _kod) = create_test_murid_with_password("correct-horse-battery").await;
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        sqlx::query("UPDATE murid SET must_change_password = true WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .expect("flag update should succeed");

        let response = post_login(&ic, "correct-horse-battery").await;
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["must_change_password"], true);
        cleanup_murid(id).await;
    }

    #[tokio::test]
    async fn login_murid_reports_must_change_password_false_by_default() {
        let (id, ic, _kod) = create_test_murid_with_password("correct-horse-battery").await;
        let response = post_login(&ic, "correct-horse-battery").await;
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["must_change_password"], false);
        cleanup_murid(id).await;
    }

    #[tokio::test]
    async fn login_murid_accepts_ic_with_mykad_style_dashes() {
        let (id, ic, _kod) = create_test_murid_with_password("correct-horse-battery").await;
        // ic is stored digit-only (e.g. "9172...") — insert dashes the way
        // a MyKad displays it, splitting after the 6th and 8th digit, and
        // confirm the normalized lookup still matches.
        let dashed = format!("{}-{}-{}", &ic[..6], &ic[6..8], &ic[8..]);
        let response = post_login(&dashed, "correct-horse-battery").await;
        assert_eq!(response.status(), StatusCode::OK);
        cleanup_murid(id).await;
    }
}
