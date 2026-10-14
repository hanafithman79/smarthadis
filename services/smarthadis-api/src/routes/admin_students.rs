use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::{middleware, password};
use crate::AppState;

async fn require_admin(state: &AppState, jar: &CookieJar) -> Result<(), (StatusCode, Json<Value>)> {
    let claims = middleware::require_session(jar, &state.jwt_secret)?;
    middleware::require_admin(&state.pool, &claims).await
}

fn internal_error() -> (StatusCode, Json<Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "server error"})),
    )
}

pub async fn list_students(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_admin(&state, &jar).await?;

    #[derive(sqlx::FromRow)]
    struct Row {
        id: i64,
        nama: String,
        kod: String,
        ic: Option<String>,
        kelas_id: i64,
        kelas_nama: String,
        mata: i32,
    }

    let rows: Vec<Row> = sqlx::query_as(
        "SELECT m.id, m.nama, m.kod, m.ic, m.kelas_id, k.nama AS kelas_nama, m.mata \
         FROM murid m JOIN kelas k ON k.id = m.kelas_id \
         ORDER BY k.nama, m.nama",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| {
        eprintln!("list_students: query failed: {e}");
        internal_error()
    })?;

    let students: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "murid_id": r.id,
                "nama": r.nama,
                "kod": r.kod,
                "ic": r.ic,
                "kelas_id": r.kelas_id,
                "kelas_nama": r.kelas_nama,
                "mata": r.mata,
            })
        })
        .collect();

    Ok(Json(json!({"students": students})))
}

#[derive(Debug, Deserialize)]
pub struct MuridIdRequest {
    pub murid_id: i64,
}

#[derive(Debug, Deserialize)]
pub struct UpdateStudentRequest {
    pub murid_id: i64,
    #[serde(default)]
    pub nama: Option<String>,
    #[serde(default)]
    pub ic: Option<String>,
}

pub async fn update_student(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<UpdateStudentRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_admin(&state, &jar).await?;

    if let Some(nama) = &body.nama {
        sqlx::query("UPDATE murid SET nama = $1 WHERE id = $2")
            .bind(nama)
            .bind(body.murid_id)
            .execute(&state.pool)
            .await
            .map_err(|e| {
                eprintln!("update_student: nama update failed: {e}");
                internal_error()
            })?;
    }

    if let Some(ic) = &body.ic {
        sqlx::query("UPDATE murid SET ic = $1 WHERE id = $2")
            .bind(ic)
            .bind(body.murid_id)
            .execute(&state.pool)
            .await
            .map_err(|e| {
                if e.as_database_error().map(|d| d.code().as_deref() == Some("23505")).unwrap_or(false) {
                    (
                        StatusCode::CONFLICT,
                        Json(json!({"error": "that ic is already in use by another student"})),
                    )
                } else {
                    eprintln!("update_student: ic update failed: {e}");
                    internal_error()
                }
            })?;
    }

    Ok(Json(json!({"ok": true})))
}

pub async fn reset_student_password(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<MuridIdRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_admin(&state, &jar).await?;

    let new_pin = password::generate_student_pin();
    let pin_for_hash = new_pin.clone();
    let hash = tokio::task::spawn_blocking(move || password::hash_password(&pin_for_hash))
        .await
        .expect("hashing task should not panic")
        .map_err(|e| {
            eprintln!("reset_student_password: hashing failed: {e}");
            internal_error()
        })?;

    sqlx::query(
        "UPDATE murid SET password_hash = $1, must_change_password = true WHERE id = $2",
    )
    .bind(&hash)
    .bind(body.murid_id)
    .execute(&state.pool)
    .await
    .map_err(|e| {
        eprintln!("reset_student_password: update failed: {e}");
        internal_error()
    })?;

    Ok(Json(json!({"ok": true, "password": new_pin})))
}

pub async fn remove_student(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<MuridIdRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_admin(&state, &jar).await?;

    sqlx::query("DELETE FROM murid WHERE id = $1")
        .bind(body.murid_id)
        .execute(&state.pool)
        .await
        .map_err(|e| {
            eprintln!("remove_student: delete failed: {e}");
            internal_error()
        })?;

    Ok(Json(json!({"ok": true})))
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

    fn admin_cookie() -> String {
        let secret = "test-secret-at-least-32-characters-long";
        let token = crate::auth::jwt::issue(secret, 1, "role_admin", "a@example.com", 3600);
        format!("session={token}")
    }

    fn teacher_cookie(account_id: i64) -> String {
        let secret = "test-secret-at-least-32-characters-long";
        let token = crate::auth::jwt::issue(secret, account_id, "role_teacher", "t@example.com", 3600);
        format!("session={token}")
    }

    /// A disposable non-admin account, scoped for role-rejection tests.
    /// Never hardcode account_id=1: require_admin checks the real row,
    /// and this project's one real admin account is id=1 with
    /// is_admin=true — a hardcoded id=1 would pass by accident.
    async fn create_test_non_admin_account() -> i64 {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        let email = format!("admin-students-nonadmin-test-{}@smarthadis-rust-test.invalid", suffix());
        sqlx::query_scalar(
            "INSERT INTO account (nama, email, role, aktif) VALUES ('Non Admin Test', $1, 'teacher', true) RETURNING id",
        )
        .bind(&email)
        .fetch_one(&pool)
        .await
        .expect("insert should succeed")
    }

    async fn cleanup_account(account_id: i64) {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        sqlx::query("DELETE FROM account WHERE id = $1")
            .bind(account_id)
            .execute(&pool)
            .await
            .ok();
    }

    async fn create_test_murid() -> (i64, String) {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        let s = suffix();
        let ic = format!("9{s}");
        let kod = format!("TEST-KOD-{s}");
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO murid (kelas_id, nama, kod, ic) VALUES (3, 'Admin Students Test Murid', $1, $2) RETURNING id",
        )
        .bind(&kod)
        .bind(&ic)
        .fetch_one(&pool)
        .await
        .expect("insert should succeed");
        (id, ic)
    }

    async fn cleanup_murid(murid_id: i64) {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        sqlx::query("DELETE FROM murid WHERE id = $1")
            .bind(murid_id)
            .execute(&pool)
            .await
            .ok();
    }

    async fn fetch_murid(murid_id: i64) -> Option<(String, String)> {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        sqlx::query_as("SELECT nama, kod FROM murid WHERE id = $1")
            .bind(murid_id)
            .fetch_optional(&pool)
            .await
            .expect("select should succeed")
    }

    async fn post_json(uri: &str, cookie: Option<&str>, body: Value) -> axum::response::Response {
        let app = super::super::app(test_state());
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(c) = cookie {
            builder = builder.header("cookie", c.to_string());
        }
        app.oneshot(builder.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }

    async fn get_with_cookie(uri: &str, cookie: Option<&str>) -> axum::response::Response {
        let app = super::super::app(test_state());
        let mut builder = Request::builder().method("GET").uri(uri);
        if let Some(c) = cookie {
            builder = builder.header("cookie", c.to_string());
        }
        app.oneshot(builder.body(Body::empty()).unwrap()).await.unwrap()
    }

    #[tokio::test]
    async fn list_students_fails_without_admin_role() {
        let account_id = create_test_non_admin_account().await;
        let response = get_with_cookie("/admin/students", Some(&teacher_cookie(account_id))).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        cleanup_account(account_id).await;
    }

    #[tokio::test]
    async fn list_students_includes_a_real_fixture() {
        let (murid_id, ic) = create_test_murid().await;
        let response = get_with_cookie("/admin/students", Some(&admin_cookie())).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        let students = parsed["students"].as_array().expect("students should be an array");
        let found = students.iter().find(|s| s["murid_id"].as_i64() == Some(murid_id));
        let found = found.expect("fixture student should be in the list");
        assert_eq!(found["nama"], "Admin Students Test Murid");
        assert_eq!(found["ic"], ic);

        cleanup_murid(murid_id).await;
    }

    #[tokio::test]
    async fn update_student_changes_nama_and_ic() {
        let (murid_id, _ic) = create_test_murid().await;
        let new_ic = format!("9{}", suffix());

        let response = post_json(
            "/admin/update-student",
            Some(&admin_cookie()),
            json!({"murid_id": murid_id, "nama": "Updated Student Name", "ic": new_ic}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let (nama, _kod) = fetch_murid(murid_id).await.expect("student should still exist");
        assert_eq!(nama, "Updated Student Name");

        cleanup_murid(murid_id).await;
    }

    #[tokio::test]
    async fn reset_student_password_returns_a_working_new_pin() {
        let (murid_id, ic) = create_test_murid().await;

        let response = post_json(
            "/admin/reset-student-password",
            Some(&admin_cookie()),
            json!({"murid_id": murid_id}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        let new_pin = parsed["password"].as_str().expect("password should be present").to_string();
        assert_eq!(new_pin.len(), 6);

        let login = post_json(
            "/login/murid",
            None,
            json!({"ic": ic, "password": new_pin}),
        )
        .await;
        assert_eq!(login.status(), StatusCode::OK);

        cleanup_murid(murid_id).await;
    }

    #[tokio::test]
    async fn remove_student_deletes_the_row() {
        let (murid_id, _ic) = create_test_murid().await;

        let response = post_json(
            "/admin/remove-student",
            Some(&admin_cookie()),
            json!({"murid_id": murid_id}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(fetch_murid(murid_id).await.is_none(), "student row should be gone");
    }

    #[tokio::test]
    async fn remove_student_fails_without_admin_role() {
        let (murid_id, _ic) = create_test_murid().await;
        let account_id = create_test_non_admin_account().await;
        let response = post_json(
            "/admin/remove-student",
            Some(&teacher_cookie(account_id)),
            json!({"murid_id": murid_id}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        cleanup_murid(murid_id).await;
        cleanup_account(account_id).await;
    }
}
