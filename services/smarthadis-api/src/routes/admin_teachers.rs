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

pub async fn list_teachers(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_admin(&state, &jar).await?;

    #[derive(sqlx::FromRow)]
    struct Row {
        id: i64,
        nama: String,
        ic: Option<String>,
        aktif: bool,
        kelas_ids: Vec<i64>,
    }

    let rows: Vec<Row> = sqlx::query_as(
        "SELECT a.id, a.nama, a.ic, a.aktif, \
                COALESCE(array_agg(gc.kelas_id) FILTER (WHERE gc.kelas_id IS NOT NULL), '{}') AS kelas_ids \
         FROM account a LEFT JOIN guru_class gc ON gc.account_id = a.id \
         WHERE a.role = 'teacher' \
         GROUP BY a.id, a.nama, a.ic, a.aktif \
         ORDER BY a.nama",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| {
        eprintln!("list_teachers: query failed: {e}");
        internal_error()
    })?;

    let teachers: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "account_id": r.id,
                "nama": r.nama,
                "ic": r.ic,
                "aktif": r.aktif,
                "kelas_ids": r.kelas_ids,
            })
        })
        .collect();

    Ok(Json(json!({"teachers": teachers})))
}

pub async fn list_classes(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_admin(&state, &jar).await?;

    let rows: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, nama FROM kelas WHERE contoh IS NOT TRUE ORDER BY nama",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| {
        eprintln!("list_classes: query failed: {e}");
        internal_error()
    })?;

    let classes: Vec<Value> = rows
        .into_iter()
        .map(|(id, nama)| json!({"id": id, "nama": nama}))
        .collect();

    Ok(Json(json!({"classes": classes})))
}

#[derive(Debug, Deserialize)]
pub struct AssignClassesRequest {
    pub account_id: i64,
    pub kelas_ids: Vec<i64>,
}

pub async fn assign_classes(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<AssignClassesRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_admin(&state, &jar).await?;

    let is_teacher: Option<i64> =
        sqlx::query_scalar("SELECT id FROM account WHERE id = $1 AND role = 'teacher'")
            .bind(body.account_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(|e| {
                eprintln!("assign_classes: teacher lookup failed: {e}");
                internal_error()
            })?;
    if is_teacher.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "account_id is not a teacher account"})),
        ));
    }

    if !body.kelas_ids.is_empty() {
        let valid_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM kelas WHERE id = ANY($1) AND contoh IS NOT TRUE",
        )
        .bind(&body.kelas_ids)
        .fetch_one(&state.pool)
        .await
        .map_err(|e| {
            eprintln!("assign_classes: kelas validation failed: {e}");
            internal_error()
        })?;
        if valid_count as usize != body.kelas_ids.len() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "one or more kelas_ids are invalid"})),
            ));
        }
    }

    let mut tx = state.pool.begin().await.map_err(|e| {
        eprintln!("assign_classes: begin failed: {e}");
        internal_error()
    })?;

    sqlx::query("DELETE FROM guru_class WHERE account_id = $1")
        .bind(body.account_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            eprintln!("assign_classes: delete failed: {e}");
            internal_error()
        })?;

    for kelas_id in &body.kelas_ids {
        sqlx::query("INSERT INTO guru_class (account_id, kelas_id) VALUES ($1, $2)")
            .bind(body.account_id)
            .bind(kelas_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                eprintln!("assign_classes: insert failed: {e}");
                internal_error()
            })?;
    }

    tx.commit().await.map_err(|e| {
        eprintln!("assign_classes: commit failed: {e}");
        internal_error()
    })?;

    Ok(Json(json!({"ok": true, "kelas_ids": body.kelas_ids})))
}

#[derive(Debug, Deserialize)]
pub struct UpdateTeacherRequest {
    pub account_id: i64,
    #[serde(default)]
    pub nama: Option<String>,
    #[serde(default)]
    pub ic: Option<String>,
}

pub async fn update_teacher(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<UpdateTeacherRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_admin(&state, &jar).await?;

    if let Some(nama) = &body.nama {
        sqlx::query("UPDATE account SET nama = $1 WHERE id = $2")
            .bind(nama)
            .bind(body.account_id)
            .execute(&state.pool)
            .await
            .map_err(|e| {
                eprintln!("update_teacher: nama update failed: {e}");
                internal_error()
            })?;
    }

    if let Some(ic) = &body.ic {
        sqlx::query("UPDATE account SET ic = $1 WHERE id = $2")
            .bind(ic)
            .bind(body.account_id)
            .execute(&state.pool)
            .await
            .map_err(|e| {
                if e.as_database_error().map(|d| d.code().as_deref() == Some("23505")).unwrap_or(false) {
                    (
                        StatusCode::CONFLICT,
                        Json(json!({"error": "that ic is already in use by another account"})),
                    )
                } else {
                    eprintln!("update_teacher: ic update failed: {e}");
                    internal_error()
                }
            })?;
    }

    Ok(Json(json!({"ok": true})))
}

#[derive(Debug, Deserialize)]
pub struct AccountIdRequest {
    pub account_id: i64,
}

pub async fn reset_teacher_password(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<AccountIdRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_admin(&state, &jar).await?;

    let new_password = password::generate_teacher_password();
    let password_for_hash = new_password.clone();
    let hash = tokio::task::spawn_blocking(move || password::hash_password(&password_for_hash))
        .await
        .expect("hashing task should not panic")
        .map_err(|e| {
            eprintln!("reset_teacher_password: hashing failed: {e}");
            internal_error()
        })?;

    sqlx::query(
        "UPDATE account SET password_hash = $1, must_change_password = true WHERE id = $2",
    )
    .bind(&hash)
    .bind(body.account_id)
    .execute(&state.pool)
    .await
    .map_err(|e| {
        eprintln!("reset_teacher_password: update failed: {e}");
        internal_error()
    })?;

    Ok(Json(json!({"ok": true, "password": new_password})))
}

#[derive(Debug, Deserialize)]
pub struct SetActiveRequest {
    pub account_id: i64,
    pub aktif: bool,
}

pub async fn set_teacher_active(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<SetActiveRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_admin(&state, &jar).await?;

    sqlx::query("UPDATE account SET aktif = $1 WHERE id = $2")
        .bind(body.aktif)
        .bind(body.account_id)
        .execute(&state.pool)
        .await
        .map_err(|e| {
            eprintln!("set_teacher_active: update failed: {e}");
            internal_error()
        })?;

    Ok(Json(json!({"ok": true, "aktif": body.aktif})))
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

    async fn create_test_teacher() -> (i64, String) {
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
        let email = format!("admin-teachers-test-{}@smarthadis-rust-test.invalid", suffix());
        let row: (Value,) = sqlx::query_as("SELECT admin_create_account($1, $2, $3)")
            .bind(&email)
            .bind("Admin Teachers Test Teacher")
            .bind("teacher")
            .fetch_one(&mut *tx)
            .await
            .expect("admin_create_account should succeed");
        tx.commit().await.expect("commit should succeed");
        (row.0["account_id"].as_i64().expect("account_id present"), email)
    }

    async fn set_teacher_ic(account_id: i64, ic: &str) {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        sqlx::query("UPDATE account SET ic = $1 WHERE id = $2")
            .bind(ic)
            .bind(account_id)
            .execute(&pool)
            .await
            .expect("set ic should succeed");
    }

    async fn assign_class_directly(account_id: i64, kelas_id: i64) {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        sqlx::query("INSERT INTO guru_class (account_id, kelas_id) VALUES ($1, $2)")
            .bind(account_id)
            .bind(kelas_id)
            .execute(&pool)
            .await
            .expect("insert should succeed");
    }

    async fn cleanup_teacher(account_id: i64) {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        sqlx::query("DELETE FROM account WHERE id = $1")
            .bind(account_id)
            .execute(&pool)
            .await
            .expect("cleanup delete should succeed");
    }

    async fn fetch_account(account_id: i64) -> (String, Option<String>, bool) {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        sqlx::query_as("SELECT nama, ic, aktif FROM account WHERE id = $1")
            .bind(account_id)
            .fetch_one(&pool)
            .await
            .expect("select should succeed")
    }

    async fn guru_class_ids(account_id: i64) -> Vec<i64> {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        sqlx::query_scalar("SELECT kelas_id FROM guru_class WHERE account_id = $1 ORDER BY kelas_id")
            .bind(account_id)
            .fetch_all(&pool)
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
    async fn list_teachers_fails_without_admin_role() {
        // Must use a disposable fixture, never a hardcoded id: require_admin
        // checks the real account row, and this project's one real admin
        // account (id=1) genuinely has is_admin=true — a hardcoded id=1
        // would pass this check by accident, not prove the rejection works.
        let (account_id, _email) = create_test_teacher().await;
        let response = get_with_cookie("/admin/teachers", Some(&teacher_cookie(account_id))).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        cleanup_teacher(account_id).await;
    }

    #[tokio::test]
    async fn list_teachers_includes_a_real_fixture_with_its_classes() {
        let (account_id, _email) = create_test_teacher().await;
        assign_class_directly(account_id, 3).await;
        assign_class_directly(account_id, 4).await;

        let response = get_with_cookie("/admin/teachers", Some(&admin_cookie())).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        let teachers = parsed["teachers"].as_array().expect("teachers should be an array");
        let found = teachers.iter().find(|t| t["account_id"].as_i64() == Some(account_id));
        let found = found.expect("fixture teacher should be in the list");
        assert_eq!(found["nama"], "Admin Teachers Test Teacher");
        let mut kelas_ids: Vec<i64> = found["kelas_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_i64().unwrap())
            .collect();
        kelas_ids.sort();
        assert_eq!(kelas_ids, vec![3, 4]);

        cleanup_teacher(account_id).await;
    }

    #[tokio::test]
    async fn list_classes_excludes_demo_classes() {
        let response = get_with_cookie("/admin/classes", Some(&admin_cookie())).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        let classes = parsed["classes"].as_array().expect("classes should be an array");
        assert!(classes.iter().all(|c| c["id"].as_i64() != Some(3) && c["id"].as_i64() != Some(4)));
        assert!(classes.len() >= 20, "expected at least the 21 real classes");
    }

    #[tokio::test]
    async fn assign_classes_replaces_the_existing_set() {
        // kelas ids 3/4 are the demo/test rows (contoh=true) — the
        // handler deliberately rejects those as assignment targets, so
        // this test uses real kelas ids (1 = "D6 Firdaus", 5 = "D1
        // Firdaus") instead, same as a real admin would.
        let (account_id, _email) = create_test_teacher().await;
        assign_class_directly(account_id, 1).await;

        let response = post_json(
            "/admin/assign-classes",
            Some(&admin_cookie()),
            json!({"account_id": account_id, "kelas_ids": [5]}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(guru_class_ids(account_id).await, vec![5]);

        cleanup_teacher(account_id).await;
    }

    #[tokio::test]
    async fn assign_classes_rejects_a_non_teacher_account_id() {
        let response = post_json(
            "/admin/assign-classes",
            Some(&admin_cookie()),
            json!({"account_id": 1, "kelas_ids": [3]}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn update_teacher_changes_nama_and_ic() {
        let (account_id, _email) = create_test_teacher().await;
        let new_ic = format!("9{}", suffix());

        let response = post_json(
            "/admin/update-teacher",
            Some(&admin_cookie()),
            json!({"account_id": account_id, "nama": "Updated Name", "ic": new_ic}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let (nama, ic, _aktif) = fetch_account(account_id).await;
        assert_eq!(nama, "Updated Name");
        assert_eq!(ic, Some(new_ic));

        cleanup_teacher(account_id).await;
    }

    #[tokio::test]
    async fn update_teacher_rejects_a_duplicate_ic() {
        let (account_id_1, _email_1) = create_test_teacher().await;
        let (account_id_2, _email_2) = create_test_teacher().await;
        let shared_ic = format!("9{}", suffix());
        set_teacher_ic(account_id_1, &shared_ic).await;

        let response = post_json(
            "/admin/update-teacher",
            Some(&admin_cookie()),
            json!({"account_id": account_id_2, "ic": shared_ic}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);

        cleanup_teacher(account_id_1).await;
        cleanup_teacher(account_id_2).await;
    }

    #[tokio::test]
    async fn reset_teacher_password_returns_a_working_new_password() {
        let (account_id, email) = create_test_teacher().await;

        let response = post_json(
            "/admin/reset-teacher-password",
            Some(&admin_cookie()),
            json!({"account_id": account_id}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        let new_password = parsed["password"].as_str().expect("password should be present").to_string();

        let login = post_json(
            "/login/password",
            None,
            json!({"identifier": email, "password": new_password}),
        )
        .await;
        assert_eq!(login.status(), StatusCode::OK);

        cleanup_teacher(account_id).await;
    }

    #[tokio::test]
    async fn set_teacher_active_can_deactivate_and_reactivate() {
        let (account_id, _email) = create_test_teacher().await;

        let off = post_json(
            "/admin/set-teacher-active",
            Some(&admin_cookie()),
            json!({"account_id": account_id, "aktif": false}),
        )
        .await;
        assert_eq!(off.status(), StatusCode::OK);
        let (_nama, _ic, aktif) = fetch_account(account_id).await;
        assert!(!aktif);

        let on = post_json(
            "/admin/set-teacher-active",
            Some(&admin_cookie()),
            json!({"account_id": account_id, "aktif": true}),
        )
        .await;
        assert_eq!(on.status(), StatusCode::OK);
        let (_nama, _ic, aktif2) = fetch_account(account_id).await;
        assert!(aktif2);

        cleanup_teacher(account_id).await;
    }
}
