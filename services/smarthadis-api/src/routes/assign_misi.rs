use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::middleware;
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct AssignMisiRequest {
    pub murid_id: i64,
    pub hadis_no: i32,
}

/// Lets a teacher assign a specific hadis mission to a specific student —
/// the only write action available to a teacher in this app; every other
/// write (completing a mission, logging a reflection) is student-
/// initiated. Reuses the existing sh_tambah_misi SECURITY DEFINER
/// function (built for student self-service) by looking up the target
/// student's own `kod`, scoped to students in one of the teacher's
/// assigned classes — a teacher can only act on their own students, not
/// an arbitrary murid_id.
pub async fn assign_misi(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<AssignMisiRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let claims = middleware::require_session(&jar, &state.jwt_secret)?;
    middleware::require_role(&claims, "role_teacher")?;
    let teacher_id: i64 = claims.sub.parse().map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid session"})),
        )
    })?;

    let kod: Option<String> = sqlx::query_scalar(
        "SELECT m.kod FROM murid m JOIN guru_class gc ON gc.kelas_id = m.kelas_id WHERE m.id = $1 AND gc.account_id = $2",
    )
    .bind(body.murid_id)
    .bind(teacher_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| {
        eprintln!("assign_misi: student lookup failed: {e}");
        internal_error()
    })?;

    let Some(kod) = kod else {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "student is not in one of your assigned classes"})),
        ));
    };

    sqlx::query_scalar::<_, Value>("SELECT sh_tambah_misi($1, $2)")
        .bind(&kod)
        .bind(body.hadis_no)
        .fetch_one(&state.pool)
        .await
        .map(Json)
        .map_err(|e| {
            eprintln!("assign_misi: sh_tambah_misi failed: {e}");
            internal_error()
        })
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
        let email = format!("assign-misi-test-{}@smarthadis-rust-test.invalid", suffix());
        let row: (Value,) = sqlx::query_as("SELECT admin_create_account($1, $2, $3)")
            .bind(&email)
            .bind("Assign Misi Test Teacher")
            .bind("teacher")
            .fetch_one(&mut *tx)
            .await
            .expect("admin_create_account should succeed");
        tx.commit().await.expect("commit should succeed");
        row.0["account_id"].as_i64().expect("account_id present")
    }

    async fn create_test_murid(kelas_id: i64) -> i64 {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        let s = suffix();
        let kod = format!("TEST-KOD-{s}");
        sqlx::query_scalar(
            "INSERT INTO murid (kelas_id, nama, kod) VALUES ($1, 'Assign Misi Test Murid', $2) RETURNING id",
        )
        .bind(kelas_id)
        .bind(&kod)
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
        sqlx::query("DELETE FROM misi WHERE murid_id = $1")
            .bind(murid_id)
            .execute(&pool)
            .await
            .expect("cleanup delete should succeed");
        sqlx::query("DELETE FROM murid WHERE id = $1")
            .bind(murid_id)
            .execute(&pool)
            .await
            .expect("cleanup delete should succeed");
    }

    async fn post_assign_misi(cookie: Option<String>, body: Value) -> axum::response::Response {
        let app = super::super::app(test_state());
        let mut builder = Request::builder()
            .method("POST")
            .uri("/assign-misi")
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
        let response = post_assign_misi(None, json!({"murid_id": 1, "hadis_no": 1})).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn fails_for_non_teacher_role() {
        let secret = "test-secret-at-least-32-characters-long";
        let token = crate::auth::jwt::issue(secret, 1, "role_parent", "p@example.com", 3600);
        let response = post_assign_misi(
            Some(format!("session={token}")),
            json!({"murid_id": 1, "hadis_no": 1}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn fails_when_student_is_not_in_the_teacher_s_classes() {
        let teacher_id = create_test_teacher().await;
        assign_class(teacher_id, 4).await; // teacher only has kelas 4
        let murid_id = create_test_murid(3).await; // student is in kelas 3
        let secret = "test-secret-at-least-32-characters-long";
        let token = crate::auth::jwt::issue(secret, teacher_id, "role_teacher", "t@example.com", 3600);

        let response = post_assign_misi(
            Some(format!("session={token}")),
            json!({"murid_id": murid_id, "hadis_no": 1}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        cleanup_murid(murid_id).await;
        cleanup_teacher(teacher_id).await;
    }

    #[tokio::test]
    async fn succeeds_for_a_student_in_the_teacher_s_own_class() {
        let teacher_id = create_test_teacher().await;
        assign_class(teacher_id, 3).await;
        let murid_id = create_test_murid(3).await;
        let secret = "test-secret-at-least-32-characters-long";
        let token = crate::auth::jwt::issue(secret, teacher_id, "role_teacher", "t@example.com", 3600);

        let response = post_assign_misi(
            Some(format!("session={token}")),
            json!({"murid_id": murid_id, "hadis_no": 1}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["misi"]["hadis_no"], 1);

        cleanup_murid(murid_id).await;
        cleanup_teacher(teacher_id).await;
    }
}
