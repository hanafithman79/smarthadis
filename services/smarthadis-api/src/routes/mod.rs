pub mod admin;
pub mod admin_students;
pub mod admin_teachers;
pub mod assign_misi;
pub mod auth;
pub mod award_points;
pub mod change_password;
pub mod dashboard;
pub mod healthz;
pub mod murid_login;
pub mod sh;

use axum::{
    middleware::from_fn_with_state,
    routing::{get, post},
    Router,
};
use std::time::Duration;

use crate::auth::rate_limit::{rate_limit, RateLimiter};
use crate::AppState;

/// 10 requests per IP per 60 seconds, shared across all three credential-
/// checking routes below — see auth::rate_limit's doc comment for why
/// these three specifically (weak/guessable secrets: a 6-digit student
/// PIN, and the account-takeover path through change-password).
const SENSITIVE_ROUTE_MAX_REQUESTS: u32 = 10;
const SENSITIVE_ROUTE_WINDOW: Duration = Duration::from_secs(60);

pub fn app(state: AppState) -> Router {
    let limiter = RateLimiter::new(SENSITIVE_ROUTE_MAX_REQUESTS, SENSITIVE_ROUTE_WINDOW);
    let sensitive: Router<AppState> = Router::new()
        .route("/login/password", post(auth::login_password))
        .route("/login/murid", post(murid_login::login_murid))
        .route("/change-password", post(change_password::change_password))
        .layer(from_fn_with_state(limiter, rate_limit));

    Router::new()
        .merge(sensitive)
        .route("/healthz", get(healthz::healthz))
        .route("/logout", post(auth::logout))
        .route("/admin/accounts", post(admin::create_account))
        .route("/admin/teachers", get(admin_teachers::list_teachers))
        .route("/admin/classes", get(admin_teachers::list_classes))
        .route("/admin/assign-classes", post(admin_teachers::assign_classes))
        .route("/admin/update-teacher", post(admin_teachers::update_teacher))
        .route("/admin/reset-teacher-password", post(admin_teachers::reset_teacher_password))
        .route("/admin/set-teacher-active", post(admin_teachers::set_teacher_active))
        .route("/admin/students", get(admin_students::list_students))
        .route("/admin/update-student", post(admin_students::update_student))
        .route("/admin/reset-student-password", post(admin_students::reset_student_password))
        .route("/admin/remove-student", post(admin_students::remove_student))
        .route("/dashboard", get(dashboard::dashboard))
        .route("/assign-misi", post(assign_misi::assign_misi))
        .route("/award-points", post(award_points::award_points))
        .route("/sh/masuk", post(sh::masuk))
        .route("/sh/dashboard", post(sh::dashboard))
        .route("/sh/rekod_hafazan", post(sh::rekod_hafazan))
        .route("/sh/simpan_refleksi", post(sh::simpan_refleksi))
        .route("/sh/tambah_misi", post(sh::tambah_misi))
        .route("/sh/tanda_misi", post(sh::tanda_misi))
        .route("/sh/tanya", post(sh::tanya))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use serde_json::json;
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

    #[tokio::test]
    async fn login_murid_is_rate_limited_per_ip_after_the_configured_max() {
        let app_router = app(test_state());
        let forwarded_for = "203.0.113.77";

        for _ in 0..SENSITIVE_ROUTE_MAX_REQUESTS {
            let response = app_router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/login/murid")
                        .header("content-type", "application/json")
                        .header("x-forwarded-for", forwarded_for)
                        .body(Body::from(
                            json!({"ic": "TOTALLY-UNKNOWN-IC", "password": "whatever"}).to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        let limited_response = app_router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login/murid")
                    .header("content-type", "application/json")
                    .header("x-forwarded-for", forwarded_for)
                    .body(Body::from(
                        json!({"ic": "TOTALLY-UNKNOWN-IC", "password": "whatever"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(limited_response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn a_different_ip_is_not_affected_by_another_ip_s_limit() {
        let app_router = app(test_state());

        for _ in 0..SENSITIVE_ROUTE_MAX_REQUESTS {
            app_router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/login/murid")
                        .header("content-type", "application/json")
                        .header("x-forwarded-for", "203.0.113.1")
                        .body(Body::from(
                            json!({"ic": "TOTALLY-UNKNOWN-IC", "password": "whatever"}).to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
        }

        let other_ip_response = app_router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login/murid")
                    .header("content-type", "application/json")
                    .header("x-forwarded-for", "203.0.113.2")
                    .body(Body::from(
                        json!({"ic": "TOTALLY-UNKNOWN-IC", "password": "whatever"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(other_ip_response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn healthz_is_not_rate_limited() {
        let app_router = app(test_state());
        for _ in 0..(SENSITIVE_ROUTE_MAX_REQUESTS + 5) {
            let response = app_router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/healthz")
                        .header("x-forwarded-for", "203.0.113.99")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
    }
}
