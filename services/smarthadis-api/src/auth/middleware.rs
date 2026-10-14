use axum::http::StatusCode;
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde_json::{json, Value};

use super::jwt::{self, TokenClaims};

pub fn require_session(
    jar: &CookieJar,
    secret: &str,
) -> Result<TokenClaims, (StatusCode, Json<Value>)> {
    let token = jar
        .get("session")
        .map(|c| c.value().to_string())
        .ok_or_else(unauthorized)?;
    jwt::verify(secret, &token).map_err(|_| unauthorized())
}

pub fn require_role(
    claims: &TokenClaims,
    role: &str,
) -> Result<(), (StatusCode, Json<Value>)> {
    if claims.role == role {
        Ok(())
    } else {
        Err((StatusCode::FORBIDDEN, Json(json!({"error": "forbidden"}))))
    }
}

/// Checks `account.is_admin` fresh from the database, rather than a JWT
/// claim — lets someone be both a teacher (their `role` claim, used for
/// /dashboard and friends) and an admin at the same time, without
/// touching jwt::issue's signature (27 call sites across this codebase
/// at the time this was added).
pub async fn require_admin(
    pool: &sqlx::PgPool,
    claims: &TokenClaims,
) -> Result<(), (StatusCode, Json<Value>)> {
    let account_id: i64 = claims.sub.parse().map_err(|_| unauthorized())?;
    let is_admin: Option<bool> = sqlx::query_scalar("SELECT is_admin FROM account WHERE id = $1")
        .bind(account_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            eprintln!("require_admin: lookup failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "server error"})),
            )
        })?;
    if is_admin == Some(true) {
        Ok(())
    } else {
        Err((StatusCode::FORBIDDEN, Json(json!({"error": "forbidden"}))))
    }
}

fn unauthorized() -> (StatusCode, Json<Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "invalid or expired session"})),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_extra::extract::cookie::Cookie;

    const SECRET: &str = "test-secret-at-least-32-characters-long";

    #[test]
    fn require_session_extracts_claims_from_valid_cookie() {
        let token = jwt::issue(SECRET, 7, "role_teacher", "t@example.com", 3600);
        let jar = CookieJar::new().add(Cookie::new("session", token));
        let claims = require_session(&jar, SECRET).expect("should extract claims");
        assert_eq!(claims.sub, "7");
        assert_eq!(claims.role, "role_teacher");
    }

    #[test]
    fn require_session_rejects_missing_cookie() {
        let jar = CookieJar::new();
        assert!(require_session(&jar, SECRET).is_err());
    }

    #[test]
    fn require_session_rejects_invalid_token() {
        let jar = CookieJar::new().add(Cookie::new("session", "not-a-real-jwt"));
        assert!(require_session(&jar, SECRET).is_err());
    }

    #[test]
    fn require_role_accepts_matching_role() {
        let token = jwt::issue(SECRET, 7, "role_admin", "a@example.com", 3600);
        let claims = jwt::verify(SECRET, &token).unwrap();
        assert!(require_role(&claims, "role_admin").is_ok());
    }

    #[test]
    fn require_role_rejects_mismatched_role() {
        let token = jwt::issue(SECRET, 7, "role_teacher", "t@example.com", 3600);
        let claims = jwt::verify(SECRET, &token).unwrap();
        assert!(require_role(&claims, "role_admin").is_err());
    }

    fn test_pool() -> sqlx::PgPool {
        sqlx::PgPool::connect_lazy(&std::env::var("TEST_DATABASE_URL").expect(
            "set TEST_DATABASE_URL to the rust_svc connection string for this test",
        ))
        .expect("lazy pool construction cannot fail")
    }

    fn cleanup_database_url() -> String {
        std::env::var("TEST_SETUP_DATABASE_URL").expect(
            "set TEST_SETUP_DATABASE_URL to the smarthadis40apps owner connection string, used only to manage test fixtures",
        )
    }

    async fn create_test_account(is_admin: bool, role: &str) -> i64 {
        let pool = sqlx::PgPool::connect_lazy(&cleanup_database_url())
            .expect("lazy pool construction cannot fail");
        let s = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let email = format!("require-admin-test-{s}@smarthadis-rust-test.invalid");
        sqlx::query_scalar(
            "INSERT INTO account (nama, email, role, aktif, is_admin) VALUES ('Require Admin Test', $1, $2, true, $3) RETURNING id",
        )
        .bind(&email)
        .bind(role)
        .bind(is_admin)
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

    #[tokio::test]
    async fn require_admin_accepts_a_dual_role_teacher_with_is_admin_true() {
        let account_id = create_test_account(true, "teacher").await;
        let claims = TokenClaims {
            sub: account_id.to_string(),
            role: "role_teacher".to_string(),
            email: "t@example.com".to_string(),
            iat: 0,
            exp: 9_999_999_999,
        };
        let result = require_admin(&test_pool(), &claims).await;
        assert!(result.is_ok(), "a teacher with is_admin=true should pass");
        cleanup_account(account_id).await;
    }

    #[tokio::test]
    async fn require_admin_rejects_a_teacher_without_is_admin() {
        let account_id = create_test_account(false, "teacher").await;
        let claims = TokenClaims {
            sub: account_id.to_string(),
            role: "role_teacher".to_string(),
            email: "t@example.com".to_string(),
            iat: 0,
            exp: 9_999_999_999,
        };
        let result = require_admin(&test_pool(), &claims).await;
        assert!(result.is_err(), "a plain teacher must not pass require_admin");
        cleanup_account(account_id).await;
    }

    #[tokio::test]
    async fn require_admin_rejects_an_unknown_account_id() {
        let claims = TokenClaims {
            sub: "99999999".to_string(),
            role: "role_teacher".to_string(),
            email: "t@example.com".to_string(),
            iat: 0,
            exp: 9_999_999_999,
        };
        let result = require_admin(&test_pool(), &claims).await;
        assert!(result.is_err());
    }
}
