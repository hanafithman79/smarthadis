use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub role: String,
    pub email: String,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Debug)]
pub enum TokenError {
    Invalid,
}

pub fn issue(secret: &str, account_id: i64, role: &str, email: &str, ttl_seconds: i64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_secs() as i64;
    let claims = TokenClaims {
        sub: account_id.to_string(),
        role: role.to_string(),
        email: email.to_string(),
        iat: now,
        exp: now + ttl_seconds,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("encoding a well-formed TokenClaims cannot fail")
}

pub fn verify(secret: &str, token: &str) -> Result<TokenClaims, TokenError> {
    let validation = Validation::new(Algorithm::HS256);
    decode::<TokenClaims>(token, &DecodingKey::from_secret(secret.as_bytes()), &validation)
        .map(|data| data.claims)
        .map_err(|_| TokenError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret-at-least-32-characters-long";

    #[test]
    fn issue_then_verify_round_trips_claims() {
        let token = issue(SECRET, 42, "role_admin", "a@example.com", 3600);
        let claims = verify(SECRET, &token).expect("should verify");
        assert_eq!(claims.sub, "42");
        assert_eq!(claims.role, "role_admin");
        assert_eq!(claims.email, "a@example.com");
    }

    #[test]
    fn verify_rejects_expired_token() {
        // -120s comfortably exceeds jsonwebtoken's default 60s leeway for
        // clock skew — -1s alone is still accepted as "recently expired".
        let token = issue(SECRET, 42, "role_admin", "a@example.com", -120);
        assert!(verify(SECRET, &token).is_err());
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let token = issue(SECRET, 42, "role_admin", "a@example.com", 3600);
        let wrong_secret = "a-different-secret-also-32-chars-plus";
        assert!(verify(wrong_secret, &token).is_err());
    }

    #[test]
    fn verify_rejects_garbage_token() {
        assert!(verify(SECRET, "not-a-jwt-at-all").is_err());
    }

    fn encode_raw_claims(fields: serde_json::Value) -> String {
        encode(
            &Header::new(Algorithm::HS256),
            &fields,
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .expect("encoding well-formed JSON cannot fail")
    }

    #[test]
    fn verify_rejects_token_missing_sub() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let token = encode_raw_claims(serde_json::json!({
            "role": "role_admin",
            "email": "a@example.com",
            "iat": now,
            "exp": now + 3600,
        }));
        assert!(verify(SECRET, &token).is_err());
    }

    #[test]
    fn verify_rejects_token_missing_role() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let token = encode_raw_claims(serde_json::json!({
            "sub": "42",
            "email": "a@example.com",
            "iat": now,
            "exp": now + 3600,
        }));
        assert!(verify(SECRET, &token).is_err());
    }

    #[test]
    fn verify_rejects_token_missing_email() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let token = encode_raw_claims(serde_json::json!({
            "sub": "42",
            "role": "role_admin",
            "iat": now,
            "exp": now + 3600,
        }));
        assert!(verify(SECRET, &token).is_err());
    }

    #[test]
    fn verify_rejects_token_missing_exp() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let token = encode_raw_claims(serde_json::json!({
            "sub": "42",
            "role": "role_admin",
            "email": "a@example.com",
            "iat": now,
        }));
        assert!(verify(SECRET, &token).is_err());
    }
}
