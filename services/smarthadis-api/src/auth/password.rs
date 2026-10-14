use bcrypt::{hash, verify, DEFAULT_COST};
use rand::Rng;

/// A real, valid, cost-12 bcrypt hash of a random UUID whose plaintext was
/// never stored anywhere — used by every login handler as the comparison
/// target for an unknown/not-yet-provisioned identifier, so the bcrypt
/// step always runs at the same cost regardless of whether the identifier
/// is real. This is the entire non-enumeration defense; see
/// `dummy_hash_is_valid_and_matches_default_cost` below.
pub const DUMMY_HASH: &str = "$2a$12$qavSGCDHpxTvX07F/ffTvOjhNqIBJA/whi8b8zKLsayk17opuNEoS";

pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    hash(password, DEFAULT_COST)
}

pub fn verify_password(password: &str, password_hash: &str) -> bool {
    verify(password, password_hash).unwrap_or(false)
}

/// A random 6-digit PIN, for students — short enough for a young child
/// to read and type from a printed slip. Shared by provision_accounts
/// (bulk) and the admin reset-password route (one at a time), so there
/// is exactly one implementation of "what a student's temp credential
/// looks like".
pub fn generate_student_pin() -> String {
    let mut rng = rand::thread_rng();
    format!("{:06}", rng.gen_range(0..1_000_000))
}

const TEACHER_PASSWORD_CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

/// A random 8-character alphanumeric password, for teachers.
pub fn generate_teacher_password() -> String {
    let mut rng = rand::thread_rng();
    (0..8)
        .map(|_| TEACHER_PASSWORD_CHARSET[rng.gen_range(0..TEACHER_PASSWORD_CHARSET.len())] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn student_pin_is_exactly_six_digits() {
        for _ in 0..100 {
            let pin = generate_student_pin();
            assert_eq!(pin.len(), 6);
            assert!(pin.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn student_pins_have_no_collision_within_a_batch_of_527() {
        let pins: HashSet<String> = (0..527).map(|_| generate_student_pin()).collect();
        assert_eq!(pins.len(), 527, "expected 527 unique PINs, got a collision");
    }

    #[test]
    fn teacher_password_is_exactly_eight_chars_from_the_charset() {
        for _ in 0..100 {
            let pw = generate_teacher_password();
            assert_eq!(pw.chars().count(), 8);
            assert!(pw.bytes().all(|b| TEACHER_PASSWORD_CHARSET.contains(&b)));
        }
    }

    #[test]
    fn teacher_passwords_have_no_collision_within_a_batch_of_43() {
        let pws: HashSet<String> = (0..43).map(|_| generate_teacher_password()).collect();
        assert_eq!(pws.len(), 43, "expected 43 unique passwords, got a collision");
    }

    // Generated via `SELECT crypt('hunter2-test-password', gen_salt('bf', 12));`
    // on the production server's pgcrypto — proves Rust's bcrypt crate can
    // read hashes Postgres produced for the existing admin/teacher/parent
    // accounts, without needing a live DB connection for this test.
    const PGCRYPTO_HASH: &str = "$2a$12$RBqtSNSbUjFk2Ifmw20tZOBvuWjyZYs3R56YpjYXYHTLTfxSZvme6";
    const PGCRYPTO_PASSWORD: &str = "hunter2-test-password";

    #[test]
    fn hash_then_verify_round_trips() {
        let hashed = hash_password("hunter2").expect("hash should succeed");
        assert!(verify_password("hunter2", &hashed));
        assert!(!verify_password("wrong", &hashed));
    }

    #[test]
    fn verify_password_accepts_a_postgres_generated_hash() {
        assert!(verify_password(PGCRYPTO_PASSWORD, PGCRYPTO_HASH));
    }

    #[test]
    fn verify_password_rejects_wrong_password_against_postgres_hash() {
        assert!(!verify_password("wrong-password", PGCRYPTO_HASH));
    }

    #[test]
    fn verify_password_returns_false_not_panic_on_malformed_hash() {
        assert!(!verify_password("anything", "not-a-real-bcrypt-hash"));
    }

    #[test]
    fn dummy_hash_is_valid_and_matches_default_cost() {
        // The whole timing-safe non-enumeration defense in login_password
        // and login_murid rests on this constant being a real, correctly
        // costed bcrypt hash — if it were ever malformed (it was mistyped
        // once during this project, caught before deploy), verify_password
        // would return false in microseconds instead of ~300ms, turning
        // the "unknown identifier" path into a timing oracle.
        assert!(bcrypt::verify("x", super::DUMMY_HASH).is_ok());
        assert!(super::DUMMY_HASH.starts_with(&format!("$2a${:02}$", DEFAULT_COST)));
    }
}
