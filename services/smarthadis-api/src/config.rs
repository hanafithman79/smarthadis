use std::env;

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub database_url: String,
    pub bind_addr: String,
    pub jwt_secret: String,
    pub jwt_ttl_seconds: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    MissingVar(String),
    WeakSecret,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::MissingVar(name) => {
                write!(f, "missing required environment variable: {name}")
            }
            ConfigError::WeakSecret => {
                write!(f, "JWT_SECRET must be at least 32 characters")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| env::var(k).ok())
    }

    pub fn from_lookup<F>(lookup: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let database_url = lookup("DATABASE_URL")
            .ok_or_else(|| ConfigError::MissingVar("DATABASE_URL".to_string()))?;
        let bind_addr = lookup("BIND_ADDR").unwrap_or_else(|| "127.0.0.1:8001".to_string());
        let jwt_secret = lookup("JWT_SECRET")
            .ok_or_else(|| ConfigError::MissingVar("JWT_SECRET".to_string()))?;
        if jwt_secret.len() < 32 || jwt_secret.to_lowercase().starts_with("changeme") {
            return Err(ConfigError::WeakSecret);
        }
        let jwt_ttl_seconds = lookup("JWT_TTL_SECONDS")
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(43200);
        Ok(Config {
            database_url,
            bind_addr,
            jwt_secret,
            jwt_ttl_seconds,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_SECRET: &str = "test-secret-at-least-32-characters-long";

    fn lookup_with(extra: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |k| extra.iter().find(|(key, _)| *key == k).map(|(_, v)| v.to_string())
    }

    #[test]
    fn from_lookup_returns_config_when_all_required_present() {
        let cfg = Config::from_lookup(lookup_with(&[
            ("DATABASE_URL", "postgres://u:p@localhost/db"),
            ("BIND_ADDR", "0.0.0.0:9000"),
            ("JWT_SECRET", VALID_SECRET),
        ]))
        .unwrap();
        assert_eq!(cfg.database_url, "postgres://u:p@localhost/db");
        assert_eq!(cfg.bind_addr, "0.0.0.0:9000");
        assert_eq!(cfg.jwt_secret, VALID_SECRET);
    }

    #[test]
    fn from_lookup_defaults_bind_addr_when_absent() {
        let cfg = Config::from_lookup(lookup_with(&[
            ("DATABASE_URL", "postgres://u:p@localhost/db"),
            ("JWT_SECRET", VALID_SECRET),
        ]))
        .unwrap();
        assert_eq!(cfg.bind_addr, "127.0.0.1:8001");
    }

    #[test]
    fn from_lookup_defaults_jwt_ttl_seconds_when_absent() {
        let cfg = Config::from_lookup(lookup_with(&[
            ("DATABASE_URL", "postgres://u:p@localhost/db"),
            ("JWT_SECRET", VALID_SECRET),
        ]))
        .unwrap();
        assert_eq!(cfg.jwt_ttl_seconds, 43200);
    }

    #[test]
    fn from_lookup_errors_when_database_url_missing() {
        let result = Config::from_lookup(lookup_with(&[("JWT_SECRET", VALID_SECRET)]));
        assert_eq!(
            result,
            Err(ConfigError::MissingVar("DATABASE_URL".to_string()))
        );
    }

    #[test]
    fn from_lookup_errors_when_jwt_secret_missing() {
        let result = Config::from_lookup(lookup_with(&[(
            "DATABASE_URL",
            "postgres://u:p@localhost/db",
        )]));
        assert_eq!(result, Err(ConfigError::MissingVar("JWT_SECRET".to_string())));
    }

    #[test]
    fn from_lookup_errors_when_jwt_secret_too_short() {
        let result = Config::from_lookup(lookup_with(&[
            ("DATABASE_URL", "postgres://u:p@localhost/db"),
            ("JWT_SECRET", "too-short"),
        ]));
        assert_eq!(result, Err(ConfigError::WeakSecret));
    }

    #[test]
    fn from_lookup_errors_when_jwt_secret_is_the_example_placeholder() {
        // .env.example's placeholder is >=32 chars by design (so copying it
        // verbatim wouldn't trip the length check alone) — reject it by
        // content instead, so a forgotten "changeme" secret fails loudly.
        let result = Config::from_lookup(lookup_with(&[
            ("DATABASE_URL", "postgres://u:p@localhost/db"),
            (
                "JWT_SECRET",
                "changeme-generate-a-real-32-plus-character-secret",
            ),
        ]));
        assert_eq!(result, Err(ConfigError::WeakSecret));
    }
}
