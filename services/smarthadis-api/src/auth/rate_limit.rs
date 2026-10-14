use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Fixed-window per-key request counter. One shared instance is applied
/// to every weak-secret credential-checking route (/login/murid,
/// /change-password, /login/password) so an attacker can't dodge the
/// limit by switching which endpoint they hit from the same IP.
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<HashMap<String, Window>>>,
    max_requests: u32,
    window: Duration,
}

struct Window {
    count: u32,
    started_at: Instant,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window,
        }
    }

    /// Returns true if this request is allowed, false if the key has
    /// exceeded max_requests within the current window.
    fn check(&self, key: &str) -> bool {
        let mut map = self.inner.lock().expect("rate limiter mutex poisoned");
        let now = Instant::now();
        let entry = map.entry(key.to_string()).or_insert_with(|| Window {
            count: 0,
            started_at: now,
        });
        if now.duration_since(entry.started_at) > self.window {
            entry.count = 0;
            entry.started_at = now;
        }
        entry.count += 1;
        entry.count <= self.max_requests
    }
}

/// Keyed by the client's real IP as Caddy reports it via
/// X-Forwarded-For — the Rust process always sees connections FROM
/// Caddy (127.0.0.1), never the real client, since Caddy reverse-proxies
/// every request. Falls back to a single shared "unknown" bucket when
/// the header is absent (local/test traffic without a proxy in front) —
/// production traffic always has Caddy in front, which sets this header
/// unconditionally.
fn client_key(req: &Request) -> String {
    req.headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

pub async fn rate_limit(State(limiter): State<RateLimiter>, req: Request, next: Next) -> Response {
    let key = client_key(&req);
    if !limiter.check(&key) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "too many requests, try again later"})),
        )
            .into_response();
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_requests_up_to_the_limit() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));
        assert!(limiter.check("1.2.3.4"));
        assert!(limiter.check("1.2.3.4"));
        assert!(limiter.check("1.2.3.4"));
    }

    #[test]
    fn rejects_requests_beyond_the_limit_within_the_window() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));
        assert!(limiter.check("1.2.3.4"));
        assert!(limiter.check("1.2.3.4"));
        assert!(limiter.check("1.2.3.4"));
        assert!(!limiter.check("1.2.3.4"));
    }

    #[test]
    fn tracks_different_keys_independently() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        assert!(limiter.check("1.1.1.1"));
        assert!(limiter.check("2.2.2.2"));
        assert!(!limiter.check("1.1.1.1"));
        assert!(!limiter.check("2.2.2.2"));
    }

    #[test]
    fn resets_the_window_after_it_elapses() {
        let limiter = RateLimiter::new(1, Duration::from_millis(50));
        assert!(limiter.check("1.2.3.4"));
        assert!(!limiter.check("1.2.3.4"));
        std::thread::sleep(Duration::from_millis(60));
        assert!(limiter.check("1.2.3.4"));
    }

    #[test]
    fn client_key_reads_first_entry_of_x_forwarded_for() {
        let req = Request::builder()
            .header("x-forwarded-for", "9.8.7.6, 127.0.0.1")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(client_key(&req), "9.8.7.6");
    }

    #[test]
    fn client_key_falls_back_to_unknown_without_the_header() {
        let req = Request::builder().body(axum::body::Body::empty()).unwrap();
        assert_eq!(client_key(&req), "unknown");
    }
}
