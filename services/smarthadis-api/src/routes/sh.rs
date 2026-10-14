use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::AppState;

// Field aliases accept the PostgREST-style `p_`-prefixed keys
// apps/smarthadis40apps/index.html's rpc() calls already send (confirmed
// by reading its fetch calls, e.g. `rpc("sh_masuk", { p_kod: kod })`) —
// so nothing on the frontend needs to change when it's eventually pointed
// at this API, alongside the plain key names used internally/by any
// future client.

#[derive(Debug, Deserialize)]
pub struct MasukRequest {
    #[serde(alias = "p_kod")]
    pub kod: String,
}

#[derive(Debug, Deserialize)]
pub struct DashboardRequest {
    #[serde(alias = "p_kod_guru")]
    pub kod_guru: String,
}

#[derive(Debug, Deserialize)]
pub struct RekodHafazanRequest {
    #[serde(alias = "p_kod")]
    pub kod: String,
    #[serde(alias = "p_hadis")]
    pub hadis: i32,
    #[serde(alias = "p_betul")]
    pub betul: bool,
}

#[derive(Debug, Deserialize)]
pub struct SimpanRefleksiRequest {
    #[serde(alias = "p_kod")]
    pub kod: String,
    #[serde(alias = "p_teks")]
    pub teks: String,
    #[serde(alias = "p_nilai", default)]
    pub nilai: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TambahMisiRequest {
    #[serde(alias = "p_kod")]
    pub kod: String,
    #[serde(alias = "p_hadis")]
    pub hadis: i32,
}

#[derive(Debug, Deserialize)]
pub struct TandaMisiRequest {
    #[serde(alias = "p_kod")]
    pub kod: String,
    #[serde(alias = "p_misi")]
    pub misi: i64,
}

#[derive(Debug, Deserialize)]
pub struct TanyaRequest {
    #[serde(alias = "p_kod")]
    pub kod: String,
    #[serde(alias = "p_soalan")]
    pub soalan: String,
}

pub async fn masuk(
    State(state): State<AppState>,
    Json(body): Json<MasukRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    sqlx::query_scalar::<_, Value>("SELECT sh_masuk($1)")
        .bind(&body.kod)
        .fetch_one(&state.pool)
        .await
        .map(Json)
        .map_err(|e| {
            eprintln!("sh_masuk query failed: {e}");
            server_error()
        })
}

pub async fn dashboard(
    State(state): State<AppState>,
    Json(body): Json<DashboardRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    sqlx::query_scalar::<_, Value>("SELECT sh_dashboard($1)")
        .bind(&body.kod_guru)
        .fetch_one(&state.pool)
        .await
        .map(Json)
        .map_err(|e| {
            eprintln!("sh_dashboard query failed: {e}");
            server_error()
        })
}

pub async fn rekod_hafazan(
    State(state): State<AppState>,
    Json(body): Json<RekodHafazanRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    sqlx::query_scalar::<_, Value>("SELECT sh_rekod_hafazan($1, $2, $3)")
        .bind(&body.kod)
        .bind(body.hadis)
        .bind(body.betul)
        .fetch_one(&state.pool)
        .await
        .map(Json)
        .map_err(|e| {
            eprintln!("sh_rekod_hafazan query failed: {e}");
            server_error()
        })
}

pub async fn simpan_refleksi(
    State(state): State<AppState>,
    Json(body): Json<SimpanRefleksiRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    sqlx::query_scalar::<_, Value>("SELECT sh_simpan_refleksi($1, $2, $3)")
        .bind(&body.kod)
        .bind(&body.teks)
        .bind(&body.nilai)
        .fetch_one(&state.pool)
        .await
        .map(Json)
        .map_err(|e| {
            eprintln!("sh_simpan_refleksi query failed: {e}");
            server_error()
        })
}

pub async fn tambah_misi(
    State(state): State<AppState>,
    Json(body): Json<TambahMisiRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    sqlx::query_scalar::<_, Value>("SELECT sh_tambah_misi($1, $2)")
        .bind(&body.kod)
        .bind(body.hadis)
        .fetch_one(&state.pool)
        .await
        .map(Json)
        .map_err(|e| {
            eprintln!("sh_tambah_misi query failed: {e}");
            server_error()
        })
}

pub async fn tanda_misi(
    State(state): State<AppState>,
    Json(body): Json<TandaMisiRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    sqlx::query_scalar::<_, Value>("SELECT sh_tanda_misi($1, $2)")
        .bind(&body.kod)
        .bind(body.misi)
        .fetch_one(&state.pool)
        .await
        .map(Json)
        .map_err(|e| {
            eprintln!("sh_tanda_misi query failed: {e}");
            server_error()
        })
}

pub async fn tanya(
    State(state): State<AppState>,
    Json(body): Json<TanyaRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    sqlx::query_scalar::<_, Value>("SELECT sh_tanya($1, $2)")
        .bind(&body.kod)
        .bind(&body.soalan)
        .fetch_one(&state.pool)
        .await
        .map(Json)
        .map_err(|e| {
            eprintln!("sh_tanya query failed: {e}");
            server_error()
        })
}

fn server_error() -> (StatusCode, Json<Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"ok": false, "ralat": "server error"})),
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

    async fn post_json(uri: &str, body: Value) -> axum::response::Response {
        let app = super::super::app(test_state());
        app.oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
    }

    async fn assert_ok_false(response: axum::response::Response) {
        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(parsed["ok"], false);
        assert!(parsed["ralat"].as_str().is_some());
    }

    #[tokio::test]
    async fn sh_masuk_rejects_unknown_kod() {
        let response = post_json("/sh/masuk", json!({"kod": "NOT-A-REAL-KOD-XYZ"})).await;
        assert_ok_false(response).await;
    }

    #[tokio::test]
    async fn sh_masuk_accepts_the_frontend_s_p_kod_key() {
        // apps/smarthadis40apps/index.html's rpc() calls send PostgREST-style
        // p_-prefixed keys (confirmed by reading its fetch calls directly:
        // `rpc("sh_masuk", { p_kod: kod })`), not the bare "kod" this crate
        // used internally — both must work so nothing needs to change on
        // the frontend side when it's eventually pointed at this API.
        let response = post_json("/sh/masuk", json!({"p_kod": "NOT-A-REAL-KOD-XYZ"})).await;
        assert_ok_false(response).await;
    }

    #[tokio::test]
    async fn sh_masuk_rejects_missing_kod_field() {
        let response = post_json("/sh/masuk", json!({})).await;
        assert!(response.status().is_client_error());
    }

    #[tokio::test]
    async fn sh_tambah_misi_rejects_wrong_field_type() {
        // "hadis" must be an integer (matches sh_tambah_misi's `p_hadis
        // integer` parameter) — a string must 400 before ever reaching SQL,
        // not get coerced or crash the handler.
        let response = post_json(
            "/sh/tambah_misi",
            json!({"kod": "NOT-A-REAL-KOD-XYZ", "hadis": "not-a-number"}),
        )
        .await;
        assert!(response.status().is_client_error());
    }

    #[tokio::test]
    async fn sh_dashboard_rejects_unknown_kod_guru() {
        let response = post_json(
            "/sh/dashboard",
            json!({"kod_guru": "NOT-A-REAL-KOD-GURU-XYZ"}),
        )
        .await;
        assert_ok_false(response).await;
    }

    #[tokio::test]
    async fn sh_rekod_hafazan_rejects_unknown_kod() {
        let response = post_json(
            "/sh/rekod_hafazan",
            json!({"kod": "NOT-A-REAL-KOD-XYZ", "hadis": 1, "betul": true}),
        )
        .await;
        assert_ok_false(response).await;
    }

    #[tokio::test]
    async fn sh_simpan_refleksi_rejects_unknown_kod() {
        let response = post_json(
            "/sh/simpan_refleksi",
            json!({"kod": "NOT-A-REAL-KOD-XYZ", "teks": "hello there friend"}),
        )
        .await;
        assert_ok_false(response).await;
    }

    #[tokio::test]
    async fn sh_tambah_misi_rejects_unknown_kod() {
        let response = post_json(
            "/sh/tambah_misi",
            json!({"kod": "NOT-A-REAL-KOD-XYZ", "hadis": 1}),
        )
        .await;
        assert_ok_false(response).await;
    }

    #[tokio::test]
    async fn sh_tanda_misi_rejects_unknown_kod() {
        let response = post_json(
            "/sh/tanda_misi",
            json!({"kod": "NOT-A-REAL-KOD-XYZ", "misi": 1}),
        )
        .await;
        assert_ok_false(response).await;
    }

    #[tokio::test]
    async fn sh_tanya_rejects_unknown_kod() {
        let response = post_json(
            "/sh/tanya",
            json!({"kod": "NOT-A-REAL-KOD-XYZ", "soalan": "apa itu solat?"}),
        )
        .await;
        assert_ok_false(response).await;
    }
}
