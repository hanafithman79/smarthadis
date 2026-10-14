use smarthadis_api::{config::Config, db, routes, AppState};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let cfg = Config::from_env().unwrap_or_else(|e| {
        eprintln!("startup failed: {e}");
        std::process::exit(1);
    });

    let pool = db::create_pool(&cfg.database_url)
        .await
        .unwrap_or_else(|e| {
            eprintln!("startup failed: could not connect to database: {e}");
            std::process::exit(1);
        });

    let state = AppState {
        pool,
        jwt_secret: cfg.jwt_secret.clone(),
        jwt_ttl_seconds: cfg.jwt_ttl_seconds,
    };

    let app = routes::app(state);

    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("startup failed: could not bind {}: {e}", cfg.bind_addr);
            std::process::exit(1);
        });

    println!("listening on {}", cfg.bind_addr);
    axum::serve(listener, app).await.unwrap();
}
