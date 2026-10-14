use sqlx::postgres::{PgPool, PgPoolOptions};

pub async fn create_pool(database_url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(std::time::Duration::from_secs(3))
        .connect(database_url)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn create_pool_connects_with_valid_credentials() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to the rust_svc connection string for this test");
        let pool = create_pool(&database_url).await.expect("pool should connect");
        let row: (i32,) = sqlx::query_as("SELECT 1")
            .fetch_one(&pool)
            .await
            .expect("query should succeed");
        assert_eq!(row.0, 1);
    }

    #[tokio::test]
    async fn create_pool_fails_with_unreachable_host() {
        let result = create_pool("postgres://rust_svc:wrong@127.0.0.1:1/smarthadis40apps").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn create_pool_fails_quickly_with_unreachable_host() {
        let start = std::time::Instant::now();
        let result = create_pool("postgres://rust_svc:wrong@127.0.0.1:1/smarthadis40apps").await;
        let elapsed = start.elapsed();
        assert!(result.is_err());
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "expected failure within 5s, took {elapsed:?}"
        );
    }
}
