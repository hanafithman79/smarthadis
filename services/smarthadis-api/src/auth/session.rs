use sqlx::{PgPool, Postgres, Transaction};

pub async fn begin_with_role(
    pool: &PgPool,
    role: &str,
) -> Result<Transaction<'static, Postgres>, sqlx::Error> {
    let role_sql: &str = match role {
        "role_admin" => "SET LOCAL ROLE role_admin",
        "role_teacher" => "SET LOCAL ROLE role_teacher",
        "role_parent" => "SET LOCAL ROLE role_parent",
        "web_anon" => "SET LOCAL ROLE web_anon",
        other => {
            return Err(sqlx::Error::Configuration(
                format!("unknown role: {other}").into(),
            ))
        }
    };
    let mut tx = pool.begin().await?;
    sqlx::query(role_sql).execute(&mut *tx).await?;
    Ok(tx)
}

pub async fn set_jwt_claims(
    tx: &mut Transaction<'static, Postgres>,
    claims_json: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT set_config('request.jwt.claims', $1, true)")
        .bind(claims_json)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_database_url() -> String {
        std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to the rust_svc connection string for this test")
    }

    #[tokio::test]
    async fn begin_with_role_switches_current_user() {
        let pool = crate::db::create_pool(&test_database_url())
            .await
            .expect("pool should connect");
        let mut tx = begin_with_role(&pool, "role_admin")
            .await
            .expect("should begin with role");
        let (current_user,): (String,) = sqlx::query_as("SELECT current_user::text")
            .fetch_one(&mut *tx)
            .await
            .expect("query should succeed");
        assert_eq!(current_user, "role_admin");
        tx.rollback().await.expect("rollback should succeed");
    }

    #[tokio::test]
    async fn begin_with_role_actually_restricts_privileges_not_just_current_user() {
        // Proves the role switch changes real privileges, not just the
        // current_user display name: role_admin has no grant on murid
        // (confirmed via information_schema.role_table_grants — 0 rows for
        // role_admin/teacher/parent), so a query against it must fail.
        let pool = crate::db::create_pool(&test_database_url())
            .await
            .expect("pool should connect");
        let mut tx = begin_with_role(&pool, "role_admin")
            .await
            .expect("should begin with role");
        let result = sqlx::query("SELECT 1 FROM murid LIMIT 1")
            .execute(&mut *tx)
            .await;
        assert!(result.is_err());
        tx.rollback().await.expect("rollback should succeed");
    }

    #[tokio::test]
    async fn begin_with_role_rejects_role_not_in_allow_list() {
        let pool = crate::db::create_pool(&test_database_url())
            .await
            .expect("pool should connect");
        let result = begin_with_role(&pool, "postgres").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn begin_with_role_rejects_sql_injection_attempt() {
        let pool = crate::db::create_pool(&test_database_url())
            .await
            .expect("pool should connect");
        let result = begin_with_role(&pool, "role_admin; DROP TABLE account;--").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn set_jwt_claims_is_readable_via_current_setting() {
        let pool = crate::db::create_pool(&test_database_url())
            .await
            .expect("pool should connect");
        let mut tx = begin_with_role(&pool, "role_admin")
            .await
            .expect("should begin with role");
        set_jwt_claims(&mut tx, r#"{"role":"role_admin","sub":"1"}"#)
            .await
            .expect("should set claims");
        let (claims,): (String,) =
            sqlx::query_as("SELECT current_setting('request.jwt.claims', true)")
                .fetch_one(&mut *tx)
                .await
                .expect("query should succeed");
        assert_eq!(claims, r#"{"role":"role_admin","sub":"1"}"#);
        tx.rollback().await.expect("rollback should succeed");
    }
}
