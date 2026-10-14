use smarthadis_api::auth::password::{self, generate_student_pin, generate_teacher_password};
use sqlx::postgres::PgPoolOptions;
use std::fs;
use std::path::Path;

/// Real teacher IC numbers are personal data (PDPA-regulated) — never
/// hardcoded in committed source. Read at runtime instead from a
/// `provisioning-data/` directory (gitignored via
/// `services/smarthadis-api/.gitignore`) that the operator populates
/// server-side before running this binary; it does not exist in the repo.
/// This was fixed during this plan's final review, after the data was
/// briefly committed directly in this file — see the execution ledger for
/// the incident.
///
/// File `guru-class-assignments.tsv`: one line per teacher,
/// `ic<TAB>id1,id2,id3`. kelas.id decode: 1F=5 1K=6 1M=7 2F=8 2K=9 2M=10
/// 3F=11 3K=12 3M=13 4F=14 4K=15 4M=16 5F=17 5K=18 5M=19 6F=1 6K=20 6M=21
/// 6N=22 PRA 1=23 PRA 2=24 (see docs/superpowers/specs/2026-10-03-ic-
/// password-bulk-provisioning-design.md for how this mapping was derived).
///
/// File `new-teacher.tsv` (optional): one line, `nama<TAB>ic`, for a
/// teacher missing from `guru` entirely — see `load_new_teacher` below.
/// Absent on every run after the teacher it was written for already
/// exists.
fn load_guru_class_assignments(path: &str) -> Vec<(String, Vec<i64>)> {
    let content = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("should read guru-class-assignments data file at {path}: {e}"));
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let mut parts = line.splitn(2, '\t');
            let ic = parts
                .next()
                .expect("each line should have an ic field")
                .trim()
                .to_string();
            let ids: Vec<i64> = parts
                .next()
                .expect("each line should have a kelas-id field")
                .split(',')
                .map(|s| s.trim().parse().expect("kelas id should be a valid integer"))
                .collect();
            (ic, ids)
        })
        .collect()
}

/// (nama, ic) for a teacher not yet in `guru` — one optional line,
/// `nama<TAB>ic`, in a gitignored file. Returns `None` if the file is
/// absent (the normal case for every run after the teacher this was
/// originally written for has already been added — see
/// `ensure_new_guru_row_exists`, which is a no-op once that row exists).
fn load_new_teacher(path: &str) -> Option<(String, String)> {
    let content = fs::read_to_string(path).ok()?;
    let line = content.lines().find(|l| !l.trim().is_empty())?;
    let mut parts = line.splitn(2, '\t');
    let nama = parts.next()?.trim().to_string();
    let ic = parts.next()?.trim().to_string();
    Some((nama, ic))
}

#[tokio::main]
async fn main() {
    let database_url = std::env::var("PROVISION_DATABASE_URL")
        .expect("set PROVISION_DATABASE_URL to the smarthadis40apps owner connection string");
    let output_dir = std::env::var("PROVISION_OUTPUT_DIR")
        .unwrap_or_else(|_| "/opt/smarthadis-api/provisioning-output".to_string());

    let guru_class_path = std::env::var("PROVISION_GURU_CLASS_FILE")
        .unwrap_or_else(|_| "provisioning-data/guru-class-assignments.tsv".to_string());
    let new_teacher_path = std::env::var("PROVISION_NEW_TEACHER_FILE")
        .unwrap_or_else(|_| "provisioning-data/new-teacher.tsv".to_string());

    ensure_output_dir_writable(&output_dir);

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("should connect as the smarthadis40apps owner role");

    ensure_new_guru_row_exists(&pool, &new_teacher_path).await;
    let student_slips = provision_students(&pool, &output_dir).await;
    let teacher_slips = provision_teachers(&pool, &output_dir).await;
    provision_guru_class(&pool, &guru_class_path).await;

    println!(
        "provisioned {} students, {} teachers. Slip files written to {output_dir}",
        student_slips.len(),
        teacher_slips.len()
    );

    verify_sample(&student_slips, &teacher_slips).await;
}

/// Only 1 `account` row exists today (the admin), confirmed live — none of
/// the 42 existing `guru` rows have a matching `account` row yet, so
/// `provision_teachers` below creates one for every teacher via
/// `placeholder_email`, not just the newly added one. This function only
/// ensures a missing `guru` row exists before that runs, and is a no-op
/// once `new-teacher.tsv` is absent or that row already exists — true for
/// every run after the one this was originally written for.
async fn ensure_new_guru_row_exists(pool: &sqlx::PgPool, new_teacher_path: &str) {
    let Some((nama, ic)) = load_new_teacher(new_teacher_path) else {
        return;
    };
    let existing: Option<i64> = sqlx::query_scalar("SELECT id FROM guru WHERE ic = $1")
        .bind(&ic)
        .fetch_optional(pool)
        .await
        .expect("guru lookup should succeed");
    if existing.is_some() {
        return;
    }
    sqlx::query("INSERT INTO guru (nama, ic) VALUES ($1, $2)")
        .bind(&nama)
        .bind(&ic)
        .execute(pool)
        .await
        .expect("guru insert should succeed");
}

/// No real teacher has an email on file (guru only has nama+ic) — every
/// teacher's `account` row uses this same non-routable placeholder
/// convention, not just the newly added teacher's. They all log in by ic,
/// so the placeholder is never user-facing.
fn placeholder_email(nama: &str, ic: &str) -> String {
    let slug: String = nama
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '.' })
        .collect();
    let slug = slug
        .split('.')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(".");
    format!("{slug}.{ic}@smarthadis.invalid")
}

struct StudentSlip {
    // kelas_id/nama are written to disk immediately by append_slip_line's
    // caller and never read back off this struct — only ic/pin feed
    // verify_sample afterward. Kept on the struct anyway since they were
    // already available at construction and cost nothing to carry.
    #[allow(dead_code)]
    kelas_id: i64,
    #[allow(dead_code)]
    nama: String,
    ic: String,
    pin: String,
}

async fn provision_students(pool: &sqlx::PgPool, output_dir: &str) -> Vec<StudentSlip> {
    #[derive(sqlx::FromRow)]
    struct Eligible {
        id: i64,
        kelas_id: i64,
        nama: String,
        ic: String,
    }

    let eligible: Vec<Eligible> = sqlx::query_as(
        "SELECT id, kelas_id, nama, ic FROM murid WHERE ic IS NOT NULL AND password_hash IS NULL",
    )
    .fetch_all(pool)
    .await
    .expect("eligible-student query should succeed");

    let mut slips = Vec::with_capacity(eligible.len());
    for row in eligible {
        if let Some(pin) = provision_one_student(pool, row.id).await {
            // Written immediately, not batched to the end — a crash later
            // in this run (e.g. mid-way through the remaining students, or
            // in provision_teachers) must not lose plaintext for rows
            // already committed to the database. See this plan's
            // execution ledger for the incident this fixes: an earlier
            // version wrote all slip files only at the very end, and a
            // permission error there lost ~541 real passwords that had
            // already been hashed and saved.
            append_slip_line(
                output_dir,
                &format!("kelas-{}-slips.txt", row.kelas_id),
                &row.nama,
                &row.ic,
                &pin,
            );
            slips.push(StudentSlip {
                kelas_id: row.kelas_id,
                nama: row.nama,
                ic: row.ic,
                pin,
            });
        }
    }
    slips
}

/// Sets a fresh PIN for exactly one `murid` row, scoped to that row's id —
/// factored out of `provision_students` so the idempotency guarantee
/// (re-running this against the same id never overwrites an already-set
/// password) can be tested against a single disposable fixture, without
/// ever scanning or touching the real, unscoped eligible-rows query.
/// Returns `None` (and leaves the row untouched) if the row already had a
/// password — the idempotent no-op path.
async fn provision_one_student(pool: &sqlx::PgPool, murid_id: i64) -> Option<String> {
    let pin = generate_student_pin();
    let hash = password::hash_password(&pin).expect("hash should succeed");
    let result = sqlx::query(
        "UPDATE murid SET password_hash = $1, must_change_password = true WHERE id = $2 AND password_hash IS NULL",
    )
    .bind(&hash)
    .bind(murid_id)
    .execute(pool)
    .await
    .expect("murid password update should succeed");
    if result.rows_affected() == 1 {
        Some(pin)
    } else {
        None
    }
}

struct TeacherSlip {
    #[allow(dead_code)]
    nama: String,
    ic: String,
    password: String,
}

async fn provision_teachers(pool: &sqlx::PgPool, output_dir: &str) -> Vec<TeacherSlip> {
    #[derive(sqlx::FromRow)]
    struct GuruRow {
        nama: String,
        ic: String,
    }

    let all_guru: Vec<GuruRow> = sqlx::query_as("SELECT nama, ic FROM guru")
        .fetch_all(pool)
        .await
        .expect("guru query should succeed");

    let mut slips = Vec::with_capacity(all_guru.len());
    for guru in all_guru {
        let account_id = ensure_teacher_account_exists(pool, &guru.nama, &guru.ic).await;

        // rows_affected() == 1, not a separate SELECT-then-UPDATE: the
        // prior version checked password_hash IS NULL in one query then
        // set it in another, which is a TOCTOU race if this script is
        // ever run concurrently — the UPDATE's own WHERE clause is the
        // only atomic check, matching provision_one_student's pattern.
        let password = generate_teacher_password();
        let hash = password::hash_password(&password).expect("hash should succeed");
        let result = sqlx::query(
            "UPDATE account SET password_hash = $1, must_change_password = true WHERE id = $2 AND password_hash IS NULL",
        )
        .bind(&hash)
        .bind(account_id)
        .execute(pool)
        .await
        .expect("account password update should succeed");

        if result.rows_affected() != 1 {
            continue;
        }

        append_slip_line(output_dir, "teacher-slips.txt", &guru.nama, &guru.ic, &password);
        slips.push(TeacherSlip {
            nama: guru.nama,
            ic: guru.ic,
            password,
        });
    }
    slips
}

/// Finds the `account` row for a teacher by `ic`, or creates one (role
/// `teacher`, a placeholder email, `aktif = true`) if none exists yet —
/// confirmed live that none of the 42 pre-existing `guru` rows have a
/// matching `account` row today. Returns the account's id either way.
async fn ensure_teacher_account_exists(pool: &sqlx::PgPool, nama: &str, ic: &str) -> i64 {
    let existing: Option<i64> = sqlx::query_scalar("SELECT id FROM account WHERE ic = $1")
        .bind(ic)
        .fetch_optional(pool)
        .await
        .expect("account lookup should succeed");
    if let Some(id) = existing {
        return id;
    }
    let email = placeholder_email(nama, ic);
    sqlx::query_scalar(
        "INSERT INTO account (nama, email, role, ic, aktif) VALUES ($1, $2, 'teacher', $3, true) RETURNING id",
    )
    .bind(nama)
    .bind(&email)
    .bind(ic)
    .fetch_one(pool)
    .await
    .expect("account insert should succeed")
}

async fn provision_guru_class(pool: &sqlx::PgPool, guru_class_path: &str) {
    let assignments = load_guru_class_assignments(guru_class_path);
    for (ic, kelas_ids) in &assignments {
        let account_id: Option<i64> = sqlx::query_scalar("SELECT id FROM account WHERE ic = $1")
            .bind(ic.as_str())
            .fetch_optional(pool)
            .await
            .expect("account lookup should succeed");
        let Some(account_id) = account_id else {
            eprintln!("WARNING: no account found for guru.ic {ic}, skipping guru_class rows");
            continue;
        };
        for kelas_id in kelas_ids {
            sqlx::query(
                "INSERT INTO guru_class (account_id, kelas_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            )
            .bind(account_id)
            .bind(*kelas_id)
            .execute(pool)
            .await
            .expect("guru_class insert should succeed");
        }
    }
}

/// Creates `output_dir` (mode 0700) and proves it's actually writable by
/// this process — writing and deleting a probe file — before any database
/// mutation happens. The prior version only discovered a permission
/// problem at the very end (in the function this replaced), by which
/// point real passwords had already been committed to the database with
/// no record of their plaintext. Failing loudly here, first, is cheap;
/// losing already-committed plaintext is not.
fn ensure_output_dir_writable(output_dir: &str) {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(output_dir)
        .expect("should create output directory");
    let probe = Path::new(output_dir).join(".write-probe");
    fs::write(&probe, "probe").unwrap_or_else(|e| {
        panic!("output directory {output_dir} exists but is not writable by this process: {e}")
    });
    fs::remove_file(&probe).ok();
}

/// Appends one slip line to `filename` inside `output_dir`, creating the
/// file (mode 0600) on first write, flushing and fsync'ing before
/// returning — called immediately after the row it describes is
/// committed to the database, never batched. See `provision_students` and
/// `provision_teachers`' call sites for why.
fn append_slip_line(output_dir: &str, filename: &str, nama: &str, ic: &str, secret: &str) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let path = Path::new(output_dir).join(filename);
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)
        .unwrap_or_else(|e| panic!("should open slip file {}: {e}", path.display()));
    writeln!(file, "{nama}\t{ic}\t{secret}").expect("should write slip line");
    file.sync_all().expect("should fsync slip file");
}

async fn verify_sample(students: &[StudentSlip], teachers: &[TeacherSlip]) {
    let base_url = std::env::var("PROVISION_API_BASE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8001".to_string());
    let client = reqwest::Client::new();

    let mut student_pass = 0;
    let mut student_total = 0;
    for slip in students.iter().take(3) {
        student_total += 1;
        let resp = client
            .post(format!("{base_url}/login/murid"))
            .json(&serde_json::json!({"ic": slip.ic, "password": slip.pin}))
            .send()
            .await;
        if matches!(&resp, Ok(r) if r.status().is_success()) {
            student_pass += 1;
        }
    }

    let mut teacher_pass = 0;
    let mut teacher_total = 0;
    let mut dashboard_pass = 0;
    for slip in teachers.iter().take(3) {
        teacher_total += 1;
        let resp = client
            .post(format!("{base_url}/login/password"))
            .json(&serde_json::json!({"identifier": slip.ic, "password": slip.password}))
            .send()
            .await;
        match resp {
            Ok(r) if r.status().is_success() => {
                teacher_pass += 1;
                if let Some(cookie) = r.headers().get("set-cookie") {
                    let cookie_value = cookie.to_str().unwrap_or("").split(';').next().unwrap_or("");
                    let dash = client
                        .get(format!("{base_url}/dashboard"))
                        .header("cookie", cookie_value)
                        .send()
                        .await;
                    if matches!(&dash, Ok(r) if r.status().is_success()) {
                        dashboard_pass += 1;
                    }
                }
            }
            _ => {}
        }
    }

    println!(
        "self-verification: students {student_pass}/{student_total} logged in; teachers {teacher_pass}/{teacher_total} logged in; {dashboard_pass}/{teacher_total} dashboards loaded"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp_file(contents: &str) -> String {
        let path = std::env::temp_dir().join(format!(
            "provision-accounts-test-{}.tsv",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, contents).expect("should write temp file");
        path.to_str().unwrap().to_string()
    }

    #[test]
    fn load_guru_class_assignments_parses_ic_and_kelas_id_list() {
        // Synthetic data only — real teacher ICs are never committed to
        // source or embedded in a test (see this function's own doc
        // comment for why).
        let path = write_temp_file("111111111111\t5,6,7\n222222222222\t8\n");
        let result = load_guru_class_assignments(&path);
        assert_eq!(
            result,
            vec![
                ("111111111111".to_string(), vec![5, 6, 7]),
                ("222222222222".to_string(), vec![8]),
            ]
        );
        fs::remove_file(&path).ok();
    }

    #[test]
    fn load_guru_class_assignments_skips_blank_lines() {
        let path = write_temp_file("111111111111\t5\n\n222222222222\t6\n");
        let result = load_guru_class_assignments(&path);
        assert_eq!(result.len(), 2);
        fs::remove_file(&path).ok();
    }

    #[test]
    fn load_new_teacher_parses_nama_and_ic() {
        let path = write_temp_file("Test Teacher\t333333333333\n");
        let result = load_new_teacher(&path);
        assert_eq!(result, Some(("Test Teacher".to_string(), "333333333333".to_string())));
        fs::remove_file(&path).ok();
    }

    #[test]
    fn load_new_teacher_returns_none_when_file_absent() {
        let result = load_new_teacher("/nonexistent/path/does-not-exist.tsv");
        assert_eq!(result, None);
    }

    fn temp_output_dir() -> String {
        let path = std::env::temp_dir().join(format!(
            "provision-accounts-test-dir-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        path.to_str().unwrap().to_string()
    }

    #[test]
    fn append_slip_line_persists_immediately_and_appends_without_clobbering() {
        let dir = temp_output_dir();
        ensure_output_dir_writable(&dir);

        append_slip_line(&dir, "test-slips.txt", "Student One", "111111111111", "123456");
        let after_first = fs::read_to_string(Path::new(&dir).join("test-slips.txt")).unwrap();
        assert_eq!(after_first, "Student One\t111111111111\t123456\n");

        append_slip_line(&dir, "test-slips.txt", "Student Two", "222222222222", "654321");
        let after_second = fs::read_to_string(Path::new(&dir).join("test-slips.txt")).unwrap();
        assert_eq!(
            after_second,
            "Student One\t111111111111\t123456\nStudent Two\t222222222222\t654321\n"
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ensure_output_dir_writable_creates_a_mode_0700_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_output_dir();
        ensure_output_dir_writable(&dir);
        let mode = fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        fs::remove_dir_all(&dir).ok();
    }

    // generate_student_pin/generate_teacher_password now live in, and are
    // tested by, auth::password — shared with the admin reset-password
    // route, no longer duplicated here.
}

#[cfg(test)]
mod idempotency_tests {
    use super::*;

    fn test_db_url() -> String {
        std::env::var("TEST_SETUP_DATABASE_URL").expect(
            "set TEST_SETUP_DATABASE_URL to the smarthadis40apps owner connection string for this test",
        )
    }

    fn suffix() -> String {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .to_string()
    }

    async fn create_disposable_murid() -> i64 {
        let pool = PgPoolOptions::new().connect(&test_db_url()).await.unwrap();
        let s = suffix();
        let ic = format!("9{s}");
        let kod = format!("TEST-KOD-{s}");
        sqlx::query_scalar(
            "INSERT INTO murid (kelas_id, nama, kod, ic) VALUES (3, 'Idempotency Test', $1, $2) RETURNING id",
        )
        .bind(&kod)
        .bind(&ic)
        .fetch_one(&pool)
        .await
        .expect("insert should succeed")
    }

    async fn cleanup_murid(id: i64) {
        let pool = PgPoolOptions::new().connect(&test_db_url()).await.unwrap();
        sqlx::query("DELETE FROM murid WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .expect("cleanup should succeed");
    }

    async fn current_hash(pool: &sqlx::PgPool, id: i64) -> Option<String> {
        sqlx::query_scalar("SELECT password_hash FROM murid WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("select should succeed")
    }

    #[tokio::test]
    async fn provisioning_the_same_student_twice_does_not_change_the_first_password() {
        // Scoped to a single disposable fixture id, never the unscoped
        // eligible-rows query — this must never run against real murid
        // rows (see Global Constraints).
        let pool = PgPoolOptions::new().connect(&test_db_url()).await.unwrap();
        let id = create_disposable_murid().await;

        let first_pin = provision_one_student(&pool, id)
            .await
            .expect("first call should set a password and return the PIN");
        let hash_after_first = current_hash(&pool, id)
            .await
            .expect("row should have a password after the first call");

        let second_result = provision_one_student(&pool, id).await;
        let hash_after_second = current_hash(&pool, id)
            .await
            .expect("row should still have a password after the second call");

        assert!(
            second_result.is_none(),
            "re-provisioning an already-provisioned row must be a no-op, not generate a new PIN"
        );
        assert_eq!(
            hash_after_first, hash_after_second,
            "re-running provisioning must not change an already-set password hash"
        );
        assert_ne!(first_pin, "", "sanity check that the first call actually ran");

        cleanup_murid(id).await;
    }
}
