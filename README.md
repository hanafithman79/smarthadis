# SmartHadis

AI-assisted hadith memorization app for Sekolah Kebangsaan Bunut Susu. Live at
[smarthadis.lynx.my](https://smarthadis.lynx.my).

## Structure

- `apps/smarthadis40apps/` — static frontend (login app + `/pembentangan/` presentation page), served by Caddy.
- `services/smarthadis-api/` — Rust backend API (Axum), deployed as a systemd service.

## Backend

No local Rust toolchain is assumed by this repo's history — `cargo build`/`cargo test`
were run over SSH on the production host throughout development. Copy
`services/smarthadis-api/.env.example` to `.env` and fill in real values before running
locally.

## Frontend

Plain HTML/CSS/JS, no build step. `apps/smarthadis40apps/index.html` is the login app;
`apps/smarthadis40apps/pembentangan/index.html` is the presentation page.
