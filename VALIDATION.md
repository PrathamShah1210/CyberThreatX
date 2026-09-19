# Upgrade validation

44 automated checks passed using PGlite, a PostgreSQL WebAssembly engine, with the original 45,206 vulnerability records restored.

Covered: repeated additive migration, existing data preservation, individual login, role restrictions on reads/writes/exports, CSRF, private research ownership, watchlist matching, import idempotency and atomic rollback, last-administrator protection, session revocation, audit entries, all six SQL views, sorting, combined filtering and frontend route delivery.

CISA ingestion was tested with clearly fictional in-memory fixtures. Live feed download is unverified due to network restrictions. Native Mac PostgreSQL connectivity, interactive browser behavior, backup restoration and remote deployment remain unverified.

Interactive browser testing was attempted but could not start because a Chromium executable is not installed. The PGlite socket adapter needed a test-only connection-close settling delay; native PostgreSQL testing is still required.
