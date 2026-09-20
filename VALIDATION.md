# Release validation — public intelligence portal

Observed locally: **104 automated checks passed** against PGlite (PostgreSQL WebAssembly), with the original 45,206 vulnerabilities restored:

- 60 public portal checks: public/private separation, normalization, exact versus related-host lookup, conflicting observations, submission handling, analyst/admin publication restrictions, withdrawal, source revocation, CSV rollback, repeatable starter imports and preservation of approved snapshots on unchanged re-imports.
- 44 account/database regression checks: migration repeatability, original vulnerability preservation, login, roles, CSRF, private research, session revocation, views, filtering and sorting.
- Python compilation and all three JavaScript syntax checks passed.

The starter collection contains five real historical reference records sourced in DATA_SOURCES.md, including one WannaCry C2 indicator. Integration-test-only actors, campaigns and CVEs are synthetic and are not loaded by the application or migrations.

The test database retained all 45,206 original vulnerability records without content changes. Your Mac database was not accessed or changed from this workspace.

PGlite tests use a test-only connection-close settling delay required by its socket adapter. Native PostgreSQL CI is configured in `.github/workflows/tests.yml`; its result must be checked separately on GitHub. Do not infer native PostgreSQL verification from PGlite success.

Not verified locally: interactive browser behavior (Chromium executable unavailable), full live CISA/MITRE downloads (network restrictions), Mac PostgreSQL connection, backup restoration or internet deployment. The application remains bound to localhost by default on port 8003.
