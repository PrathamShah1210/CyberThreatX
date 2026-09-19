# CyberThreatX

A PostgreSQL threat-intelligence workspace with individual logins, administrator / analyst / viewer access, private research tools, CISA KEV ingestion and six SQL reporting views.

## Upgrade your existing Mac installation

This repository extends the original 26-table PostgreSQL edition. It does not connect to the older hosted D1 website. Keep your current application folder and database until you have verified the upgrade.

1. Back up your `cyberthreatx` database in pgAdmin (Custom format, schema and data). Do not commit backups or credentials.
2. Clone this repository into a **new folder**, e.g. `git clone https://github.com/PrathamShah1210/CyberThreatX.git CyberThreatX-v2`.
3. Copy your existing application's `config.json` into that new folder locally. This file contains credentials; keep it private. If you do not copy it, setup will ask for your existing PostgreSQL connection and initial website administrator login.
4. In that folder run `bash start.command`. It installs dependencies, runs an additive transactional migration, and starts on http://127.0.0.1:8001. Stop the previous process first, or use `PORT=8002 bash start.command`.
5. Sign in with your existing website administrator credentials. The initial migration copies that password hash into `ctx_accounts` once. Later account changes are made in the Accounts screen, not config.json.
6. Create individual analyst and viewer accounts in **Accounts**. Use **Imports → Synchronize CISA KEV** to load public intelligence, then **Reports** to view it.

The migration runs inside a transaction and can be rerun. It adds five `ctx_` tables, an incident-assignment column, indexes, and six views. It does not drop tables, overwrite existing vulnerabilities or insert fictional incidents. The legacy `users` table remains a project directory; `ctx_accounts` is the website authentication principal. Keeping these separate avoids converting imported directory contacts into login accounts.

## Role access

| Capability | Admin | Analyst | Viewer |
|---|---|---|---|
| Intelligence tables / search / CSV | Yes | Yes | No |
| Create and edit intelligence | Yes | Yes | No |
| Delete intelligence | Yes | No | No |
| Directory tables and accounts | Yes | No | No |
| Public CISA intelligence view | Yes | Yes | Yes |
| Internal SQL reports | Yes | Yes | No |
| Private notes / bookmarks / searches / watchlist / review queue | Own | Own | Own |
| Feed synchronization and audit log | Yes | No | No |

Backend permissions apply to direct API calls and exports, not just navigation. Account changes revoke existing sessions. At least one active administrator must remain. Sessions use HttpOnly, SameSite cookies and CSRF checks. Login throttling is process-local, appropriate for the default single-server installation; distributed deployment needs shared throttling.

## Real intelligence

The importer uses the CISA Known Exploited Vulnerabilities JSON feed:
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Source catalogue: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

CVE IDs deduplicate records. Existing descriptions and severity classifications are preserved; new records use `Unknown` severity rather than inventing CVSS. KEV metadata retains vendor, product, required action, catalogue dates, original JSON and import timestamp. A feed error rolls back the import and records a failed run. Synchronization is manually initiated; no scheduler is installed.

If your environment cannot download the feed, obtain the JSON from CISA and run:

```bash
.venv/bin/python manage.py import-kev --file /path/to/known_exploited_vulnerabilities.json
```

Watchlist matching uses case-insensitive product/vendor text, not version analysis. A match is a research lead, not proof your installation is affected. Public feed records are not automatically converted into personal security incidents. Existing demo data is not relabelled as real intelligence.

## SQL views

- `vw_vulnerability_summary`: vulnerability records, incident counts, KEV context.
- `vw_active_incidents`: open incidents and assigned account name.
- `vw_ioc_context`: IOC, threat and source context.
- `vw_campaign_overview`: campaigns with actor counts.
- `vw_analyst_workload`: open incident counts per account.
- `vw_viewer_intelligence`: imported public KEV records without internal incidents or notes.

Views are reusable queries, not a substitute for API authorization. Database connections are server-side using one configured DB principal. This release does not create one PostgreSQL login per website user or use PostgreSQL RLS. Do not share the configured DB credentials with website users. Audit history currently covers API intelligence changes, account changes and online imports; direct SQL edits in pgAdmin are not audited by this application.

## Recovery and backups

```bash
.venv/bin/python manage.py reset-login
.venv/bin/python manage.py backup --file /private/path/cyberthreatx.dump
```

`pg_dump` must be installed for the backup command. To verify a backup, restore it into a **separate empty database**, using pgAdmin Restore or `pg_restore --no-owner -d cyberthreatx_restore_check /private/path/cyberthreatx.dump`. Compare row counts and start the application using a separate local configuration. Never test restore against your working database. Backup restoration has not been exercised in this workspace.

## Development and verification

Python 3.10+ and PostgreSQL are required. `requirements.txt` pins the application dependencies. `database/schema.sql` is the original schema for an empty database only. Your 45,206-row export is deliberately not published to GitHub. For a new empty installation, apply schema.sql before running setup; import your own vulnerability data or use the CISA feed after migration.

`tests/upgrade.py` expects a disposable database with the original schema and the original 45,206-row export. It tests migration repeatability, preservation, role restrictions, CSRF, private ownership, session revocation, views, import deduplication and rollback. Do not run it against your working database.

This is a local application, not an internet-ready hosted deployment. Before remote access, configure HTTPS, secure cookies, restricted DB credentials and shared operational monitoring. Evidence remains metadata rather than uploaded file storage.
