# CyberThreatX — public intelligence, analyst desk and administration

The public homepage searches published IP, domain, URL and file-hash observations, with source evidence and explicit unknown/conflicting results. Selected files are hashed locally in the browser (SHA-256, up to 100 MB); file contents are not uploaded or executed. No target URLs are fetched.

## Update the existing Mac folder

Back up your database first. Stop the running server, then from your current Git checkout:

```bash
git pull --ff-only origin main
PORT=8003 bash start.command
```

Alternatively run `bash update.command`. Neither command discards local changes. If Git reports a conflict, preserve your edits and resolve it before restarting. `config.json` remains private and untracked.

Public portal: http://127.0.0.1:8003/
Staff / personal workspace: http://127.0.0.1:8003/workspace

The startup migration is additive. It preserves existing intelligence and accounts, adds public catalog/observations/review/source-control tables and stages existing CISA records privately. It does **not** automatically publish internal records. There is no migration rollback command; restore the verified backup into a separate database if recovery is needed.

## Get real records into the public portal

1. Admin → Sources → Load sourced starter collection (five real historical references; works without downloading a feed).
2. Admin → Sources → synchronize CISA and MITRE for broader coverage when network access is available.
3. Analyst → Desk → review source evidence and move approved records to Ready.
4. Admin → Desk → Ready → Publish.
5. Open the public portal without signing in. Review DATA_SOURCES.md for IOC CSV ingestion and source terms.

Actors/campaigns are not IOCs. To get positive file/IP/URL matches, import **sourced indicator observations** and publish them. Arbitrary existing IOC values are not automatically labelled malicious. Public submissions enter review as unknown.

## Portal responsibilities

- Public: published intelligence search/browse, source references, relationships, exact IOC lookup and suspicious-indicator submissions. No login needed.
- Analyst: incoming/review/ready queues, sourced records, verdicts, review notes, duplicates/rejections, original database tools and private research.
- Admin: user accounts, roles, source enable/disable, synchronization, publication/withdrawal and audit history.
- Signed-in Viewer: public intelligence and private research; no internal table access.

See DATA_SOURCES.md for source details and VALIDATION.md for tested behavior and limits.

## First installation

Requires Python 3.10+ and PostgreSQL. Use the existing CyberThreatX database. Keep `config.json` in the project folder locally, or let `bash start.command` ask for the connection details and initial administrator login. For an empty database only, apply `database/schema.sql` before setup. The original 45,206-row export is not distributed in this repository.

## Data and permissions

The original 26 tables remain, with ten extension tables for accounts, research, source observations and publication. This release therefore has 36 application tables. Imported source metadata and supported relationships populate the corresponding legacy intelligence tables as well as the publication catalog. Accounts, incidents and private records are created through actual use rather than fabricated to fill a table.

Backend authorization applies to reads, writes and CSV exports. Analysts can edit intelligence but cannot delete core records, manage accounts or publish. Viewers cannot access internal tables. Each account's notes and watchlists are private. At least one administrator must remain active. Role/password changes revoke active sessions.

Published catalog data is a separate editorial snapshot. Existing legacy rows do not automatically become public or receive a malicious verdict. The six SQL reporting views remain available; the viewer-intelligence view includes only published CISA items. The application uses one server-side PostgreSQL connection principal; website roles are not separate PostgreSQL logins. SQL views do not replace API permissions.

## Backup and account recovery

```bash
.venv/bin/python manage.py backup --file /private/path/cyberthreatx.dump
.venv/bin/python manage.py reset-login
```

Backup requires `pg_dump`. Test restore into a **separate empty database**, using pgAdmin Restore or `pg_restore --no-owner -d cyberthreatx_restore_check /private/path/cyberthreatx.dump`. Never test a restore against the working database. Backup restoration was not exercised here.

## Operational boundaries

Default binding is localhost on port 8003. Before internet hosting, configure HTTPS, secure cookies, shared rate limiting and restricted database credentials. Rate limits in this release are process-local. Public lookup requests contain the submitted indicator and are sent only to your own backend; files stay in the browser. Evidence remains metadata, not uploaded files.

Audit history covers API mutations and editorial actions. Direct pgAdmin edits are not captured. Feed runs record successes/failures. No background scheduler is installed; DATA_SOURCES.md explains CLI scheduling. The app downloads only fixed intelligence-source URLs, never user-submitted target URLs. Indicator checks are historical reputation lookups, not behavioral malware analysis.

## Tests

`tests/public_portal.py` runs only on a disposable database containing the original schema. The GitHub Actions workflow uses PostgreSQL 16 with a synthetic CI fixture. `tests/upgrade.py` additionally expects the original 45,206-row export. Neither test should run against your working database. See VALIDATION.md for observed results and remaining limits.
