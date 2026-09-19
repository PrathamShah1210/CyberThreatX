CREATE TABLE IF NOT EXISTS ctx_accounts (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 username varchar(100) NOT NULL UNIQUE,
 password_hash text NOT NULL,
 role text NOT NULL CHECK(role IN ('admin','analyst','viewer')),
 active boolean NOT NULL DEFAULT true,
 session_version integer NOT NULL DEFAULT 1,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ctx_audit (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 actor_id bigint REFERENCES ctx_accounts(id), action text NOT NULL,
 entity text NOT NULL, record_key jsonb, occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ctx_research (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 owner_id bigint NOT NULL REFERENCES ctx_accounts(id),
 kind text NOT NULL CHECK(kind IN ('watchlist','bookmark','note','search','review')),
 title varchar(200) NOT NULL, content text NOT NULL DEFAULT '',
 status text NOT NULL DEFAULT 'open' CHECK(status IN ('open','done')),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ctx_import_runs (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 source text NOT NULL, started_at timestamptz NOT NULL DEFAULT now(),
 finished_at timestamptz, status text NOT NULL, records integer NOT NULL DEFAULT 0,
 message text
);
CREATE TABLE IF NOT EXISTS ctx_kev (
 cve_id varchar(30) PRIMARY KEY REFERENCES vulnerabilities(cve_id),
 vendor text NOT NULL, product text NOT NULL, required_action text NOT NULL,
 date_added date NOT NULL, due_date date, source_url text NOT NULL,
 raw_record jsonb NOT NULL, imported_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS assigned_account_id bigint REFERENCES ctx_accounts(id);
CREATE INDEX IF NOT EXISTS ctx_research_owner ON ctx_research(owner_id,kind);
CREATE INDEX IF NOT EXISTS ctx_audit_date ON ctx_audit(occurred_at DESC);
CREATE INDEX IF NOT EXISTS ctx_incident_vuln_reverse ON incident_vuln(vuln_id);
CREATE OR REPLACE VIEW vw_vulnerability_summary AS
 SELECT v.*, (SELECT count(*) FROM incident_vuln i WHERE i.vuln_id=v.vuln_id) AS incident_count,
 k.vendor,k.product,k.date_added,k.required_action,k.source_url,
 (k.cve_id IS NOT NULL) AS known_exploited FROM vulnerabilities v LEFT JOIN ctx_kev k USING(cve_id);
CREATE OR REPLACE VIEW vw_active_incidents AS
 SELECT i.*, a.username AS assigned_analyst FROM incidents i LEFT JOIN ctx_accounts a ON a.id=i.assigned_account_id
 WHERE lower(coalesce(i.status,'')) NOT IN ('closed','resolved');
CREATE OR REPLACE VIEW vw_ioc_context AS
 SELECT i.*,t.name AS threat_name,s.source_name FROM iocs i LEFT JOIN threats t USING(threat_id) LEFT JOIN sources s USING(source_id);
CREATE OR REPLACE VIEW vw_campaign_overview AS
 SELECT c.*, (SELECT count(*) FROM actor_campaign a WHERE a.campaign_id=c.campaign_id) AS actor_count FROM campaigns c;
CREATE OR REPLACE VIEW vw_analyst_workload AS
 SELECT a.id,a.username,count(i.incident_id) AS open_incidents FROM ctx_accounts a LEFT JOIN vw_active_incidents i ON i.assigned_account_id=a.id GROUP BY a.id,a.username;
CREATE OR REPLACE VIEW vw_viewer_intelligence AS
 SELECT v.cve_id,v.description,v.severity,k.vendor,k.product,k.required_action,k.source_url,k.date_added
 FROM vulnerabilities v JOIN ctx_kev k USING(cve_id);
REVOKE ALL ON ctx_accounts,ctx_audit,ctx_research,ctx_import_runs,ctx_kev FROM PUBLIC;
