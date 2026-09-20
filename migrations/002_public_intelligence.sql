CREATE TABLE IF NOT EXISTS ctx_catalog (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 external_key text UNIQUE NOT NULL,
 category text NOT NULL CHECK(category IN ('vulnerability','actor','campaign','threat','indicator','advisory')),
 title text NOT NULL, summary text NOT NULL DEFAULT '',
 source_name text NOT NULL, source_url text NOT NULL,
 payload jsonb NOT NULL DEFAULT '{}',
 state text NOT NULL DEFAULT 'incoming' CHECK(state IN ('incoming','review','ready','published','rejected','duplicate','withdrawn')),
 assigned_to bigint REFERENCES ctx_accounts(id), review_note text NOT NULL DEFAULT '',
 reviewed_by bigint REFERENCES ctx_accounts(id), published_by bigint REFERENCES ctx_accounts(id),
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), published_at timestamptz,
 legacy_table text, legacy_id integer
);
CREATE INDEX IF NOT EXISTS ctx_catalog_browse ON ctx_catalog(state,category,id DESC);
CREATE TABLE IF NOT EXISTS ctx_indicator_values (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 kind text NOT NULL CHECK(kind IN ('ip','domain','url','md5','sha1','sha256')),
 value text NOT NULL, UNIQUE(kind,value)
);
CREATE TABLE IF NOT EXISTS ctx_observations (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 indicator_id bigint NOT NULL REFERENCES ctx_indicator_values(id),
 catalog_id bigint NOT NULL REFERENCES ctx_catalog(id),
 verdict text NOT NULL CHECK(verdict IN ('malicious','suspicious','benign','unknown')),
 confidence integer CHECK(confidence BETWEEN 0 AND 100),
 first_seen timestamptz, last_seen timestamptz, recorded_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(indicator_id,catalog_id)
);
CREATE TABLE IF NOT EXISTS ctx_catalog_links (
 from_id bigint REFERENCES ctx_catalog(id), to_id bigint REFERENCES ctx_catalog(id),
 relationship text NOT NULL, source_url text NOT NULL,
 PRIMARY KEY(from_id,to_id,relationship)
);
CREATE TABLE IF NOT EXISTS ctx_source_settings (
 name text PRIMARY KEY, enabled boolean NOT NULL DEFAULT true,
 description text NOT NULL
);
INSERT INTO ctx_source_settings(name,description) VALUES
 ('cisa','CISA Known Exploited Vulnerabilities; public vulnerability intelligence'),
 ('mitre','MITRE ATT&CK Enterprise STIX: groups, campaigns, malware and techniques') ON CONFLICT DO NOTHING;
REVOKE ALL ON ctx_catalog,ctx_indicator_values,ctx_observations,ctx_catalog_links,ctx_source_settings FROM PUBLIC;
CREATE OR REPLACE VIEW vw_viewer_intelligence AS
 SELECT (c.payload->>'cveID')::varchar(30) AS cve_id,c.summary AS description,
 'Unknown'::varchar(20) AS severity,c.payload->>'vendorProject' AS vendor,
 c.payload->>'product' AS product,c.payload->>'requiredAction' AS required_action,
 c.source_url,(c.payload->>'dateAdded')::date AS date_added
 FROM ctx_catalog c WHERE c.external_key LIKE 'cisa:%' AND c.state='published';
