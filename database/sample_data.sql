-- CyberThreatX: sample data for your exported PostgreSQL schema.
-- HOW TO RUN: In pgAdmin select your EXISTING CyberThreatX database,
-- open Query Tool, open this file, and execute the whole script.
-- On an error, execute ROLLBACK; before correcting and retrying.
-- This is an insertion script, not a replacement database backup.
-- All new records are fictional classroom examples identified by CTX-DEMO.
-- Existing vulnerability records are read only. Incident/CVE links below
-- illustrate relationships; they do NOT claim actual exploitation.
-- The unrelated course, department and student tables are untouched.
-- Repeat runs reuse the demo records. No permanent schema changes.
-- Database records here do not create authenticated application accounts.
-- This file alone does not connect the hosted frontend to PostgreSQL.

BEGIN;
SET LOCAL search_path = public, pg_catalog;
SET LOCAL lock_timeout = '10s';
-- Serialize executions of this seed script.
SELECT pg_advisory_xact_lock(20260911, 112233);

DO $seed$
DECLARE
  n integer;
  uid integer;
  rid integer;
  tid integer;
  sid integer;
  aid integer;
  cid integer;
  iid integer;
  oid integer;
  vid integer;
  marker text;
  incident_kind text;
  role_label text;
  phone_value text;
  incident_note text;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM public.vulnerabilities) THEN
    RAISE EXCEPTION 'Expected your existing vulnerability data. Select the correct database before running this script.';
  END IF;

  INSERT INTO public.roles(role_name, description) VALUES
    ('CTX-DEMO Admin', 'Fictional administrator role for classroom data'),
    ('CTX-DEMO Analyst', 'Fictional analyst role for classroom data'),
    ('CTX-DEMO Viewer', 'Fictional viewer role for classroom data')
    ON CONFLICT (role_name) DO NOTHING;

  INSERT INTO public.permissions(perm_name, description) VALUES
    ('CTX-DEMO Read', 'Demonstration permission: read threat intelligence'),
    ('CTX-DEMO Create', 'Demonstration permission: create records'),
    ('CTX-DEMO Update', 'Demonstration permission: edit records'),
    ('CTX-DEMO Delete', 'Demonstration permission: delete records')
    ON CONFLICT (perm_name) DO NOTHING;
  -- Your current schema has no role-permission junction table.
  -- These permission rows are catalog data, not enforced access control.

  FOR n IN 1..6 LOOP
    marker := 'CTX-DEMO-' || lpad(n::text, 2, '0');
    phone_value := '+1-202-555-01' || lpad(n::text, 2, '0');
    role_label := CASE WHEN n = 1 THEN 'CTX-DEMO Admin'
                       WHEN n <= 4 THEN 'CTX-DEMO Analyst'
                       ELSE 'CTX-DEMO Viewer' END;

    INSERT INTO public.users(name,email,phone,first_name,last_name,login)
      VALUES ('Demo Analyst ' || n, 'ctx-demo-' || n || '@example.com',
              phone_value, 'Demo', 'Analyst ' || n, 'ctx-demo-' || n)
      ON CONFLICT (email) DO NOTHING;
    SELECT user_id INTO STRICT uid FROM public.users
      WHERE email = 'ctx-demo-' || n || '@example.com';
    SELECT role_id INTO STRICT rid FROM public.roles WHERE role_name = role_label;
    INSERT INTO public.user_role VALUES (uid,rid) ON CONFLICT DO NOTHING;
    INSERT INTO public.user_phones VALUES (uid,phone_value) ON CONFLICT DO NOTHING;

    INSERT INTO public.threats(name,description,risk_score,created_at)
      SELECT marker || ' Threat', 'Fictional classroom threat scenario ' || n,
             35 + n * 10, timestamp '2026-09-01 09:00:00' + n * interval '1 day'
      WHERE NOT EXISTS (SELECT 1 FROM public.threats WHERE name = marker || ' Threat');
    SELECT min(threat_id) INTO tid FROM public.threats WHERE name = marker || ' Threat';

    INSERT INTO public.sources(source_name,source_type,reliability_score)
      SELECT marker || ' Lab sensor', 'Simulated telemetry', 70 + n * 3
      WHERE NOT EXISTS (SELECT 1 FROM public.sources WHERE source_name = marker || ' Lab sensor');
    SELECT min(source_id) INTO sid FROM public.sources WHERE source_name = marker || ' Lab sensor';
    INSERT INTO public.source_urls VALUES
      (sid, 'https://example.com/ctx-demo/sensor-' || n) ON CONFLICT DO NOTHING;

    INSERT INTO public.threat_actors(actor_name,origin)
      VALUES (marker || ' Fictional actor','Simulated lab')
      ON CONFLICT (actor_name) DO NOTHING;
    SELECT actor_id INTO STRICT aid FROM public.threat_actors
      WHERE actor_name = marker || ' Fictional actor';
    INSERT INTO public.threat_actor_aliases VALUES
      (aid, marker || ' Alias') ON CONFLICT DO NOTHING;

    INSERT INTO public.campaigns(name,start_date,end_date)
      VALUES (marker || ' Training campaign', date '2026-09-01', date '2026-09-10')
      ON CONFLICT (name) DO NOTHING;
    SELECT campaign_id INTO STRICT cid FROM public.campaigns
      WHERE name = marker || ' Training campaign';
    INSERT INTO public.campaign_objectives VALUES
      (cid, 'Simulate detection and triage of classroom scenario ' || n)
      ON CONFLICT DO NOTHING;
    INSERT INTO public.actor_campaign VALUES (aid,cid) ON CONFLICT DO NOTHING;
    -- targets references SOURCES in your exported schema.
    INSERT INTO public.targets VALUES (aid,cid,sid) ON CONFLICT DO NOTHING;

    incident_kind := CASE WHEN n <= 2 THEN 'Security'
                          WHEN n <= 4 THEN 'Data Breach' ELSE 'Malware' END;
    incident_note := marker || ' Fictional ' || incident_kind ||
      ' exercise. Any linked CVE is an illustrative association, not evidence of exploitation.';
    INSERT INTO public.incidents(incident_type,detected_at,status,description)
      SELECT incident_kind, timestamp '2026-09-01 10:00:00' + n * interval '1 day',
             CASE WHEN n % 3 = 0 THEN 'Closed' WHEN n % 3 = 1 THEN 'Open'
                  ELSE 'Investigating' END, incident_note
      WHERE NOT EXISTS (SELECT 1 FROM public.incidents WHERE description = incident_note);
    SELECT min(incident_id) INTO iid FROM public.incidents WHERE description = incident_note;

    IF n <= 2 THEN
      INSERT INTO public.security_incidents VALUES
        (iid,CASE WHEN n = 1 THEN 'Suspicious sign-in' ELSE 'Network anomaly' END,
         CASE WHEN n = 1 THEN 'High' ELSE 'Medium' END) ON CONFLICT DO NOTHING;
    ELSIF n <= 4 THEN
      INSERT INTO public.data_breaches VALUES
        (iid, n * 250, 'Synthetic email addresses; Synthetic account identifiers')
        ON CONFLICT DO NOTHING;
      INSERT INTO public.data_breach_datatypes VALUES
        (iid,'Synthetic email addresses'), (iid,'Synthetic account identifiers')
        ON CONFLICT DO NOTHING;
    ELSE
      INSERT INTO public.malware_incidents VALUES
        (iid,marker || ' Test sample','Fictional training family') ON CONFLICT DO NOTHING;
      INSERT INTO public.m_att_sys VALUES
        (iid,marker || '-workstation'), (iid,marker || '-lab-server') ON CONFLICT DO NOTHING;
    END IF;

    INSERT INTO public.iocs(type,raw_data,encoding_type,first_seen,last_seen,threat_id,source_id)
      SELECT 'IPv4','192.0.2.' || n,'Plain text',
             timestamp '2026-09-01 09:00:00' + n * interval '1 day',
             timestamp '2026-09-01 11:00:00' + n * interval '1 day',tid,sid
      WHERE NOT EXISTS (SELECT 1 FROM public.iocs
                        WHERE type = 'IPv4' AND raw_data = '192.0.2.' || n
                          AND threat_id = tid AND source_id = sid);
    SELECT min(ioc_id) INTO oid FROM public.iocs
      WHERE type = 'IPv4' AND raw_data = '192.0.2.' || n
        AND threat_id = tid AND source_id = sid;
    INSERT INTO public.incident_ioc VALUES (iid,oid) ON CONFLICT DO NOTHING;

    INSERT INTO public.iocs(type,raw_data,encoding_type,first_seen,last_seen,threat_id,source_id)
      SELECT 'Domain','ctx-demo-' || n || '.example.com','Plain text',
             timestamp '2026-09-01 09:00:00' + n * interval '1 day',
             timestamp '2026-09-01 11:00:00' + n * interval '1 day',tid,sid
      WHERE NOT EXISTS (SELECT 1 FROM public.iocs
                        WHERE type = 'Domain' AND raw_data = 'ctx-demo-' || n || '.example.com'
                          AND threat_id = tid AND source_id = sid);
    SELECT min(ioc_id) INTO oid FROM public.iocs
      WHERE type = 'Domain' AND raw_data = 'ctx-demo-' || n || '.example.com'
        AND threat_id = tid AND source_id = sid;
    INSERT INTO public.incident_ioc VALUES (iid,oid) ON CONFLICT DO NOTHING;

    SELECT vuln_id INTO vid FROM public.vulnerabilities
      ORDER BY vuln_id OFFSET (n - 1) LIMIT 1;
    IF vid IS NOT NULL THEN
      INSERT INTO public.incident_vuln VALUES (iid,vid) ON CONFLICT DO NOTHING;
    END IF;

    INSERT INTO public.attachments(incident_id,attach_no,name,type,size)
      VALUES (iid,1,marker || '-synthetic-evidence.txt','text/plain',
              octet_length(marker || ' synthetic evidence')) ON CONFLICT DO NOTHING;
    -- MD5 of the stated synthetic text, not a hash of an uploaded artifact.
    -- Only attachment metadata is created; no evidence file is uploaded.
    INSERT INTO public.attachment_hashes VALUES
      (iid,1,md5(marker || ' synthetic evidence')) ON CONFLICT DO NOTHING;
  END LOOP;
END;
$seed$;

COMMIT;

-- Verification: expected counts if the database matches your uploaded export.
-- Subsequent executions keep these row counts unchanged.
SELECT 'vulnerabilities' AS table_name, count(*) AS actual, 45206 AS expected FROM public.vulnerabilities
UNION ALL SELECT 'users',count(*),6 FROM public.users
UNION ALL SELECT 'roles',count(*),3 FROM public.roles
UNION ALL SELECT 'permissions',count(*),4 FROM public.permissions
UNION ALL SELECT 'user_role',count(*),6 FROM public.user_role
UNION ALL SELECT 'user_phones',count(*),6 FROM public.user_phones
UNION ALL SELECT 'threats',count(*),6 FROM public.threats
UNION ALL SELECT 'sources',count(*),6 FROM public.sources
UNION ALL SELECT 'source_urls',count(*),6 FROM public.source_urls
UNION ALL SELECT 'threat_actors',count(*),6 FROM public.threat_actors
UNION ALL SELECT 'threat_actor_aliases',count(*),6 FROM public.threat_actor_aliases
UNION ALL SELECT 'campaigns',count(*),6 FROM public.campaigns
UNION ALL SELECT 'campaign_objectives',count(*),6 FROM public.campaign_objectives
UNION ALL SELECT 'actor_campaign',count(*),6 FROM public.actor_campaign
UNION ALL SELECT 'targets',count(*),6 FROM public.targets
UNION ALL SELECT 'incidents',count(*),6 FROM public.incidents
UNION ALL SELECT 'security_incidents',count(*),2 FROM public.security_incidents
UNION ALL SELECT 'data_breaches',count(*),2 FROM public.data_breaches
UNION ALL SELECT 'data_breach_datatypes',count(*),4 FROM public.data_breach_datatypes
UNION ALL SELECT 'malware_incidents',count(*),2 FROM public.malware_incidents
UNION ALL SELECT 'm_att_sys',count(*),4 FROM public.m_att_sys
UNION ALL SELECT 'iocs',count(*),12 FROM public.iocs
UNION ALL SELECT 'incident_ioc',count(*),12 FROM public.incident_ioc
UNION ALL SELECT 'incident_vuln',count(*),6 FROM public.incident_vuln
UNION ALL SELECT 'attachments',count(*),6 FROM public.attachments
UNION ALL SELECT 'attachment_hashes',count(*),6 FROM public.attachment_hashes
ORDER BY table_name;

-- Presentation query: actual linked rows from your PostgreSQL database.
SELECT i.incident_id, i.incident_type, i.status,
       (SELECT count(*) FROM public.incident_ioc x WHERE x.incident_id=i.incident_id) AS indicator_count,
       (SELECT string_agg(v.cve_id, ', ' ORDER BY v.cve_id)
          FROM public.incident_vuln x JOIN public.vulnerabilities v USING(vuln_id)
         WHERE x.incident_id=i.incident_id) AS illustrative_cve_links
FROM public.incidents i
WHERE i.description LIKE 'CTX-DEMO-%'
ORDER BY i.incident_id;
