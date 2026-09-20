"""Explicit public-source imports; every imported record enters editorial review."""
import json,os,csv,hashlib
from urllib.request import urlopen
from pathlib import Path
from flask import request,session,jsonify,abort
from intelligence import stage,observe,reference
from workspace import ingest_kev,audit,FEED
MITRE='https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json'

def stage_kev(c,payload):
 n=ingest_kev(c,payload)
 for r in payload['vulnerabilities']:
  v=c.execute('SELECT vuln_id FROM vulnerabilities WHERE cve_id=%s',(r['cveID'],)).fetchone()['vuln_id']
  stage(c,'cisa:'+r['cveID'],'vulnerability',r['cveID']+' · '+r.get('vulnerabilityName',r['product']),r['shortDescription']+'\nRecommended action: '+r['requiredAction'],'CISA KEV','https://www.cisa.gov/known-exploited-vulnerabilities-catalog',r,'vulnerabilities',v)
 return n

def stage_mitre(c,payload):
 if payload.get('type')!='bundle' or not isinstance(payload.get('objects'),list):raise ValueError('Expected MITRE ATT&CK STIX bundle.')
 c.execute('SELECT pg_advisory_xact_lock(72626413)')
 ids={};n=0
 for o in payload['objects']:
  category={'intrusion-set':'actor','campaign':'campaign','malware':'threat','attack-pattern':'threat'}.get(o.get('type'))
  if o.get('revoked') or o.get('x_mitre_deprecated'):
   c.execute("UPDATE ctx_catalog SET state='withdrawn',review_note='Withdrawn by source: revoked or deprecated',updated_at=now() WHERE external_key=%s",('mitre:'+o.get('id',''),))
   continue
  if not category:continue
  refs=[r for r in o.get('external_references',[]) if r.get('source_name')=='mitre-attack' and r.get('url','').startswith('https://attack.mitre.org/')]
  if not refs:continue
  key='mitre:'+o['id'];existing=c.execute('SELECT legacy_table,legacy_id FROM ctx_catalog WHERE external_key=%s',(key,)).fetchone();table=None;rid=None
  if existing:table,rid=existing['legacy_table'],existing['legacy_id']
  elif category=='actor':
   table='threat_actors';rid=c.execute('INSERT INTO threat_actors(actor_name) VALUES (%s) ON CONFLICT(actor_name) DO UPDATE SET actor_name=excluded.actor_name RETURNING actor_id',(o['name'][:150],)).fetchone()['actor_id']
   for alias in o.get('aliases',[]):c.execute('INSERT INTO threat_actor_aliases(actor_id,alias) VALUES (%s,%s) ON CONFLICT DO NOTHING',(rid,alias[:150]))
  elif category=='campaign':
   table='campaigns';rid=c.execute('INSERT INTO campaigns(name) VALUES (%s) ON CONFLICT(name) DO UPDATE SET name=excluded.name RETURNING campaign_id',(o['name'][:150],)).fetchone()['campaign_id']
  else:
   table='threats';rid=c.execute('INSERT INTO threats(name,description) VALUES (%s,%s) RETURNING threat_id',(o['name'][:150],o.get('description',''))).fetchone()['threat_id']
  ids[o['id']]=stage(c,key,category,o['name'],o.get('description',''),'MITRE ATT&CK',refs[0]['url'],o,table,rid);n+=1
 for o in payload['objects']:
  if o.get('type')!='relationship' or o.get('revoked'):continue
  src,tgt=o.get('source_ref'),o.get('target_ref')
  if src not in ids or tgt not in ids:continue
  refs=o.get('external_references',[]);url=next((r['url'] for r in refs if r.get('url','').startswith('https://')), 'https://attack.mitre.org/')
  c.execute('INSERT INTO ctx_catalog_links(from_id,to_id,relationship,source_url) VALUES (%s,%s,%s,%s) ON CONFLICT DO NOTHING',(ids[src],ids[tgt],o.get('relationship_type','related-to'),url))
  # Only explicit campaign attribution supports this legacy relationship.
  if src.startswith('campaign--') and tgt.startswith('intrusion-set--') and o.get('relationship_type')=='attributed-to':
   a=c.execute('SELECT legacy_id FROM ctx_catalog WHERE id=%s',(ids[tgt],)).fetchone()['legacy_id'];camp=c.execute('SELECT legacy_id FROM ctx_catalog WHERE id=%s',(ids[src],)).fetchone()['legacy_id']
   c.execute('INSERT INTO actor_campaign(actor_id,campaign_id) VALUES (%s,%s) ON CONFLICT DO NOTHING',(a,camp))
 if n==0:raise ValueError('No supported MITRE objects found.')
 return n

def stage_csv(c,rows):
 """Portable operator-supplied IOC CSV. No inference from URL payload lists."""
 n=0
 for r in rows:
  for key in ('type','value','verdict','source_name','source_url'):
   if not r.get(key):raise ValueError('CSV requires type,value,verdict,source_name,source_url.')
  ref=reference(r['source_url']);source=r['source_name'].strip()
  identity=hashlib.sha256((source+'|'+ref+'|'+r['type']+'|'+r['value']).encode()).hexdigest()
  cid=stage(c,'ioc:'+identity,'indicator',r['value'],r.get('description',''),source,ref,dict(r))
  observe(c,cid,r['type'],r['value'],r['verdict'],int(r['confidence']) if r.get('confidence') else None,r.get('first_seen') or None,r.get('last_seen') or None);n+=1
 if not n:raise ValueError('CSV contains no records.')
 return n

def fetch_source(source):
 if source not in ('cisa','mitre'):raise ValueError('Unsupported source.')
 with urlopen(FEED if source=='cisa' else MITRE,timeout=45) as r: raw=r.read(65_000_001)
 if len(raw)>65_000_000:raise ValueError('Feed exceeds size limit.')
 return json.loads(raw)

def sync(config,connect,source):
 with connect(config) as c:
  setting=c.execute('SELECT enabled FROM ctx_source_settings WHERE name=%s',(source,)).fetchone()
  if not setting or not setting['enabled']:raise ValueError('Source is disabled or unknown.')
  # Avoid overlapping imports of the same feed, and report abandoned jobs after an hour.
  c.execute("UPDATE ctx_import_runs SET status='failed',finished_at=now(),message='Import did not complete within one hour' WHERE status='running' AND started_at<now()-interval '1 hour'")
  c.execute('SELECT pg_advisory_xact_lock(72626414)')
  if c.execute("SELECT 1 FROM ctx_import_runs WHERE source=%s AND status='running'",(source,)).fetchone():raise ValueError('This source already has an import running.')
  run=c.execute("INSERT INTO ctx_import_runs(source,status) VALUES (%s,'running') RETURNING id",(source,)).fetchone()['id']
 try:
  payload=fetch_source(source)
  with connect(config) as c:
   c.execute("SET LOCAL statement_timeout='120s'")
   n=(stage_kev if source=='cisa' else stage_mitre)(c,payload)
   c.execute("UPDATE ctx_import_runs SET status='success',records=%s,finished_at=now(),message='Staged for analyst review; not automatically published' WHERE id=%s",(n,run))
  return n
 except Exception:
  with connect(config) as c:c.execute("UPDATE ctx_import_runs SET status='failed',finished_at=now(),message='Download or validation failed. Feed transaction rolled back.' WHERE id=%s",(run,))
  raise

def install(app,config,connect,protected):
 @app.route('/api/sources',methods=['GET','PUT'])
 @protected
 def sources():
  if session['role']!='admin':abort(403)
  with connect(config) as c:
   if request.method=='PUT':
    d=request.get_json() or {}
    if not isinstance(d.get('enabled'),bool):raise ValueError('Enabled must be a boolean.')
    if not c.execute('UPDATE ctx_source_settings SET enabled=%s WHERE name=%s RETURNING name',(d['enabled'],d.get('name'))).fetchone():abort(404)
    audit(c,'source_setting','sources',{'name':d['name'],'enabled':d['enabled']})
   return jsonify(rows=c.execute('SELECT * FROM ctx_source_settings ORDER BY name').fetchall())
 @app.post('/api/sources/starter')
 @protected
 def starter():
  if session['role']!='admin':abort(403)
  from starter import load
  return jsonify(records=load(config))
 @app.post('/api/sources/<source>/sync')
 @protected
 def synchronize(source):
  if session['role']!='admin':abort(403)
  try:n=sync(config,connect,source)
  except ValueError:raise
  except Exception:return jsonify(error='Source download or import failed. See import history. No partial records committed.'),502
  with connect(config) as c:audit(c,'source_sync',source,{'records':n})
  return jsonify(records=n,message='Imported into the analyst queue. Review and publish to make records public.')

if __name__=='__main__':
 import argparse
 from app import read_config,connect
 p=argparse.ArgumentParser();p.add_argument('source',choices=['cisa','mitre','ioc-csv','all']);p.add_argument('--file');a=p.parse_args();config=read_config()
 if a.file:
  if a.source=='all':raise SystemExit('Choose one source for --file.')
  with connect(config) as c:
   c.execute("SET LOCAL statement_timeout='120s'")
   with open(a.file,encoding='utf-8-sig',newline='') as f:n=stage_csv(c,csv.DictReader(f)) if a.source=='ioc-csv' else (stage_kev if a.source=='cisa' else stage_mitre)(c,json.load(f))
   c.execute("INSERT INTO ctx_import_runs(source,status,records,finished_at,message) VALUES (%s,'success',%s,now(),'Local file staged for review')",(a.source,n))
  print(n,'records staged for review.')
 else:
  if a.source=='ioc-csv':raise SystemExit('Use --file with a sourced IOC CSV.')
  for source in (['cisa','mitre'] if a.source=='all' else [a.source]):print(source,sync(config,connect,source),'records staged.')
