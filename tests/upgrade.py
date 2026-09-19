"""Run against a disposable database with the original schema and vulnerability export loaded."""
import os,sys,secrets
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
# Optional transport settling for PGlite socket tests; not used with native PostgreSQL.
if os.environ.get('CTX_PGLITE_TEST'):
 import psycopg,time
 original_close=psycopg.Connection.close
 def settled_close(self):
  original_close(self);time.sleep(0.03)
 psycopg.Connection.close=settled_close
from app import create_app,connect
from migrate import migrate
from workspace import ingest_kev
from psycopg.conninfo import conninfo_to_dict
from werkzeug.security import generate_password_hash
config={'database':conninfo_to_dict(os.environ['CTX_TEST_DSN']),'secret_key':secrets.token_hex(32),'admin_username':'test-admin','admin_password_hash':generate_password_hash('test-admin-password')}
n=0
def check(x,label):
 global n
 assert x,label
 n+=1
with connect(config) as c:
 before=c.execute("SELECT md5(string_agg(row(v.*)::text,'' ORDER BY vuln_id)) AS h FROM vulnerabilities v").fetchone()['h']
migrate(config);migrate(config)
app=create_app(config);app.testing=True

def login(username,password):
 client=app.test_client();csrf=client.get('/api/session').json['csrf'];r=client.post('/api/login',json={'username':username,'password':password},headers={'X-CSRF-Token':csrf});check(r.status_code==200,'login '+username);return client,{'X-CSRF-Token':r.json['csrf']}
a,h=login('test-admin','test-admin-password')
check(a.get('/api/tables/vulnerabilities').json['total']==45206,'original data')
for role in ('analyst','viewer'):
 check(a.post('/api/accounts',json={'username':role,'role':role,'password':'test-user-password'},headers=h).status_code==200,'create '+role)
v,vh=login('viewer','test-user-password');b,bh=login('analyst','test-user-password')
for path in ('tables/vulnerabilities','tables/incidents','export/incidents','accounts','audit','imports','reports/vw_active_incidents'):
 check(v.get('/api/'+path).status_code==403,'viewer denied '+path)
for path in ('tables/users','export/users','accounts','audit'):
 check(b.get('/api/'+path).status_code==403,'analyst denied '+path)
check(v.get('/api/reports/vw_viewer_intelligence').status_code==200,'public view')
check(v.post('/api/tables/threats',json={'values':{'name':'Denied'}},headers=vh).status_code==403,'viewer write denied')
check(b.post('/api/tables/threats',json={'values':{'name':'Allowed'}},headers=bh).status_code==201,'analyst write')
check(b.delete('/api/tables/threats',json={'key':{'threat_id':1}},headers=bh).status_code==403,'analyst deletion denied')
check(b.post('/api/research',json={'kind':'note','title':'Private'}).status_code==403,'csrf')
check(b.post('/api/research',json={'kind':'note','title':'Private'},headers=bh).status_code==200,'private note')
check(not v.get('/api/research').json['rows'],'notes private')
note=b.get('/api/research').json['rows'][0]['id']
check(v.delete('/api/research',json={'id':note},headers=vh).status_code==404,'ownership enforced')
check(v.post('/api/research',json={'kind':'watchlist','title':'Example'},headers=vh).status_code==200,'viewer watchlist')
fixture={'vulnerabilities':[{'cveID':'CVE-2099-99999','vendorProject':'Example','product':'Test product','shortDescription':'Test fixture only','requiredAction':'Review test advisory','dateAdded':'2026-01-01'}]}
with connect(config) as c: ingest_kev(c,fixture);ingest_kev(c,fixture)
check(len(v.get('/api/watchlist-matches').json['rows'])==1,'deduplicated watchlist match')
with connect(config) as c:
 check(c.execute("SELECT count(*) AS n FROM vulnerabilities WHERE cve_id='CVE-2099-99999'").fetchone()['n']==1,'import idempotent')
try:
 with connect(config) as c: ingest_kev(c,{'vulnerabilities':[dict(fixture['vulnerabilities'][0],cveID='CVE-2099-88888'),{'cveID':'bad'}]})
except ValueError: pass
with connect(config) as c:
 check(c.execute("SELECT count(*) AS n FROM vulnerabilities WHERE cve_id='CVE-2099-88888'").fetchone()['n']==0,'import rollback')
 c.execute("DELETE FROM ctx_kev WHERE cve_id='CVE-2099-99999'");c.execute("DELETE FROM vulnerabilities WHERE cve_id='CVE-2099-99999'")
 after=c.execute("SELECT md5(string_agg(row(v.*)::text,'' ORDER BY vuln_id)) AS h FROM vulnerabilities v").fetchone()['h'];check(before==after,'existing vulnerabilities unchanged')
accounts=a.get('/api/accounts').json['rows'];viewer=next(x for x in accounts if x['username']=='viewer');admin=next(x for x in accounts if x['username']=='test-admin')
check(a.put('/api/accounts',json={'id':admin['id'],'username':'test-admin','role':'viewer'},headers=h).status_code==400,'last admin preserved')
check(a.put('/api/accounts',json={'id':viewer['id'],'username':'viewer','role':'viewer','active':False},headers=h).status_code==200,'disable viewer')
check(v.get('/api/research').status_code==401,'existing session revoked')
check(len(a.get('/api/audit').json['rows'])>=3,'audit history')
for view in ('vw_vulnerability_summary','vw_active_incidents','vw_ioc_context','vw_campaign_overview','vw_analyst_workload','vw_viewer_intelligence'): check(a.get('/api/reports/'+view).status_code==200,'SQL view '+view)
check(a.get('/').status_code==200,'frontend served')
check(a.get('/api/tables/vulnerabilities?sort=invalid').status_code==400,'reject invalid sort')
check(a.get('/api/tables/vulnerabilities?sort=cve_id&direction=desc').status_code==200,'sorting')
check(a.get('/api/tables/vulnerabilities?q=CVE&severity=HIGH').status_code==200,'combined filter')
print(f'{n} upgrade checks passed')
if os.environ.get('CTX_BROWSER_CONFIG'):
 import json
 Path(os.environ['CTX_BROWSER_CONFIG']).write_text(json.dumps(config))
