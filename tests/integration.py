"""Run ONLY against an empty disposable PostgreSQL database.
Set CTX_TEST_DSN to its connection string, then python tests/integration.py.
The test creates all CTI tables and imports the bundled export.
"""
import os
import sys
from pathlib import Path
import secrets
import psycopg
from psycopg.conninfo import conninfo_to_dict
from werkzeug.security import generate_password_hash

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from app import create_app, connect, TABLES
from import_database import restore

dsn=os.environ.get('CTX_TEST_DSN')
if not dsn: raise SystemExit('Set CTX_TEST_DSN to an EMPTY DISPOSABLE database. Never use your working database.')
config={'database':conninfo_to_dict(dsn),'secret_key':secrets.token_hex(32),
        'admin_username':'test-admin','admin_password_hash':generate_password_hash('test-only-password')}
checks=0
def check(condition,message):
    global checks
    assert condition,message
    checks+=1

with connect(config) as conn:
    restore(conn,ROOT/'database')
    check(conn.execute('SELECT count(*) AS n FROM vulnerabilities').fetchone()['n']==45206,'export count')
    before=conn.execute("SELECT md5(string_agg(row(v.*)::text,'' ORDER BY vuln_id)) AS hash FROM vulnerabilities v").fetchone()['hash']

from migrate import migrate
migrate(config)
app=create_app(config)
client=app.test_client()
check(client.get('/api/dashboard').status_code==401,'anonymous read blocked')
s=client.get('/api/session').json
check(client.post('/api/login',json={'username':'test-admin','password':'wrong'},headers={'X-CSRF-Token':s['csrf']}).status_code==401,'wrong login blocked')
login=client.post('/api/login',json={'username':'test-admin','password':'test-only-password'},headers={'X-CSRF-Token':s['csrf']})
check(login.status_code==200,'login')
headers={'X-CSRF-Token':login.json['csrf']}
check(client.post('/api/tables/threats',json={'values':{'name':'blocked'}}).status_code==403,'CSRF protection')
schema=client.get('/api/schema').json
check(len(schema['tables'])==26,'schema table count')
for table in TABLES:
    r=client.get('/api/tables/'+table)
    check(r.status_code==200,'list '+table)
check(client.get('/api/tables/student').status_code==400,'unrelated table inaccessible')
v=client.get('/api/tables/vulnerabilities').json
check(v['total']==45206 and len(v['rows'])==25,f'real data pagination: total={v.get("total")!r}, rows={len(v.get("rows", []))}')
check(client.get('/api/tables/vulnerabilities?page=2').json['rows'][0]['vuln_id']!=v['rows'][0]['vuln_id'],'second page')
cve=v['rows'][0]['cve_id']
check(client.get('/api/tables/vulnerabilities',query_string={'q':cve}).json['total']>=1,'CVE search')

def post(table,values,status=201):
    r=client.post('/api/tables/'+table,json={'values':values},headers=headers)
    check(r.status_code==status,f'{table}: {r.status_code} {r.json}')
    return r.json.get('row')

threat=post('threats',{'name':'Integration test','description':"O'Reilly <script>alert(1)</script>",'risk_score':65})
key={'threat_id':threat['threat_id']}
with connect(config) as conn:
    check(conn.execute('SELECT risk_score FROM threats WHERE threat_id=%s',(threat['threat_id'],)).fetchone()['risk_score']==65,'independent database read after API write')
u=client.put('/api/tables/threats',json={'key':key,'values':{'risk_score':75}},headers=headers)
check(u.status_code==200,'update')
with connect(config) as conn:
    check(conn.execute('SELECT risk_score FROM threats WHERE threat_id=%s',(threat['threat_id'],)).fetchone()['risk_score']==75,'update committed')
post('threats',{'name':'Invalid score','risk_score':200},400)
check(client.get('/api/tables/threats?q=Invalid%20score').json['total']==0,'failed insert rolled back')
post('threats',{'threat_id':999,'name':'Manual ID'},400)
post('threats',{'name':' '},400)
post('iocs',{'type':'IPv4','raw_data':'192.0.2.77','threat_id':-999},400)
incident=post('incidents',{'incident_type':'Security','detected_at':'2026-09-11T10:00:00','status':'Open','description':'Integration test'})
ik={'incident_id':incident['incident_id']}
post('incident_vuln',{'incident_id':incident['incident_id'],'vuln_id':v['rows'][0]['vuln_id']})
post('incident_vuln',{'incident_id':incident['incident_id'],'vuln_id':v['rows'][0]['vuln_id']},400)
post('attachments',{'incident_id':incident['incident_id'],'attach_no':1,'name':'test.txt','type':'text/plain','size':4})
post('attachment_hashes',{'incident_id':incident['incident_id'],'attach_no':1,'hash':'test-metadata'})
check(client.delete('/api/tables/incidents',json={'key':ik},headers=headers).status_code==200,'delete incident')
check(client.get('/api/tables/incident_vuln').json['total']==0,'relationship cascade')
check(client.get('/api/tables/attachment_hashes').json['total']==0,'weak entity cascade')
check(client.get('/api/export/threats').status_code==200,'CSV export')
check(client.get('/api/tables/threats',query_string={'q':"'; DROP TABLE threats; --"}).json['total']==0,'search injection treated literally')
check(client.delete('/api/tables/threats',json={'key':key},headers=headers).status_code==200,'delete threat')

# Seed twice to verify exact-schema compatibility and repeatability.
seed=(ROOT/'database/sample_data.sql').read_text()
with connect(config) as conn:
    conn.execute(seed)
with connect(config) as conn:
    counts1={t:conn.execute(f'SELECT count(*) AS n FROM public.{t}').fetchone()['n'] for t in TABLES}
with connect(config) as conn:
    conn.execute(seed)
with connect(config) as conn:
    counts2={t:conn.execute(f'SELECT count(*) AS n FROM public.{t}').fetchone()['n'] for t in TABLES}
    after=conn.execute("SELECT md5(string_agg(row(v.*)::text,'' ORDER BY vuln_id)) AS hash FROM vulnerabilities v").fetchone()['hash']
check(counts1==counts2,'seed idempotent')
check(before==after,'all original vulnerability values unchanged')
check(counts2['iocs']==12 and counts2['incidents']==6,'sample counts')
check(client.get('/api/dashboard').json['counts']['vulnerabilities']==45206,'dashboard real counts')
check(client.post('/api/logout',headers=headers).status_code==200,'logout')
check(client.get('/api/tables/vulnerabilities').status_code==401,'session invalidated')
print(f'PASS: {checks} integration checks. All 45,206 exported vulnerability rows preserved.')
