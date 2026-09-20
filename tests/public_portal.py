"""Integration checks against an original-schema disposable PostgreSQL database."""
import os,sys,time,secrets
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
if os.environ.get('CTX_PGLITE_TEST'):
 import psycopg
 close=psycopg.Connection.close
 def settled(self):close(self);time.sleep(.03)
 psycopg.Connection.close=settled
from psycopg.conninfo import conninfo_to_dict
from werkzeug.security import generate_password_hash
from app import connect,create_app
from migrate import migrate
from intelligence import normalized,stage,observe
from feeds import stage_mitre,stage_kev,stage_csv
config={'database':conninfo_to_dict(os.environ['CTX_TEST_DSN']),'secret_key':secrets.token_hex(32),'admin_username':'portal-admin','admin_password_hash':generate_password_hash('portal-admin-password')}
checks=0
def check(ok,label):
 global checks
 assert ok,label
 checks+=1
with connect(config) as c:before=c.execute("SELECT md5(string_agg(row(v.*)::text,'' ORDER BY vuln_id)) AS h FROM vulnerabilities v").fetchone()['h']
migrate(config);migrate(config)
app=create_app(config);app.testing=True
anon=app.test_client();csrf=anon.get('/api/session').json['csrf'];ah={'X-CSRF-Token':csrf}
def login(name,password):
 client=app.test_client();token=client.get('/api/session').json['csrf'];r=client.post('/api/login',json={'username':name,'password':password},headers={'X-CSRF-Token':token});check(r.status_code==200,'login');return client,{'X-CSRF-Token':r.json['csrf']}
a,h=login('portal-admin','portal-admin-password')
a.post('/api/accounts',json={'username':'reviewer','role':'analyst','password':'reviewer-password'},headers=h)
a.post('/api/accounts',json={'username':'citizen','role':'viewer','password':'citizen-password'},headers=h)
b,bh=login('reviewer','reviewer-password');v,vh=login('citizen','citizen-password')
check(anon.get('/').status_code==200,'public landing')
check(anon.get('/workspace').status_code==200,'login shell')
check(anon.get('/api/public/catalog').json['total']==0,'no accidental publication')
for path in ('/api/desk','/api/sources','/api/accounts','/api/tables/users'):check(anon.get(path).status_code==401,'anonymous protected '+path)
check(v.get('/api/desk').status_code==403,'viewer desk blocked')
check(b.get('/api/sources').status_code==403,'analyst settings blocked')
check(normalized('HTTPS://Example.COM:443/Case?B=2&a=1#fragment')==('url','https://example.com/Case?B=2&a=1'),'URL normalization preserves semantics')
check(normalized('2001:0db8::1')==('ip','2001:db8::1'),'IPv6 normalization')
check(normalized('A'*64)==('sha256','a'*64),'hash normalization')
for invalid in ('https://user:pass@example.com','999.999.999.999','javascript:alert(1)','bad value'):
 try:normalized(invalid);check(False,'invalid accepted')
 except ValueError:check(True,'invalid rejected')
check(anon.post('/api/public/lookup',json={'value':'example.org'}).status_code==403,'lookup csrf')
look=lambda val:anon.post('/api/public/lookup',json={'value':val},headers=ah).json
check(look('example.org')['result']=='no_matching_intelligence','unknown not safe')
r=b.post('/api/desk',json={'category':'indicator','title':'bad.example.org','summary':'Synthetic fixture only','source_name':'Test source','source_url':'https://example.org/report','verdict':'malicious'},headers=bh)
check(r.status_code==201,'analyst creates');cid=r.json['id']
check(look('bad.example.org')['result']=='no_matching_intelligence','unpublished IOC hidden')
check(anon.get('/api/public/catalog/'+str(cid)).status_code==404,'unpublished detail hidden')
check(b.put('/api/desk/'+str(cid),json={'state':'published','review_note':'bad bypass'},headers=bh).status_code==403,'analyst cannot publish')
check(a.put('/api/desk/'+str(cid),json={'state':'published','review_note':'skip review'},headers=h).status_code==400,'admin cannot skip review')
check(b.put('/api/desk/'+str(cid),json={'state':'ready','review_note':'Source checked'},headers=bh).status_code==200,'ready')
check(a.put('/api/desk/'+str(cid),json={'state':'published','review_note':'Approved'},headers=h).status_code==200,'publish')
check(look('BAD.EXAMPLE.ORG')['result']=='recorded_malicious','exact lookup')
x=look('https://bad.example.org/new');check(x['result']=='no_matching_intelligence' and len(x['related_host_matches'])==1,'host not exact URL verdict')
public=anon.get('/api/public/catalog').json['rows'][0];check('review_note' not in public and 'payload' not in public and 'assigned_to' not in public,'public projection')
check(b.put('/api/desk/'+str(cid),json={'state':'review','review_note':'edit'},headers=bh).status_code==400,'published immutable to analyst')
with connect(config) as c:
 other=stage(c,'test:benign','indicator','bad.example.org','Test only','Other source','https://example.org/other',{'test':True});observe(c,other,'domain','bad.example.org','benign');c.execute("UPDATE ctx_catalog SET state='published',published_at=now() WHERE id=%s",(other,))
check(look('bad.example.org')['result']=='conflicting_reports','conflicting evidence')
check(a.put('/api/desk/'+str(cid),json={'state':'withdrawn','review_note':'Withdraw test'},headers=h).status_code==200,'withdraw')
check(look('bad.example.org')['result']=='source_reports_benign','withdrawn no longer contributes')
check(anon.post('/api/public/submissions',json={'value':'new.example.org'},headers=ah).status_code==202,'public submission')
check(look('new.example.org')['result']=='no_matching_intelligence','submission not malicious')
with connect(config) as c:
 sub=c.execute("SELECT id FROM ctx_catalog WHERE source_name='Public submission'").fetchone()['id']
check(b.put('/api/desk/'+str(sub),json={'state':'ready','review_note':'No evidence'},headers=bh).status_code==400,'unverified cannot ready')
check(b.put('/api/desk/'+str(sub),json={'state':'review','review_note':'Evidence added','source_name':'Verified source','source_url':'https://example.org/evidence','verdict':'suspicious'},headers=bh).status_code==200,'submission evidence')
check(b.put('/api/desk/'+str(sub),json={'state':'ready','review_note':'Reviewed evidence'},headers=bh).status_code==200,'verified submission ready')
fixture={'type':'bundle','objects':[{'type':'intrusion-set','id':'intrusion-set--test','name':'TEST ACTOR','external_references':[{'source_name':'mitre-attack','url':'https://attack.mitre.org/groups/G0000/'}]},{'type':'campaign','id':'campaign--test','name':'TEST CAMPAIGN','external_references':[{'source_name':'mitre-attack','url':'https://attack.mitre.org/campaigns/C0000/'}]},{'type':'relationship','source_ref':'campaign--test','target_ref':'intrusion-set--test','relationship_type':'attributed-to'}]}
with connect(config) as c:
 check(stage_mitre(c,fixture)==2,'MITRE import');stage_mitre(c,fixture)
 check(c.execute("SELECT count(*) AS n FROM ctx_catalog WHERE external_key LIKE 'mitre:%'").fetchone()['n']==2,'MITRE dedup')
 check(c.execute('SELECT count(*) AS n FROM actor_campaign').fetchone()['n']==1,'explicit attribution mapping')
 fixture['objects'][0]['revoked']=True;stage_mitre(c,fixture)
 check(c.execute("SELECT state FROM ctx_catalog WHERE external_key='mitre:intrusion-set--test'").fetchone()['state']=='withdrawn','source revocation')
try:
 with connect(config) as c:stage_csv(c,[{'type':'sha256','value':'b'*64,'verdict':'malicious','source_name':'Test CSV','source_url':'https://example.org/csv'}, {'type':'bad'}])
except ValueError:pass
with connect(config) as c:
 check(c.execute("SELECT count(*) AS n FROM ctx_indicator_values WHERE value=%s",('b'*64,)).fetchone()['n']==0,'CSV rollback')
 after=c.execute("SELECT md5(string_agg(row(v.*)::text,'' ORDER BY vuln_id)) AS h FROM vulnerabilities v").fetchone()['h'];check(before==after,'45206 originals preserved')
check(a.get('/api/desk?state=ready').status_code==200,'queue browsing')
check(a.get('/api/public/catalog?category=actor&q=test').status_code==200,'public filtering')
check(a.post('/api/sources/starter',headers=h).json['records']==5,'real starter import')
check(a.post('/api/sources/starter',headers=h).json['records']==5,'starter repeatable')
with connect(config) as c:
 check(c.execute("SELECT count(*) AS n FROM ctx_catalog WHERE external_key LIKE 'starter:%'").fetchone()['n']==5,'starter no duplicates')
 sid=c.execute("SELECT id FROM ctx_catalog WHERE external_key='starter:wcry-c2'").fetchone()['id']
check(b.put('/api/desk/'+str(sid),json={'state':'ready','review_note':'Historical source verified'},headers=bh).status_code==200,'historical indicator ready')
check(a.put('/api/desk/'+str(sid),json={'state':'published','review_note':'Historical context retained'},headers=h).status_code==200,'historical indicator publish')
check(look('gx7ekbenv2riucmf.onion')['result']=='recorded_malicious','real historical IOC lookup')
check(anon.post('/api/public/lookup',json=[],headers=ah).status_code==400,'malformed JSON rejected')
check(b.post('/api/desk/relationships',json={},headers=bh).status_code==403,'analyst cannot change public relationships')
check(a.get('/api/desk?state=incoming').status_code==200,'queue with verdict projection')
with connect(config) as c:
 item=c.execute('SELECT * FROM ctx_catalog WHERE id=%s',(sid,)).fetchone()
 c.execute("UPDATE ctx_catalog SET summary='Reviewed historical snapshot' WHERE id=%s",(sid,))
 stage(c,item['external_key'],item['category'],item['title'],'Unreviewed replacement',item['source_name'],item['source_url'],item['payload'])
 observe(c,sid,'domain','gx7ekbenv2riucmf.onion','benign')
 check(c.execute('SELECT summary FROM ctx_catalog WHERE id=%s',(sid,)).fetchone()['summary']=='Reviewed historical snapshot','unchanged feed preserves reviewed summary')
check(look('gx7ekbenv2riucmf.onion')['result']=='recorded_malicious','unchanged feed preserves published verdict')
# A changed published feed observation must become private until re-reviewed.
with connect(config) as c:
 stage(c,'starter:wcry-c2','indicator','gx7ekbenv2riucmf.onion','Changed test source snapshot','Secureworks CTU (Sophos)','https://www.sophos.com/en-us/research/wcry-ransomware-analysis',{'changed':True})
check(look('gx7ekbenv2riucmf.onion')['result']=='no_matching_intelligence','changed feed requires rereview')
print(f'{checks} public portal checks passed')
