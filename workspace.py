"""Account management, private research, SQL reports, and CISA KEV import."""
import json,re
from urllib.request import urlopen
from flask import request,jsonify,session,abort
from werkzeug.security import generate_password_hash
from psycopg import sql
from psycopg.types.json import Jsonb

PEOPLE={'users','roles','permissions','user_role','user_phones'}
VIEWS=('vw_vulnerability_summary','vw_active_incidents','vw_ioc_context','vw_campaign_overview','vw_analyst_workload','vw_viewer_intelligence')
FEED='https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

def audit(conn,action,entity,key=None):
 conn.execute('INSERT INTO ctx_audit(actor_id,action,entity,record_key) VALUES (%s,%s,%s,%s)',(session.get('account_id'),action,entity,Jsonb(key)))

def install(app,config,connect,protected):
 def admin():
  if session.get('role')!='admin': abort(403)
 @app.get('/api/assignees')
 @protected
 def assignees():
  if session['role']=='viewer': abort(403)
  with connect(config) as c:
   return jsonify(rows=c.execute("SELECT id,username FROM ctx_accounts WHERE active AND role IN ('admin','analyst') ORDER BY username").fetchall())
 @app.route('/api/accounts',methods=['GET','POST','PUT'])
 @protected
 def accounts():
  admin()
  with connect(config) as c:
   if request.method=='GET': return jsonify(rows=c.execute('SELECT id,username,role,active,created_at FROM ctx_accounts ORDER BY id').fetchall())
   d=request.get_json() or {}; role=d.get('role'); username=d.get('username','').strip(); password=d.get('password','')
   if role not in ('admin','analyst','viewer') or not re.fullmatch(r'[A-Za-z0-9_.-]{3,100}',username): raise ValueError('Use a valid role and a username of 3–100 letters, numbers, dots, dashes or underscores.')
   if password and (not isinstance(password,str) or len(password)<12): raise ValueError('Password needs at least 12 characters.')
   if request.method=='POST':
    if not password: raise ValueError('Password is required.')
    row=c.execute('INSERT INTO ctx_accounts(username,password_hash,role) VALUES (%s,%s,%s) RETURNING id',(username,generate_password_hash(password),role)).fetchone()
   else:
    # Serialize account changes so concurrent demotions cannot remove every administrator.
    c.execute('LOCK TABLE ctx_accounts IN SHARE ROW EXCLUSIVE MODE')
    old=c.execute('SELECT * FROM ctx_accounts WHERE id=%s',(d.get('id'),)).fetchone()
    if not old: abort(404)
    active=d.get('active',True)
    if not isinstance(active,bool): raise ValueError('Active must be true or false.')
    if old['role']=='admin' and (role!='admin' or not active) and c.execute("SELECT count(*) AS n FROM ctx_accounts WHERE role='admin' AND active").fetchone()['n']<=1: raise ValueError('Keep at least one active administrator.')
    row=c.execute('UPDATE ctx_accounts SET username=%s,role=%s,active=%s,password_hash=%s,session_version=session_version+1 WHERE id=%s RETURNING id',(username,role,active,generate_password_hash(password) if password else old['password_hash'],old['id'])).fetchone()
   audit(c,'account_change','accounts',row)
  return jsonify(ok=True)
 @app.route('/api/research',methods=['GET','POST','DELETE','PUT'])
 @protected
 def research():
  uid=session['account_id']
  with connect(config) as c:
   if request.method=='GET': return jsonify(rows=c.execute('SELECT * FROM ctx_research WHERE owner_id=%s ORDER BY id DESC',(uid,)).fetchall())
   d=request.get_json() or {}
   if request.method=='POST':
    if d.get('kind') not in ('watchlist','bookmark','note','search','review') or not isinstance(d.get('title'),str) or not d['title'].strip(): raise ValueError('Choose a type and enter a title.')
    c.execute('INSERT INTO ctx_research(owner_id,kind,title,content) VALUES (%s,%s,%s,%s)',(uid,d['kind'],d['title'].strip(),d.get('content','')))
   else:
    if request.method=='DELETE': r=c.execute('DELETE FROM ctx_research WHERE id=%s AND owner_id=%s RETURNING id',(d.get('id'),uid)).fetchone()
    else:
     if d.get('status') not in ('open','done'): raise ValueError('Invalid status.')
     r=c.execute('UPDATE ctx_research SET status=%s WHERE id=%s AND owner_id=%s RETURNING id',(d['status'],d.get('id'),uid)).fetchone()
    if not r: abort(404)
  return jsonify(ok=True)
 @app.get('/api/watchlist-matches')
 @protected
 def matches():
  with connect(config) as c:
   rows=c.execute("""SELECT DISTINCT k.cve_id,k.vendor,k.product,k.required_action,k.source_url FROM ctx_research r JOIN ctx_kev k ON position(lower(r.title) in lower(k.vendor||' '||k.product))>0 WHERE r.owner_id=%s AND r.kind='watchlist' AND (%s OR EXISTS(SELECT 1 FROM ctx_catalog c WHERE c.external_key='cisa:'||k.cve_id AND c.state='published')) ORDER BY k.cve_id DESC LIMIT 100""",(session['account_id'],session['role']!='viewer')).fetchall()
  return jsonify(rows=rows,note='Possible product-name matches. Verify the affected version and configuration in the original advisory.')
 @app.get('/api/reports/<name>')
 @protected
 def reports(name):
  if name not in VIEWS: abort(404)
  if session['role']=='viewer' and name!='vw_viewer_intelligence': abort(403)
  with connect(config) as c:
   rows=c.execute(sql.SQL('SELECT * FROM {} LIMIT 200').format(sql.Identifier(name))).fetchall()
  return jsonify(rows=rows,limit=200)
 @app.get('/api/audit')
 @protected
 def history():
  admin()
  with connect(config) as c: return jsonify(rows=c.execute('SELECT x.*,a.username FROM ctx_audit x LEFT JOIN ctx_accounts a ON a.id=x.actor_id ORDER BY x.id DESC LIMIT 200').fetchall())
 @app.route('/api/imports',methods=['GET','POST'])
 @protected
 def imports():
  admin()
  with connect(config) as c:
   if request.method=='GET': return jsonify(rows=c.execute('SELECT * FROM ctx_import_runs ORDER BY id DESC LIMIT 30').fetchall())
   run=c.execute("INSERT INTO ctx_import_runs(source,status) VALUES ('CISA KEV','running') RETURNING id").fetchone()['id']
  try:
   with urlopen(FEED,timeout=30) as response:
    raw=response.read(12_000_001)
   if len(raw)>12_000_000: raise ValueError('Feed exceeds size limit.')
   payload=json.loads(raw)
   with connect(config) as c:
    from feeds import stage_kev
    count=stage_kev(c,payload)
    c.execute("UPDATE ctx_import_runs SET status='success',finished_at=now(),records=%s WHERE id=%s",(count,run))
    audit(c,'import','CISA KEV',{'records':count})
   return jsonify(ok=True,records=count)
  except Exception:
   with connect(config) as c: c.execute("UPDATE ctx_import_runs SET status='failed',finished_at=now(),message='Download or validation failed; no feed records committed. Retry when connectivity is available.' WHERE id=%s",(run,))
   return jsonify(error='Import failed. No partial feed changes were saved. Check connectivity and import history.'),502

def ingest_kev(conn,payload):
 records=payload.get('vulnerabilities')
 if not isinstance(records,list) or not records: raise ValueError('Invalid or empty KEV feed.')
 conn.execute('SELECT pg_advisory_xact_lock(72626412)')
 for r in records:
  if not re.fullmatch(r'CVE-\d{4}-\d{4,}',r.get('cveID','')): raise ValueError('Invalid CVE identifier.')
  for field in ('vendorProject','product','shortDescription','requiredAction','dateAdded'):
   if not isinstance(r.get(field),str) or not r[field]: raise ValueError('Incomplete KEV entry.')
  # Preserve original descriptions and severity for existing CVEs.
  conn.execute("INSERT INTO vulnerabilities(cve_id,description,severity) VALUES (%s,%s,'Unknown') ON CONFLICT(cve_id) DO NOTHING",(r['cveID'],r['shortDescription']))
  conn.execute('''INSERT INTO ctx_kev(cve_id,vendor,product,required_action,date_added,due_date,source_url,raw_record) VALUES (%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(cve_id) DO UPDATE SET vendor=excluded.vendor,product=excluded.product,required_action=excluded.required_action,date_added=excluded.date_added,due_date=excluded.due_date,raw_record=excluded.raw_record,imported_at=now()''',(r['cveID'],r['vendorProject'],r['product'],r['requiredAction'],r['dateAdded'],r.get('dueDate') or None,'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',Jsonb(r)))
 return len(records)
