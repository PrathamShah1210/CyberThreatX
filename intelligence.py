"""Source-backed catalog, exact IOC lookup and review/publication boundary."""
import ipaddress,re,time,threading
from urllib.parse import urlsplit,urlunsplit
from flask import request,session,jsonify,abort
from psycopg.types.json import Jsonb
from workspace import audit

KINDS={'ip','domain','url','md5','sha1','sha256'}

def normalized(value,kind='auto'):
 if not isinstance(value,str) or not value.strip() or len(value)>4096: raise ValueError('Enter an indicator of at most 4096 characters.')
 value=value.strip()
 if any(ord(c)<32 for c in value): raise ValueError('Control characters are not allowed.')
 if kind=='auto':
  if re.fullmatch('[a-fA-F0-9]{64}',value): kind='sha256'
  elif re.fullmatch('[a-fA-F0-9]{40}',value): kind='sha1'
  elif re.fullmatch('[a-fA-F0-9]{32}',value): kind='md5'
  elif '://' in value: kind='url'
  else:
   try: ipaddress.ip_address(value);kind='ip'
   except ValueError: kind='domain'
 if kind not in KINDS: raise ValueError('Unsupported indicator type.')
 if kind=='ip': return kind,str(ipaddress.ip_address(value))
 if kind in ('md5','sha1','sha256'):
  if not re.fullmatch('[a-fA-F0-9]{%d}'%{'md5':32,'sha1':40,'sha256':64}[kind],value): raise ValueError('Invalid hash length or characters.')
  return kind,value.lower()
 def host(h):
  try: return str(ipaddress.ip_address(h))
  except ValueError: pass
  h=h.rstrip('.').encode('idna').decode().lower()
  if len(h)>253 or '.' not in h or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in h.split('.')): raise ValueError('Enter a valid domain name.')
  if re.fullmatch(r'[0-9.]+',h): raise ValueError('Invalid IP address.')
  return h
 if kind=='domain': return kind,host(value)
 parts=urlsplit(value)
 if parts.scheme.lower() not in ('http','https') or not parts.hostname: raise ValueError('Only complete HTTP/HTTPS URLs are supported.')
 if parts.username is not None or parts.password is not None: raise ValueError('Remove credentials from the URL.')
 h=host(parts.hostname);port=parts.port;authority='['+h+']' if ':' in h else h
 if port and (parts.scheme.lower(),port) not in (('http',80),('https',443)): authority+=':'+str(port)
 # Preserve path case, query ordering and escapes. Fragments are not sent to servers.
 return kind,urlunsplit((parts.scheme.lower(),authority,parts.path or '/',parts.query,''))

def reference(value):
 if not isinstance(value,str) or len(value)>4096: raise ValueError('A source reference is required.')
 p=urlsplit(value)
 if p.scheme!='https' or not p.hostname or p.username: raise ValueError('Use an HTTPS source reference without credentials.')
 return value

def stage(c,key,category,title,summary,source,url,payload,legacy_table=None,legacy_id=None):
 c.execute('SELECT pg_advisory_xact_lock(72626415)')
 source_row=c.execute('SELECT source_id FROM sources WHERE source_name=%s ORDER BY source_id LIMIT 1',(source[:150],)).fetchone()
 sid=source_row['source_id'] if source_row else c.execute("INSERT INTO sources(source_name,source_type) VALUES (%s,'Public intelligence') RETURNING source_id",(source[:150],)).fetchone()['source_id']
 c.execute('INSERT INTO source_urls(source_id,url) VALUES (%s,%s) ON CONFLICT DO NOTHING',(sid,reference(url)))
 # Published snapshots are immutable to automatic refresh. Changes re-enter review.
 return c.execute('''INSERT INTO ctx_catalog(external_key,category,title,summary,source_name,source_url,payload,legacy_table,legacy_id)
 VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
 ON CONFLICT(external_key) DO UPDATE SET title=CASE WHEN ctx_catalog.payload IS DISTINCT FROM excluded.payload THEN excluded.title ELSE ctx_catalog.title END,summary=CASE WHEN ctx_catalog.payload IS DISTINCT FROM excluded.payload THEN excluded.summary ELSE ctx_catalog.summary END,payload=excluded.payload,
 source_url=CASE WHEN ctx_catalog.payload IS DISTINCT FROM excluded.payload THEN excluded.source_url ELSE ctx_catalog.source_url END,updated_at=CASE WHEN ctx_catalog.payload IS DISTINCT FROM excluded.payload THEN now() ELSE ctx_catalog.updated_at END,
 state=CASE WHEN ctx_catalog.payload IS DISTINCT FROM excluded.payload THEN 'incoming' ELSE ctx_catalog.state END
 RETURNING id''',(key,category,title,summary,source,reference(url),Jsonb(payload),legacy_table,legacy_id)).fetchone()['id']

def observe(c,catalog_id,kind,value,verdict,confidence=None,first=None,last=None):
 if c.execute('SELECT state FROM ctx_catalog WHERE id=%s',(catalog_id,)).fetchone()['state']=='published':return
 kind,value=normalized(value,kind)
 if verdict not in ('malicious','suspicious','benign','unknown'): raise ValueError('Invalid verdict.')
 iid=c.execute('INSERT INTO ctx_indicator_values(kind,value) VALUES (%s,%s) ON CONFLICT(kind,value) DO UPDATE SET value=excluded.value RETURNING id',(kind,value)).fetchone()['id']
 item=c.execute('SELECT legacy_id,source_name FROM ctx_catalog WHERE id=%s',(catalog_id,)).fetchone()
 if not item['legacy_id']:
  sid=c.execute('SELECT source_id FROM sources WHERE source_name=%s ORDER BY source_id LIMIT 1',(item['source_name'][:150],)).fetchone()['source_id']
  legacy=c.execute('INSERT INTO iocs(type,raw_data,source_id) VALUES (%s,%s,%s) RETURNING ioc_id',(kind,value,sid)).fetchone()['ioc_id']
  c.execute("UPDATE ctx_catalog SET legacy_table='iocs',legacy_id=%s WHERE id=%s",(legacy,catalog_id))
 c.execute('''INSERT INTO ctx_observations(indicator_id,catalog_id,verdict,confidence,first_seen,last_seen) VALUES (%s,%s,%s,%s,%s,%s)
 ON CONFLICT(indicator_id,catalog_id) DO UPDATE SET verdict=excluded.verdict,confidence=excluded.confidence,first_seen=excluded.first_seen,last_seen=excluded.last_seen,recorded_at=now()''',(iid,catalog_id,verdict,confidence,first,last))

PUBLIC_COLUMNS='id,category,title,summary,source_name,source_url,published_at,updated_at'

def install(app,config,connect,protected):
 throttle={};lock=threading.Lock()
 def rate(bucket,limit):
  now=time.monotonic();key=(request.remote_addr,bucket)
  with lock:
   if len(throttle)>10000:
    for k in list(throttle):
     if now-throttle[k][0]>3600: del throttle[k]
   start,n=throttle.get(key,(now,0))
   if now-start>3600:start,n=now,0
   if n>=limit:abort(429)
   throttle[key]=(start,n+1)
 def csrf():
  import secrets
  token=request.headers.get('X-CSRF-Token','')
  if not token or not secrets.compare_digest(token,session.get('csrf','missing')):abort(403)
 def analyst():
  if session['role'] not in ('analyst','admin'):abort(403)
 @app.get('/api/public/catalog')
 def catalog():
  rate('read',1200)
  q=request.args.get('q','')[:200];category=request.args.get('category','');page=max(1,int(request.args.get('page',1)))
  clauses=["state='published'"];params=[]
  if category:clauses.append('category=%s');params.append(category)
  if q:clauses.append('(title ILIKE %s OR summary ILIKE %s)');params+=['%'+q+'%']*2
  where=' AND '.join(clauses)
  with connect(config) as c:
   total=c.execute('SELECT count(*) AS n FROM ctx_catalog WHERE '+where,params).fetchone()['n']
   rows=c.execute('SELECT '+PUBLIC_COLUMNS+' FROM ctx_catalog WHERE '+where+' ORDER BY published_at DESC,id DESC LIMIT 24 OFFSET %s',params+[(page-1)*24]).fetchall()
   counts=c.execute("SELECT category,count(*) AS count FROM ctx_catalog WHERE state='published' GROUP BY category").fetchall()
  return jsonify(rows=rows,total=total,page=page,counts=counts)
 @app.get('/api/public/catalog/<int:item_id>')
 def detail(item_id):
  with connect(config) as c:
   row=c.execute('SELECT '+PUBLIC_COLUMNS+" FROM ctx_catalog WHERE id=%s AND state='published'",(item_id,)).fetchone()
   if not row:abort(404)
   links=c.execute('''SELECT t.id,t.title,t.category,l.relationship,l.source_url FROM ctx_catalog_links l JOIN ctx_catalog t ON t.id=l.to_id WHERE l.from_id=%s AND t.state='published'
    UNION SELECT t.id,t.title,t.category,'reverse: '||l.relationship,l.source_url FROM ctx_catalog_links l JOIN ctx_catalog t ON t.id=l.from_id WHERE l.to_id=%s AND t.state='published' ''',(item_id,item_id)).fetchall()
  return jsonify(item=row,relationships=links)
 @app.post('/api/public/lookup')
 def lookup():
  csrf();rate('lookup',300)
  d=request.get_json(silent=True) or {};kind,value=normalized(d.get('value'),d.get('kind','auto'))
  with connect(config) as c:
   query='''SELECT o.verdict,o.confidence,o.first_seen,o.last_seen,o.recorded_at,c.id,c.title,c.source_name,c.source_url,c.updated_at
    FROM ctx_indicator_values i JOIN ctx_observations o ON o.indicator_id=i.id JOIN ctx_catalog c ON c.id=o.catalog_id
    WHERE i.kind=%s AND i.value=%s AND c.state='published' ORDER BY o.recorded_at DESC LIMIT 100'''
   rows=c.execute(query,(kind,value)).fetchall();related=[]
   verdicts={r['verdict'] for r in c.execute("SELECT DISTINCT o.verdict FROM ctx_indicator_values i JOIN ctx_observations o ON o.indicator_id=i.id JOIN ctx_catalog c ON c.id=o.catalog_id WHERE i.kind=%s AND i.value=%s AND c.state='published'",(kind,value)).fetchall()}
   if kind=='url':
    host=urlsplit(value).hostname
    try:k,v=normalized(host,'ip')
    except ValueError:k,v=normalized(host,'domain')
    related=c.execute(query,(k,v)).fetchall()
  result='conflicting_reports' if 'benign' in verdicts and verdicts&{'malicious','suspicious'} else 'recorded_malicious' if 'malicious' in verdicts else 'recorded_suspicious' if 'suspicious' in verdicts else 'source_reports_benign' if 'benign' in verdicts else 'unclassified_record' if rows else 'no_matching_intelligence'
  return jsonify(kind=kind,value=value,result=result,exact_matches=rows,related_host_matches=related,
   explanation='Historical source reports, not a live scan. No match does not mean safe. Related host matches do not establish the verdict of this exact URL.')
 @app.post('/api/public/submissions')
 def submission():
  csrf();rate('submit',10)
  d=request.get_json(silent=True) or {};kind,value=normalized(d.get('value'),d.get('kind','auto'));note=d.get('note','')
  if not isinstance(note,str) or len(note)>2000:raise ValueError('Notes must be under 2000 characters.')
  import hashlib
  key='submission:'+hashlib.sha256((kind+':'+value).encode()).hexdigest()
  with connect(config) as c:
   existing=c.execute('SELECT id FROM ctx_catalog WHERE external_key=%s',(key,)).fetchone()
   if not existing:
    cid=stage(c,key,'indicator',value,'Unverified public submission','Public submission','https://example.invalid/unverified',{'kind':kind,'value':value,'submission_note':note})
    observe(c,cid,kind,value,'unknown')
  # Do not reveal prior submission existence or internal record IDs.
  return jsonify(ok=True,message='Submitted for analyst review. This does not classify the indicator as malicious.'),202
 @app.route('/api/desk',methods=['GET','POST'])
 @protected
 def desk():
  analyst()
  with connect(config) as c:
   if request.method=='GET':
    state=request.args.get('state','incoming');q=request.args.get('q','')[:200];page=max(1,int(request.args.get('page',1)))
    rows=c.execute('SELECT ctx_catalog.*,(SELECT verdict FROM ctx_observations o WHERE o.catalog_id=ctx_catalog.id LIMIT 1) AS observation_verdict FROM ctx_catalog WHERE state=%s AND (title ILIKE %s OR source_name ILIKE %s) ORDER BY id DESC LIMIT 50 OFFSET %s',(state,'%'+q+'%','%'+q+'%',(page-1)*50)).fetchall()
    counts=c.execute('SELECT state,count(*) AS count FROM ctx_catalog GROUP BY state').fetchall()
    return jsonify(rows=rows,counts=counts,page=page)
   d=request.get_json() or {}
   category=d.get('category');title=d.get('title','');summary=d.get('summary','')
   if category not in ('indicator','advisory','actor','campaign','threat','vulnerability') or not isinstance(title,str) or not title.strip() or len(title)>4096: raise ValueError('Choose a category and enter a title.')
   if not isinstance(summary,str) or len(summary)>20000:raise ValueError('Summary too long.')
   source=d.get('source_name','').strip();url=reference(d.get('source_url'))
   if not source:raise ValueError('Source name required.')
   import hashlib
   key='manual:'+hashlib.sha256((category+'|'+title.strip()+'|'+url).encode()).hexdigest()
   old=c.execute('SELECT id FROM ctx_catalog WHERE external_key=%s',(key,)).fetchone()
   if old:return jsonify(error='A record from this source already exists.',existing_id=old['id']),409
   cid=stage(c,key,category,title.strip(),summary,source,url,{'manual':True})
   if category=='indicator':observe(c,cid,d.get('kind','auto'),title,d.get('verdict','unknown'),d.get('confidence'))
   audit(c,'intelligence_add','catalog',{'id':cid})
  return jsonify(id=cid),201
 @app.put('/api/desk/<int:item_id>')
 @protected
 def review(item_id):
  analyst();d=request.get_json() or {};target=d.get('state');note=d.get('review_note','')
  if target not in ('review','ready','published','rejected','duplicate','withdrawn'):raise ValueError('Invalid review state.')
  if not isinstance(note,str) or not note.strip() or len(note)>4000:raise ValueError('A review note is required (up to 4000 characters).')
  if target in ('published','withdrawn') and session['role']!='admin':abort(403)
  with connect(config) as c:
   item=c.execute('SELECT * FROM ctx_catalog WHERE id=%s FOR UPDATE',(item_id,)).fetchone()
   if not item:abort(404)
   if item['state']=='published' and target!='withdrawn':raise ValueError('Withdraw published content before editing it.')
   if target=='published' and item['state']!='ready':raise ValueError('Only reviewed, ready items may be published.')
   if target=='withdrawn' and item['state']!='published':raise ValueError('Only published items can be withdrawn.')
   if target in ('ready','published') and (item['source_name']=='Public submission' or 'example.invalid' in item['source_url']):raise ValueError('Replace the unverified submission reference with source evidence before approval.')
   updates={'state':target,'review_note':note,'assigned_to':session['account_id'],'reviewed_by':session['account_id']}
   if 'summary' in d:
    if not isinstance(d['summary'],str) or len(d['summary'])>20000:raise ValueError('Invalid summary.')
    updates['summary']=d['summary']
   if 'source_url' in d:updates['source_url']=reference(d['source_url'])
   if 'source_name' in d:
    if not isinstance(d['source_name'],str) or not d['source_name'].strip():raise ValueError('Source name required.')
    updates['source_name']=d['source_name'].strip()
   from psycopg import sql
   c.execute(sql.SQL('UPDATE ctx_catalog SET {} ,updated_at=now() WHERE id=%s').format(sql.SQL(',').join(sql.SQL('{}=%s').format(sql.Identifier(k)) for k in updates)),list(updates.values())+[item_id])
   if 'verdict' in d:
    if item['category']!='indicator' or d['verdict'] not in ('malicious','suspicious','benign','unknown'):raise ValueError('Invalid indicator verdict.')
    c.execute('UPDATE ctx_observations SET verdict=%s,recorded_at=now() WHERE catalog_id=%s',(d['verdict'],item_id))
   if target=='published':c.execute('UPDATE ctx_catalog SET published_at=now(),published_by=%s WHERE id=%s',(session['account_id'],item_id))
   audit(c,'intelligence_'+target,'catalog',{'id':item_id})
  return jsonify(ok=True)
 @app.post('/api/desk/relationships')
 @protected
 def relationship():
  if session['role']!='admin':abort(403)
  analyst();d=request.get_json() or {};ref=reference(d.get('source_url'));relation=d.get('relationship','')
  if relation not in ('attributed-to','uses','targets','related-to'):raise ValueError('Unsupported relationship.')
  with connect(config) as c:
   c.execute('INSERT INTO ctx_catalog_links(from_id,to_id,relationship,source_url) VALUES (%s,%s,%s,%s)',(d.get('from_id'),d.get('to_id'),relation,ref))
   audit(c,'relationship_add','catalog',{'from':d.get('from_id'),'to':d.get('to_id')})
  return jsonify(ok=True),201
 @app.errorhandler(429)
 def limited(e):return jsonify(error='Too many requests. Please try later.'),429
