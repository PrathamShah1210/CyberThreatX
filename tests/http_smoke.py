"""HTTP smoke test against an already initialized DISPOSABLE test database.
Set CTX_TEST_DSN. Starts the delivered WSGI app on an ephemeral local port.
"""
import http.cookiejar
import json
import os
import secrets
import sys
import threading
import urllib.request
from pathlib import Path
from psycopg.conninfo import conninfo_to_dict
from werkzeug.security import generate_password_hash
from waitress import create_server
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app import create_app,connect

dsn=os.environ.get('CTX_TEST_DSN')
if not dsn: raise SystemExit('Set CTX_TEST_DSN to a disposable test database, never your working database.')
password=secrets.token_urlsafe(24)
config={'database':conninfo_to_dict(dsn),'secret_key':secrets.token_hex(32),'admin_username':'http-test','admin_password_hash':generate_password_hash(password)}
server=create_server(create_app(config),host='127.0.0.1',port=0,threads=2)
threading.Thread(target=server.run,daemon=True).start()
base='http://127.0.0.1:'+str(server.effective_port)
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def call(path,body=None,token=None,method=None):
    headers={}
    if token: headers['X-CSRF-Token']=token
    if body is not None: headers['Content-Type']='application/json'
    request=urllib.request.Request(base+path,data=json.dumps(body).encode() if body is not None else None,headers=headers,method=method)
    with opener.open(request,timeout=30) as r:
        data=r.read()
        return json.loads(data) if r.headers.get_content_type()=='application/json' else data
try:
    assert b'CyberThreatX' in call('/')
    assert b'async function api' in call('/static/app.js')
    assert b'.workspace' in call('/static/style.css')
    token=call('/api/session')['csrf']
    token=call('/api/login',{'username':'http-test','password':password},token)['csrf']
    assert call('/api/dashboard')['counts']['vulnerabilities']==45206
    row=call('/api/tables/threats',{'values':{'name':'HTTP persistence verification','risk_score':50}},token)['row']
    key={'threat_id':row['threat_id']}
    with connect(config) as conn:
        assert conn.execute('SELECT risk_score FROM threats WHERE threat_id=%s',(row['threat_id'],)).fetchone()['risk_score']==50
    call('/api/tables/threats',{'key':key,'values':{'risk_score':80}},token,'PUT')
    result=call('/api/tables/threats?q=HTTP%20persistence%20verification')
    assert result['rows'][0]['risk_score']==80
    call('/api/tables/threats',{'key':key},token,'DELETE')
    assert call('/api/tables/threats?q=HTTP%20persistence%20verification')['total']==0
    print('PASS: Running Waitress server served frontend assets and completed authenticated HTTP create/read/update/delete with independent PostgreSQL verification.')
finally:
    server.close()
