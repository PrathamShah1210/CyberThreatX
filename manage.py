"""Local account recovery, database backup, and offline CISA JSON import."""
import argparse,getpass,json,os,subprocess
from pathlib import Path
from werkzeug.security import generate_password_hash
from app import read_config,connect
from feeds import stage_kev as ingest_kev
p=argparse.ArgumentParser();p.add_argument('action',choices=['reset-login','backup','import-kev']);p.add_argument('--file');a=p.parse_args();config=read_config()
if a.action=='reset-login':
 username=input('Existing website username: ').strip()
 password=getpass.getpass('New password (12+ characters): ')
 if len(password)<12 or password!=getpass.getpass('Confirm password: '): raise SystemExit('Passwords must match and contain at least 12 characters.')
 with connect(config) as c:
  r=c.execute('UPDATE ctx_accounts SET password_hash=%s,session_version=session_version+1 WHERE username=%s RETURNING id',(generate_password_hash(password),username)).fetchone()
  if not r: raise SystemExit('Username not found. Use the administrator Accounts screen to create an account.')
 print('Password reset. Existing sessions revoked.')
elif a.action=='backup':
 if not a.file: raise SystemExit('Pass --file /private/path/cyberthreatx.dump')
 d=config['database'];env=os.environ.copy();env['PGPASSWORD']=d.get('password','')
 target=Path(a.file)
 fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 try:
  with os.fdopen(fd,'wb') as out:
   subprocess.run(['pg_dump','-Fc','-h',d.get('host','localhost'),'-p',str(d.get('port',5432)),'-U',d['user'],'-d',d['dbname']],stdout=out,env=env,check=True)
 except Exception:
  target.unlink(missing_ok=True);raise
 print('Backup saved. Test restoration into a separate empty database.')
else:
 if not a.file: raise SystemExit('Pass --file known_exploited_vulnerabilities.json')
 payload=json.loads(Path(a.file).read_text())
 with connect(config) as c:
  n=ingest_kev(c,payload)
  c.execute("INSERT INTO ctx_import_runs(source,status,records,finished_at,message) VALUES ('CISA KEV local JSON','success',%s,now(),'Imported from operator-provided file')",(n,))
 print(f'Imported {n} entries; existing vulnerability records preserved.')
