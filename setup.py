"""Interactive local configuration; credentials never enter frontend code."""
import getpass
import json
import os
import secrets
from pathlib import Path
import psycopg
from werkzeug.security import generate_password_hash

ROOT = Path(__file__).resolve().parent

def ask(label, default):
    return input(f'{label} [{default}]: ').strip() or default

if __name__ == '__main__':
    path = ROOT / 'config.json'
    if path.exists():
        print('config.json already exists. Edit it to change the connection; no settings overwritten.')
        raise SystemExit(0)
    print('Connect to the EXISTING PostgreSQL database shown in pgAdmin.')
    db = {'host': ask('Host','localhost'), 'port':int(ask('Port','5432')),
          'dbname':ask('Database name','cyberthreatx'), 'user':ask('Database username',getpass.getuser()),
          'password':getpass.getpass('Database password (blank if local trust authentication): ')}
    try:
        with psycopg.connect(**db,connect_timeout=5) as conn:
            count = conn.execute('SELECT count(*) FROM public.vulnerabilities').fetchone()[0]
            print(f'Connected. Found {count:,} vulnerability records.')
    except psycopg.Error as e:
        print('Connection failed. Check host, database name and credentials in pgAdmin.')
        print(str(e))
        raise SystemExit(1)
    username = ask('Website administrator username','pratham')
    while True:
        password = getpass.getpass('Choose website password (at least 12 characters): ')
        if len(password)>=12 and password==getpass.getpass('Confirm website password: '): break
        print('Passwords must match and contain at least 12 characters.')
    config = {'database':db,'admin_username':username,
              'admin_password_hash':generate_password_hash(password),
              'secret_key':secrets.token_hex(32),'secure_cookie':False}
    fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f: json.dump(config,f,indent=2)
    print('Saved. Run python app.py, then open http://127.0.0.1:8000')
