"""Transactional, additive upgrade. Does not restore or overwrite existing intelligence."""
from pathlib import Path
from app import connect, read_config

def migrate(config):
 with connect(config) as conn:
  conn.execute('SELECT pg_advisory_xact_lock(72626411)')
  conn.execute(Path(__file__).with_name('migrations').joinpath('001_workspace.sql').read_text())
  if not conn.execute('SELECT 1 FROM ctx_accounts LIMIT 1').fetchone():
   conn.execute("INSERT INTO ctx_accounts(username,password_hash,role) VALUES (%s,%s,'admin')",(config['admin_username'],config['admin_password_hash']))
if __name__=='__main__':
 migrate(read_config())
 print('Upgrade complete. Your existing administrator login is ready.')
