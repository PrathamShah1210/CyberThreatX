"""Transactional, additive upgrade. Does not restore or overwrite existing intelligence."""
from pathlib import Path
from app import connect, read_config

def migrate(config):
 with connect(config) as conn:
  conn.execute('SELECT pg_advisory_xact_lock(72626411)')
  for migration in sorted(Path(__file__).with_name('migrations').glob('*.sql')):
   conn.execute(migration.read_text())
  if not conn.execute('SELECT 1 FROM ctx_accounts LIMIT 1').fetchone():
   conn.execute("INSERT INTO ctx_accounts(username,password_hash,role) VALUES (%s,%s,'admin')",(config['admin_username'],config['admin_password_hash']))
 # Convert existing KEV metadata into an unpublished queue once per CVE.
 with connect(config) as conn:
  from intelligence import stage
  for row in conn.execute("SELECT k.* FROM ctx_kev k WHERE NOT EXISTS (SELECT 1 FROM ctx_catalog c WHERE c.external_key='cisa:'||k.cve_id)").fetchall():
   r=row['raw_record']
   stage(conn,'cisa:'+row['cve_id'],'vulnerability',row['cve_id'],r.get('shortDescription','')+'\nRecommended action: '+r.get('requiredAction',''),'CISA KEV',row['source_url'],r)
if __name__=='__main__':
 migrate(read_config())
 print('Upgrade complete. Your existing administrator login is ready.')
