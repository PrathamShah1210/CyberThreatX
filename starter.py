"""Small real-world reference collection, staged for review; no invented incidents."""
from intelligence import stage,observe
from app import connect,read_config

RECORDS=[
 ('G0007','actor','APT28','MITRE ATT&CK identifies APT28 as a threat group active since at least 2004 and attributed in public reporting to Russian military intelligence.','https://attack.mitre.org/groups/G0007/'),
 ('G0016','actor','APT29','MITRE ATT&CK documents APT29 and its association with the SolarWinds compromise.','https://attack.mitre.org/groups/G0016/'),
 ('C0024','campaign','SolarWinds Compromise','A supply-chain campaign discovered in December 2020 involving malicious changes to SolarWinds Orion updates. MITRE attributes this campaign to APT29.','https://attack.mitre.org/campaigns/C0024/'),
 ('S0366','threat','WannaCry','Ransomware observed in the May 2017 global outbreak. MITRE documents its worm-like spread using the SMBv1 EternalBlue exploit.','https://attack.mitre.org/software/S0366/')
]
def load(config):
 ids={}
 with connect(config) as c:
  for key,category,name,summary,url in RECORDS:
   existing=c.execute('SELECT legacy_table,legacy_id FROM ctx_catalog WHERE external_key=%s',('starter:'+key,)).fetchone()
   if existing:table,rid=existing['legacy_table'],existing['legacy_id']
   elif category=='actor':
    table='threat_actors';rid=c.execute('INSERT INTO threat_actors(actor_name) VALUES (%s) ON CONFLICT(actor_name) DO UPDATE SET actor_name=excluded.actor_name RETURNING actor_id',(name,)).fetchone()['actor_id']
   elif category=='campaign':
    table='campaigns';rid=c.execute('INSERT INTO campaigns(name) VALUES (%s) ON CONFLICT(name) DO UPDATE SET name=excluded.name RETURNING campaign_id',(name,)).fetchone()['campaign_id']
   else:
    table='threats';rid=c.execute('INSERT INTO threats(name,description) VALUES (%s,%s) RETURNING threat_id',(name,summary)).fetchone()['threat_id']
   ids[key]=stage(c,'starter:'+key,category,name,summary,'MITRE ATT&CK — curated reference',url,{'reference_id':key,'source_checked':'2026-09-19','summary':summary},table,rid)
  c.execute("INSERT INTO ctx_catalog_links(from_id,to_id,relationship,source_url) VALUES (%s,%s,'attributed-to','https://attack.mitre.org/campaigns/C0024/') ON CONFLICT DO NOTHING",(ids['C0024'],ids['G0016']))
  c.execute("INSERT INTO actor_campaign(actor_id,campaign_id) SELECT a.legacy_id,c.legacy_id FROM ctx_catalog a CROSS JOIN ctx_catalog c WHERE a.id=%s AND c.id=%s ON CONFLICT DO NOTHING",(ids['G0016'],ids['C0024']))
  ref='https://www.sophos.com/en-us/research/wcry-ransomware-analysis'
  domain='gx7ekbenv2riucmf.onion'
  cid=stage(c,'starter:wcry-c2','indicator',domain,'Historical WannaCry command-and-control address documented by Secureworks CTU in its 2017 analysis. This is historical evidence, not a claim of current operation.','Secureworks CTU (Sophos)',ref,{'indicator':domain,'source_checked':'2026-09-19','historical':True})
  observe(c,cid,'domain',domain,'malicious')
  c.execute("INSERT INTO ctx_catalog_links(from_id,to_id,relationship,source_url) VALUES (%s,%s,'related-to',%s) ON CONFLICT DO NOTHING",(cid,ids['S0366'],ref))
  c.execute("INSERT INTO ctx_import_runs(source,status,records,finished_at,message) VALUES ('Curated real-world references','success',5,now(),'Staged for review; historical reference collection, not a live feed')")
 return len(ids)+1
if __name__=='__main__':print(load(read_config()),'real reference records staged for analyst review.')
