"""Optional fresh-database restore. NEVER needed for your existing database."""
import argparse
import re
from pathlib import Path
from psycopg import sql
from app import read_config, connect, TABLES

def decode_copy(value):
    if value == r'\N': return None
    escapes={'b':'\b','f':'\f','n':'\n','r':'\r','t':'\t','v':'\v','\\':'\\'}
    def decode(match):
        token=match.group(1)
        if token.startswith('x') and len(token)>1: return chr(int(token[1:],16))
        if token[0] in '01234567': return chr(int(token,8))
        return escapes.get(token,token)
    return re.sub(r'\\(x[0-9a-fA-F]{1,2}|[0-7]{1,3}|.)',decode,value)

def restore(conn, root):
    existing=conn.execute("SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename=ANY(%s)",(list(TABLES),)).fetchall()
    if existing:
        raise RuntimeError('Refusing import: CyberThreatX tables already exist. Use your existing data directly.')
    conn.execute((root/'schema.sql').read_text())
    # Bounded parameterized batches preserve COPY text escapes without depending
    # on a particular proxy's support for the COPY streaming wire protocol.
    def insert_batch(rows):
        if not rows: return
        query=sql.SQL('INSERT INTO public.vulnerabilities (vuln_id,cve_id,description,severity) VALUES ')
        query+=sql.SQL(',').join(sql.SQL('(%s,%s,%s,%s)') for _ in rows)
        conn.execute(query,[value for row in rows for value in row])
    batch=[]
    with (root/'vulnerabilities.copy').open(encoding='utf-8') as source:
        for line in source:
            values=[decode_copy(value) for value in line.rstrip('\n').split('\t')]
            if len(values)!=4: raise ValueError('Invalid vulnerability export row.')
            batch.append(values)
            if len(batch)==500:
                insert_batch(batch)
                batch=[]
        insert_batch(batch)
    conn.execute("SELECT setval(pg_get_serial_sequence('public.vulnerabilities','vuln_id'),coalesce(max(vuln_id),1),count(*)>0) FROM public.vulnerabilities")

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--seed',action='store_true',help='Add labeled sample records after fresh import')
    args=p.parse_args()
    config=read_config()
    with connect(config) as conn:
        restore(conn,Path(__file__).parent/'database')
    print('Restored 45,206 exported vulnerability records and 26 CTI tables.')
    if args.seed:
        with connect(config) as conn:
            conn.execute((Path(__file__).parent/'database/sample_data.sql').read_text())
        print('Added fictional CTX-DEMO sample records.')
