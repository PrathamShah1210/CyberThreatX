"""CyberThreatX: same-origin frontend and transactional PostgreSQL API."""
import csv
import io
import json
import os
import secrets
import time
from datetime import timedelta
from pathlib import Path
from functools import wraps

import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from flask import Flask, jsonify, request, session, send_from_directory, Response, abort
from werkzeug.security import check_password_hash

ROOT = Path(__file__).resolve().parent
TABLES = (
    'incidents', 'vulnerabilities', 'iocs', 'threats', 'threat_actors',
    'campaigns', 'sources', 'users', 'roles', 'permissions',
    'security_incidents', 'data_breaches', 'malware_incidents',
    'incident_ioc', 'incident_vuln', 'actor_campaign', 'targets',
    'attachments', 'attachment_hashes', 'threat_actor_aliases',
    'campaign_objectives', 'source_urls', 'data_breach_datatypes',
    'm_att_sys', 'user_phones', 'user_role',
)


def read_config():
    path = Path(os.environ.get('CYBERTHREATX_CONFIG', ROOT / 'config.json'))
    if not path.exists():
        raise RuntimeError('Run python setup.py to configure your PostgreSQL connection first.')
    config = json.loads(path.read_text())
    for key in ('database', 'secret_key', 'admin_username', 'admin_password_hash'):
        if not config.get(key):
            raise RuntimeError(f'Missing setting: {key}. Run python setup.py.')
    return config


def connect(config):
    return psycopg.connect(**config['database'], connect_timeout=5, row_factory=dict_row,
                          cursor_factory=psycopg.ClientCursor, prepare_threshold=None,
                          options='-c statement_timeout=15000 -c search_path=public,pg_catalog')


def inspect_schema(conn):
    result = {}
    for table in TABLES:
        columns = conn.execute('''SELECT column_name AS name, data_type AS type,
            is_nullable = 'YES' AS nullable, column_default AS default,
            character_maximum_length AS max_length
            FROM information_schema.columns WHERE table_schema='public' AND table_name=%s
            ORDER BY ordinal_position''', (table,)).fetchall()
        if not columns:
            raise RuntimeError(f'Missing table public.{table}; select the CyberThreatX database.')
        pk = [r['name'] for r in conn.execute('''SELECT a.attname AS name
            FROM pg_index i JOIN pg_attribute a ON a.attrelid=i.indrelid
            AND a.attnum=ANY(i.indkey)
            WHERE i.indrelid=%s::regclass AND i.indisprimary ORDER BY a.attnum''',
            (f'public.{table}',)).fetchall()]
        fks = conn.execute('''SELECT k.column_name AS column, c.table_name AS target,
            c.column_name AS target_column FROM information_schema.table_constraints t
            JOIN information_schema.key_column_usage k USING(constraint_catalog,constraint_schema,constraint_name)
            JOIN information_schema.referential_constraints r USING(constraint_catalog,constraint_schema,constraint_name)
            JOIN information_schema.key_column_usage c
            ON c.constraint_catalog=r.unique_constraint_catalog
            AND c.constraint_schema=r.unique_constraint_schema
            AND c.constraint_name=r.unique_constraint_name
            AND c.ordinal_position=k.position_in_unique_constraint
            WHERE t.table_schema='public' AND t.table_name=%s AND t.constraint_type='FOREIGN KEY'
            ''', (table,)).fetchall()
        result[table] = {'name': table, 'columns': columns, 'pk': pk, 'foreign_keys': fks}
    return result


def create_app(config=None):
    config = config or read_config()
    app = Flask(__name__, static_folder=str(ROOT / 'static'))
    app.config.update(SECRET_KEY=config['secret_key'], MAX_CONTENT_LENGTH=1024*1024,
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict',
                      SESSION_COOKIE_SECURE=config.get('secure_cookie', False),
                      PERMANENT_SESSION_LIFETIME=timedelta(hours=8))
    with connect(config) as conn:
        schema = inspect_schema(conn)
    from workspace import install, audit, PEOPLE
    attempts = {}

    def protected(fn):
        @wraps(fn)
        def inner(*args, **kwargs):
            if not session.get('authenticated'):
                return jsonify(error='Sign in to continue.'), 401
            with connect(config) as auth_conn:
                account = auth_conn.execute('SELECT id,username,role,active,session_version FROM ctx_accounts WHERE id=%s', (session.get('account_id'),)).fetchone()
            if not account or not account['active'] or account['session_version'] != session.get('version'):
                session.clear()
                return jsonify(error='Please sign in again.'), 401
            session['role'] = account['role']
            session['username'] = account['username']
            table = kwargs.get('table')
            if table and ((account['role']=='viewer') or (table in PEOPLE and account['role']!='admin')):
                abort(403)
            if account['role']=='viewer' and request.path=='/api/dashboard':
                return jsonify(viewer=True, username=account['username'])
            if request.method not in ('GET', 'HEAD'):
                if account['role']=='viewer' and request.path not in ('/api/logout','/api/research'):
                    abort(403)
                if request.method=='DELETE' and table and account['role']!='admin':
                    abort(403)
                token = request.headers.get('X-CSRF-Token', '')
                if not token or not secrets.compare_digest(token, session.get('csrf', '')):
                    return jsonify(error='Session expired. Refresh and sign in again.'), 403
            return fn(*args, **kwargs)
        return inner

    @app.before_request
    def json_object_only():
        if request.is_json and request.method in ('POST','PUT','DELETE') and request.get_data(cache=True) and not isinstance(request.get_json(silent=True),dict):
            return jsonify(error='Expected a JSON object.'),400

    @app.after_request
    def headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'same-origin'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        if request.path.startswith('/api/'):
            response.headers['Cache-Control'] = 'no-store'
        return response

    @app.errorhandler(psycopg.Error)
    def database_error(error):
        code = error.sqlstate or ''
        if code == '23505': message = 'That unique value or relationship already exists.'
        elif code == '23503': message = 'A linked record does not exist, or another record still references this one.'
        elif code == '23502': message = 'A required field is missing.'
        elif code == '23514': message = 'A value violates a database rule. Check scores and dates.'
        elif code.startswith('22'): message = 'A value has the wrong type, length, or format.'
        else:
            app.logger.error('Database operation failed: SQLSTATE %s', code)
            return jsonify(error='Database unavailable or query failed. Check the server connection.'), 503
        return jsonify(error=message), 400

    @app.errorhandler(ValueError)
    def invalid(error):
        return jsonify(error=str(error)), 400

    @app.get('/')
    def home():
        return send_from_directory(ROOT / 'static', 'public.html')

    @app.get('/workspace')
    def workspace_home():
        return send_from_directory(ROOT / 'static', 'index.html')

    @app.get('/api/session')
    def current_session():
        if 'csrf' not in session: session['csrf'] = secrets.token_urlsafe(32)
        return jsonify(authenticated=bool(session.get('authenticated')), csrf=session['csrf'],
                       username=session.get('username'), role=session.get('role'))

    @app.post('/api/login')
    def login():
        if not secrets.compare_digest(request.headers.get('X-CSRF-Token', ''), session.get('csrf', 'missing')):
            return jsonify(error='Refresh the page before signing in.'), 403
        key = request.remote_addr
        recent = [x for x in attempts.get(key, []) if time.time()-x < 300]
        if len(recent) >= 10:
            return jsonify(error='Too many attempts. Try again in five minutes.'), 429
        data = request.get_json(silent=True) or {}
        if not isinstance(data.get('password'), str) or not isinstance(data.get('username'), str):
            return jsonify(error='Enter username and password.'), 400
        with connect(config) as conn:
            account = conn.execute('SELECT * FROM ctx_accounts WHERE username=%s',(data['username'],)).fetchone()
        valid = check_password_hash(account['password_hash'] if account else config['admin_password_hash'], data['password'])
        if not account or not account['active'] or not valid:
            attempts[key] = recent + [time.time()]
            return jsonify(error='Incorrect username or password.'), 401
        attempts.pop(key, None)
        session.clear()
        session.update(authenticated=True, csrf=secrets.token_urlsafe(32), account_id=account['id'], username=account['username'], role=account['role'], version=account['session_version'])
        session.permanent = True
        return jsonify(authenticated=True, csrf=session['csrf'])

    @app.post('/api/logout')
    @protected
    def logout():
        session.clear()
        return jsonify(ok=True)

    @app.get('/api/schema')
    @protected
    def get_schema():
        return jsonify(tables=[v for k,v in schema.items() if session['role']!='viewer' and (session['role']=='admin' or k not in PEOPLE)])

    @app.get('/api/dashboard')
    @protected
    def dashboard():
        with connect(config) as conn:
            counts = {t: conn.execute(sql.SQL('SELECT count(*) AS n FROM public.{}').format(sql.Identifier(t))).fetchone()['n'] for t in TABLES if session['role']=='admin' or t not in PEOPLE}
            status = conn.execute("SELECT coalesce(status,'Unspecified') AS label,count(*) AS count FROM public.incidents GROUP BY status ORDER BY count DESC").fetchall()
            severity = conn.execute("SELECT coalesce(severity,'Unspecified') AS label,count(*) AS count FROM public.vulnerabilities GROUP BY severity ORDER BY count DESC").fetchall()
            latest = conn.execute('SELECT * FROM public.incidents ORDER BY detected_at DESC LIMIT 6').fetchall()
            name = conn.execute('SELECT current_database() AS name').fetchone()['name']
        return jsonify(counts=counts,status=status,severity=severity,latest=latest,database=name)

    def spec(table):
        if table not in schema: raise ValueError('Unknown table.')
        return schema[table]

    def key_where(meta, key):
        if not isinstance(key, dict) or set(key) != set(meta['pk']):
            raise ValueError('A complete primary key is required.')
        return sql.SQL(' AND ').join(sql.SQL('{} = %s').format(sql.Identifier(k)) for k in meta['pk']), [key[k] for k in meta['pk']]

    def validated(meta, values, editing=False):
        if not isinstance(values, dict) or not values: raise ValueError('Enter at least one field.')
        columns = {c['name']: c for c in meta['columns']}
        if set(values)-set(columns): raise ValueError('Unknown field.')
        for name, value in values.items():
            c = columns[name]
            if editing and name in meta['pk']: raise ValueError('Primary keys cannot be edited.')
            if c['default'] and str(c['default']).startswith('nextval('): raise ValueError('IDs are generated by PostgreSQL.')
            if isinstance(value,(list,dict)): raise ValueError('Fields must contain scalar values.')
            if value is None and not c['nullable']: raise ValueError(f'{name} is required.')
            if isinstance(value,str) and not value.strip() and not c['nullable']: raise ValueError(f'{name} cannot be blank.')
            if isinstance(value,str) and c['max_length'] and len(value)>c['max_length']: raise ValueError(f'{name} exceeds {c["max_length"]} characters.')
        if not editing:
            for c in meta['columns']:
                if not c['nullable'] and not c['default'] and c['name'] not in values: raise ValueError(f'{c["name"]} is required.')
        return values

    def select_query(table):
        meta = spec(table)
        q = request.args.get('q','').strip()[:300]
        search = sql.SQL('')
        params = []
        if q:
            search = sql.SQL(' WHERE (') + sql.SQL(' OR ').join(sql.SQL('CAST({} AS text) ILIKE %s').format(sql.Identifier(c['name'])) for c in meta['columns']) + sql.SQL(')')
            literal = q.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')
            params = ['%'+literal+'%']*len(meta['columns'])
        for field in ('severity','status'):
            value=request.args.get(field,'')
            if value and any(c['name']==field for c in meta['columns']):
                search += sql.SQL(' AND ' if params else ' WHERE ') if not q else sql.SQL(' AND ')
                # Search OR terms are parenthesized before adding exact filters.
                search += sql.SQL('{}=%s').format(sql.Identifier(field))
                params.append(value)
        base = sql.SQL(' FROM public.{}').format(sql.Identifier(table)) + search
        sort=request.args.get('sort') or meta['pk'][0]
        if sort not in [c['name'] for c in meta['columns']]: raise ValueError('Unknown sort column.')
        direction=sql.SQL(' DESC' if request.args.get('direction')=='desc' else ' ASC')
        order=sql.Identifier(sort)+direction
        for k in meta['pk']:
            if k!=sort: order+=sql.SQL(', ')+sql.Identifier(k)
        return base, order, params

    @app.get('/api/tables/<table>')
    @protected
    def rows(table):
        base, order, params = select_query(table)
        page = max(1,int(request.args.get('page',1)))
        limit = min(100,max(1,int(request.args.get('limit',25))))
        with connect(config) as conn:
            total = conn.execute(sql.SQL('SELECT count(*) AS n')+base,params).fetchone()['n']
            records = conn.execute(sql.SQL('SELECT *')+base+sql.SQL(' ORDER BY ')+order+sql.SQL(' LIMIT %s OFFSET %s'),params+[limit,(page-1)*limit]).fetchall()
        return jsonify(rows=records,total=total,page=page,limit=limit)

    @app.get('/api/export/<table>')
    @protected
    def export(table):
        base, order, params = select_query(table)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([c['name'] for c in schema[table]['columns']])
        with connect(config) as conn:
            with conn.cursor(name='csv_export') as cursor:
                cursor.execute(sql.SQL('SELECT *')+base+sql.SQL(' ORDER BY ')+order,params)
                for row in cursor:
                    # Prevent spreadsheet formula evaluation of untrusted text.
                    writer.writerow(["'"+v if isinstance(v,str) and v.startswith(('=','+','-','@','\t','\r')) else v for v in row.values()])
        return Response(output.getvalue(),mimetype='text/csv',headers={'Content-Disposition':f'attachment; filename={table}.csv'})

    @app.post('/api/tables/<table>')
    @protected
    def insert(table):
        meta = spec(table)
        body = request.get_json(silent=True) or {}
        values = validated(meta,body.get('values'))
        query = sql.SQL('INSERT INTO public.{} ({}) VALUES ({}) RETURNING *').format(sql.Identifier(table),sql.SQL(',').join(map(sql.Identifier,values)),sql.SQL(',').join(sql.Placeholder() for _ in values))
        with connect(config) as conn:
            record = conn.execute(query,list(values.values())).fetchone()
            audit(conn,'create',table,{k:record[k] for k in meta['pk']})
        return jsonify(row=record),201

    @app.put('/api/tables/<table>')
    @protected
    def update(table):
        meta = spec(table)
        body = request.get_json(silent=True) or {}
        values = validated(meta,body.get('values'),True)
        where, params = key_where(meta,body.get('key'))
        query = sql.SQL('UPDATE public.{} SET {} WHERE {} RETURNING *').format(sql.Identifier(table),sql.SQL(',').join(sql.SQL('{}=%s').format(sql.Identifier(k)) for k in values),where)
        with connect(config) as conn:
            record = conn.execute(query,list(values.values())+params).fetchone()
            if record: audit(conn,'update',table,body.get('key'))
        if not record: return jsonify(error='Record no longer exists.'),404
        return jsonify(row=record)

    @app.delete('/api/tables/<table>')
    @protected
    def delete(table):
        meta = spec(table)
        body = request.get_json(silent=True) or {}
        where, params = key_where(meta,body.get('key'))
        with connect(config) as conn:
            record = conn.execute(sql.SQL('DELETE FROM public.{} WHERE {} RETURNING *').format(sql.Identifier(table),where),params).fetchone()
            if record: audit(conn,'delete',table,body.get('key'))
        if not record: return jsonify(error='Record no longer exists.'),404
        return jsonify(deleted=True)

    @app.errorhandler(403)
    def forbidden(error):
        return jsonify(error='Your role does not allow this action.'),403

    @app.errorhandler(404)
    def missing(error):
        return jsonify(error='Record or endpoint not found.'),404

    install(app,config,connect,protected)
    from intelligence import install as install_intelligence
    from feeds import install as install_feeds
    install_intelligence(app,config,connect,protected)
    install_feeds(app,config,connect,protected)
    return app


if __name__ == '__main__':
    from waitress import serve
    print('CyberThreatX running (default URL http://127.0.0.1:8003)', flush=True)
    serve(create_app(),host='127.0.0.1',port=int(os.environ.get('PORT','8003')),threads=4)
