#!/usr/bin/env python3
"""Sentry SOC — lightweight self-hosted SIEM (Flask + SQLite + SPL-lite).

Endpoints:
  POST /api/ingest              bulk log ingestion (JSON lines or JSON array)
  GET  /api/stats               KPIs, timeline buckets, risk score, console tail
  GET  /api/search?q=<spl>      SPL-lite search: index=/sourcetype= hints,
                                severity=/rule_name=/src= filters, free text,
                                | stats count by <fields>, | sort - count, | head N
  GET  /api/events?sev=&limit=  raw event listing
  GET  /api/incidents           incidents (auto-created from crit/warn events)
  PATCH /api/incidents/<id>     set status (new/progress/resolved) or owner
  GET  /api/health              liveness
"""
import json, os, re, shlex, sqlite3, sys, time
from datetime import datetime
from flask import Flask, jsonify, request, send_from_directory

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, 'sentry.db')
SEV_ORDER = {'critical': 0, 'warning': 1, 'info': 2}
SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  epoch REAL NOT NULL,
  ts TEXT NOT NULL,
  sev TEXT NOT NULL,
  rule_name TEXT NOT NULL,
  src TEXT NOT NULL,
  msg TEXT DEFAULT '',
  raw TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ev_epoch ON events(epoch);
CREATE INDEX IF NOT EXISTS idx_ev_sev   ON events(sev);
CREATE TABLE IF NOT EXISTS incidents(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER NOT NULL,
  status TEXT DEFAULT 'new',
  owner TEXT DEFAULT 'unassigned',
  opened_at TEXT NOT NULL,
  closed_at TEXT
);
"""

def get_db():
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA journal_mode=WAL')
    return db

app = Flask(__name__, static_folder=None)

# ---------------------------------------------------------------- ingestion

def normalize_event(item, fallback_ts=None):
    now = fallback_ts or datetime.now()
    ts = item.get('ts') or now.strftime('%Y-%m-%d %H:%M:%S')
    try:
        epoch = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S').timestamp()
    except ValueError:
        epoch = now.timestamp()
    sev = str(item.get('sev', 'info')).lower()
    if sev not in SEV_ORDER:
        sev = 'info'
    rule = str(item.get('rule_name') or item.get('name') or 'Unknown rule')
    src = str(item.get('src') or item.get('source') or '-')
    msg = str(item.get('msg') or '')
    raw = item.get('raw') or json.dumps(item, ensure_ascii=False)
    return epoch, ts, sev, rule, src, msg, raw

@app.post('/api/ingest')
def ingest():
    payload = request.get_data(as_text=True).strip()
    if not payload:
        return jsonify({'ok': False, 'error': 'empty body'}), 400
    try:
        items = json.loads(payload) if payload.startswith('[') else \
                [json.loads(l) for l in payload.splitlines() if l.strip()]
    except json.JSONDecodeError as e:
        return jsonify({'ok': False, 'error': f'bad JSON: {e}'}), 400
    if not isinstance(items, list):
        items = [items]
    db = get_db()
    now = datetime.now()
    created = 0
    for it in items:
        epoch, ts, sev, rule, src, msg, raw = normalize_event(it, now)
        cur = db.execute(
            'INSERT INTO events(epoch, ts, sev, rule_name, src, msg, raw) VALUES(?,?,?,?,?,?,?)',
            (epoch, ts, sev, rule, src, msg, raw))
        if sev in ('critical', 'warning'):          # auto-open an incident
            db.execute('INSERT INTO incidents(event_id, status, owner, opened_at) VALUES(?,?,?,?)',
                       (cur.lastrowid, 'new', 'unassigned', ts))
        created += 1
    db.commit(); db.close()
    return jsonify({'ok': True, 'ingested': created})

# ---------------------------------------------------------------- dashboard

@app.get('/api/stats')
def stats():
    db = get_db()
    counts = {s: 0 for s in SEV_ORDER}
    for r in db.execute('SELECT sev, COUNT(*) c FROM events GROUP BY sev'):
        counts[r['sev']] = r['c']
    total = sum(counts.values())

    span, buckets = 12 * 60, 20                    # last 12 minutes in 20 buckets
    step, end, start = span / buckets, time.time(), time.time() - span
    hist = [0] * buckets
    for r in db.execute('SELECT epoch FROM events WHERE epoch >= ? AND epoch <= ?',
                        (start, end)).fetchall():
        hist[min(buckets - 1, int((r['epoch'] - start) / step))] += 1

    recent = [dict(r) for r in db.execute(
        'SELECT * FROM events ORDER BY epoch DESC LIMIT 8').fetchall()]
    console = [dict(r) for r in db.execute(
        'SELECT * FROM events ORDER BY id DESC LIMIT 40').fetchall()]
    console.reverse()
    db.close()
    return jsonify({
        'counts': counts,
        'total': total,
        'timeline': {'start': start, 'step': step, 'buckets': hist},
        'risk_score': min(100, counts['critical'] * 18 + counts['warning'] * 8 + counts['info'] * 2),
        'recent': recent,
        'console': console,
    })

# ---------------------------------------------------------------- SPL-lite

FIELD_MAP = {'sev': 'sev', 'severity': 'sev', 'rule_name': 'rule_name',
             'src': 'src', 'source': 'src', 'count': 'count'}

def parse_spl(q):
    """Parse a small, safe subset of SPL into structured filters."""
    info = {'filters': [], 'terms': [], 'stats': None, 'sort': None, 'head': 200}
    for part in [p.strip() for p in q.split('|') if p.strip()]:
        low = part.lower()
        if low.startswith(('index=', 'sourcetype=')):
            continue                                # single-index appliance: hints ignored
        if low.startswith('search '):
            info['terms'] += shlex.split(part[7:]); continue
        if low.startswith('stats '):
            m = re.match(r'stats\s+count(?:\s+as\s+\w+)?\s+by\s+(.+)', part, re.I)
            if m:
                info['stats'] = [f.strip() for f in m.group(1).split(',') if f.strip()]
            else:
                info['stats'] = []                  # bare `stats count`
            continue
        if low.startswith('sort '):
            rest = shlex.split(part[5:])
            d = 'asc'
            if rest and rest[0] in ('-', 'desc'):
                d, rest = 'desc', rest[1:]
            if rest:
                info['sort'] = (rest[0].lower(), d)
            continue
        if low.startswith('head '):
            try:
                info['head'] = int(part.split()[1])
            except (IndexError, ValueError):
                pass
            continue
        pairs = re.findall(r'(\w+)\s*=\s*("([^"]*)"|(\S+))', part)
        if pairs:
            for k, _, quoted, unquoted in pairs:
                info['filters'].append((k.lower(), quoted or unquoted))
        else:
            info['terms'] += shlex.split(part)
    return info

@app.get('/api/search')
def search():
    info = parse_spl(request.args.get('q', ''))
    where, params = [], []
    for k, v in info['filters']:
        if k in ('sev', 'severity'):
            where.append('sev = ?'); params.append(v.lower())
        elif k == 'rule_name':
            where.append('rule_name LIKE ?'); params.append(f'%{v}%')
        elif k in ('src', 'source'):
            where.append('src LIKE ?'); params.append(f'%{v}%')
        elif k in ('msg', 'message'):
            where.append('msg LIKE ?'); params.append(f'%{v}%')
    if info['terms']:
        pat = '%' + ' '.join(info['terms']) + '%'
        where.append('(raw LIKE ? OR rule_name LIKE ? OR src LIKE ?)')
        params += [pat, pat, pat]
    wsql = (' WHERE ' + ' AND '.join(where)) if where else ''

    db = get_db()
    if info['stats'] is not None:
        bad = [f for f in info['stats'] if f not in FIELD_MAP]
        if bad:
            db.close()
            return jsonify({'error': f'unsupported stats field(s): {", ".join(bad)}'}), 400
        if info['stats']:
            cols = ', '.join(FIELD_MAP[f] for f in info['stats'])
            rows = db.execute(
                f'SELECT {cols}, COUNT(*) AS count, MAX(ts) AS last_seen '
                f'FROM events{wsql} GROUP BY {cols}', params).fetchall()
        else:
            rows = db.execute(
                f'SELECT COUNT(*) AS count, MAX(ts) AS last_seen FROM events{wsql}',
                params).fetchall()
        result = [dict(r) for r in rows]
        if info['sort']:
            f, d = info['sort']
            key = 'count' if f in ('count', 'c') else 'last_seen'
            result.sort(key=lambda r: r.get(key) or '', reverse=(d == 'desc'))
        else:                                        # useful default for stats mode
            result.sort(key=lambda r: r.get('count') or 0, reverse=True)
        result = result[:info['head']]
        mode = 'stats'
    else:
        rows = db.execute(f'SELECT * FROM events{wsql} ORDER BY epoch DESC LIMIT ?',
                          params + [info['head']]).fetchall()
        result = [dict(r) for r in rows]
        mode = 'events'
    db.close()
    return jsonify({'query': q, 'total': len(result), 'rows': result, 'mode': mode})

# ---------------------------------------------------------------- incidents

@app.get('/api/incidents')
def list_incidents():
    db = get_db()
    rows = db.execute(
        '''SELECT i.id, i.status, i.owner, i.opened_at, i.closed_at,
                  e.sev, e.rule_name, e.src, e.ts
           FROM incidents i JOIN events e ON e.id = i.event_id
           ORDER BY i.id DESC LIMIT 200''').fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.patch('/api/incidents/<int:iid>')
def update_incident(iid):
    data = request.get_json(silent=True) or {}
    sets, params = [], []
    if 'status' in data:
        if data['status'] not in ('new', 'progress', 'resolved'):
            return jsonify({'ok': False, 'error': 'bad status'}), 400
        sets.append('status = ?'); params.append(data['status'])
        sets.append('closed_at = ?')
        params.append(datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                      if data['status'] == 'resolved' else None)
    if 'owner' in data:
        sets.append('owner = ?'); params.append(str(data['owner']))
    if not sets:
        return jsonify({'ok': False, 'error': 'nothing to update'}), 400
    db = get_db()
    cur = db.execute(f'UPDATE incidents SET {", ".join(sets)} WHERE id = ?', params + [iid])
    db.commit(); db.close()
    return jsonify({'ok': bool(cur.rowcount)})

# ---------------------------------------------------------------- misc

@app.get('/api/events')
def events():
    sev = request.args.get('sev')
    limit = min(int(request.args.get('limit', 100)), 1000)
    db = get_db()
    if sev:
        rows = db.execute('SELECT * FROM events WHERE sev = ? ORDER BY epoch DESC LIMIT ?',
                          (sev, limit)).fetchall()
    else:
        rows = db.execute('SELECT * FROM events ORDER BY epoch DESC LIMIT ?', (limit,)).fetchall()
    out = [dict(r) for r in rows]
    db.close()
    return jsonify(out)

@app.get('/api/health')
def health():
    return jsonify({'status': 'ok', 'time': datetime.now().isoformat()})

def seed_events(n=180):
    """Pre-fill the DB so the dashboard is alive on first run (used with --seed)."""
    import random
    rules = [
        ('critical', 'Multiple failed admin logins', '10.0.4.19'),
        ('critical', 'Unsigned binary executed', '192.168.1.44'),
        ('critical', 'Privilege escalation attempt', '10.0.4.77'),
        ('warning', 'Unusual outbound traffic volume', '172.16.9.3'),
        ('warning', 'New device joined network', '10.0.4.201'),
        ('warning', 'Port scan detected', '203.0.113.8'),
        ('info', 'Scheduled scan completed', 'localhost'),
        ('info', 'Security patch applied', '10.0.4.19'),
        ('info', 'User session started', 'client-host'),
    ]
    db = get_db()
    now = time.time()
    for _ in range(n):
        sev, rule, src = random.choice(rules)
        epoch = now - random.random() * 12 * 60
        ts = datetime.fromtimestamp(epoch).strftime('%Y-%m-%d %H:%M:%S')
        msg = f'{rule} observed from {src}'
        cur = db.execute(
            'INSERT INTO events(epoch, ts, sev, rule_name, src, msg, raw) VALUES(?,?,?,?,?,?,?)',
            (epoch, ts, sev, rule, src, msg, msg))
        if sev in ('critical', 'warning'):
            db.execute('INSERT INTO incidents(event_id, status, owner, opened_at) VALUES(?,?,?,?)',
                       (cur.lastrowid, 'new', 'unassigned', ts))
    db.commit(); db.close()

@app.get('/')
def index():
    return send_from_directory(os.path.join(BASE, 'static'), 'index.html')

if __name__ == '__main__':
    db = get_db(); db.executescript(SCHEMA); db.close()
    if '--seed' in sys.argv:
        db = get_db()
        empty = db.execute('SELECT COUNT(*) c FROM events').fetchone()['c'] == 0
        db.close()
        if empty:
            seed_events()
            print('[*] seeded 180 historical events')
    app.run(host='0.0.0.0', port=5001, debug=False, threaded=True)