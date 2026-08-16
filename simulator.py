#!/usr/bin/env python3
"""Sentry SOC log simulator — streams realistic events into the ingest API."""
import argparse, json, random, sys, time
from datetime import datetime
import requests

RULES = [
    # (weight, severity, rule_name, src)
    (0.08, 'critical', 'Multiple failed admin logins', '10.0.4.19'),
    (0.06, 'critical', 'Unsigned binary executed', '192.168.1.44'),
    (0.05, 'critical', 'Privilege escalation attempt', '10.0.4.77'),
    (0.12, 'warning', 'Unusual outbound traffic volume', '172.16.9.3'),
    (0.10, 'warning', 'New device joined network', '10.0.4.201'),
    (0.09, 'warning', 'Port scan detected', '203.0.113.8'),
    (0.18, 'info', 'Scheduled scan completed', 'localhost'),
    (0.15, 'info', 'Security patch applied', '10.0.4.19'),
    (0.17, 'info', 'User session started', 'client-host'),
]
WEIGHTS = [r[0] for r in RULES]

def make_event():
    _, sev, rule, src = random.choices(RULES, weights=WEIGHTS, k=1)[0]
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    msg = f'{rule} observed from {src}'
    return {'ts': now, 'sev': sev, 'rule_name': rule, 'src': src, 'msg': msg}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--url', default='http://127.0.0.1:5001')
    ap.add_argument('--burst', type=int, default=10, help='events on startup')
    args = ap.parse_args()
    url = args.url.rstrip('/') + '/api/ingest'

    print(f'[*] Sentry simulator -> {url}  (Ctrl+C to stop)')
    sent = 0
    time.sleep(0.5)
    try:
        while True:
            batch = [make_event() for _ in range(args.burst if sent == 0 else 1)]
            try:
                r = requests.post(url, json=batch, timeout=3)
                if r.status_code == 200:
                    sent += len(batch)
                    print(f'[+] {len(batch)} event(s) ingested (total: {sent})')
                else:
                    print(f'[-] ingest error {r.status_code}: {r.text[:120]}')
            except requests.RequestException as e:
                print(f'[!] cannot reach server ({e}) — retrying in 3s...')
                time.sleep(3)
            time.sleep(random.uniform(1.5, 6.0))
    except KeyboardInterrupt:
        print(f'\n[*] stopped, {sent} events sent')

if __name__ == '__main__':
    main()