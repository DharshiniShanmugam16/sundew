#!/usr/bin/env python3
"""Sundew - Day 5: dashboard.

A read-only web UI over sundew.db. It also runs the analyzer in a background
thread so the `detections` table stays fresh.

    python dashboard.py                      # http://127.0.0.1:5000
    python dashboard.py --analyze-every 30   # slower analyzer for big databases

SECURITY NOTES
- Binds to 127.0.0.1 only. View it remotely through an SSH tunnel, never by
  opening a port to the internet.
- The database contains attacker-controlled text (usernames, passwords, URLs).
  The page renders all of it with textContent, never innerHTML, and a strict
  Content-Security-Policy blocks inline scripts that lack our per-request nonce.
- debug mode is never enabled (the Werkzeug debugger allows remote code execution).
"""
import argparse
import os
import secrets
import sqlite3
import sys
import threading
import time

from flask import Flask, Response, jsonify, request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analyzer  # noqa: E402

DEFAULT_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sundew.db")
app = Flask(__name__)
app.config["DB_PATH"] = DEFAULT_DB


# ---------- database helpers (read-only) ----------
def query(sql, params=()):
    conn = sqlite3.connect(app.config["DB_PATH"], timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA query_only = ON")
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def safe_query(sql, params=()):
    try:
        return query(sql, params)
    except sqlite3.OperationalError:      # e.g. detections table not created yet
        return []


def one(sql, params=()):
    rows = safe_query(sql, params)
    return list(rows[0].values())[0] if rows else 0


def parse_hours(raw):
    try:
        return max(0, min(int(raw), 24 * 365))
    except (TypeError, ValueError):
        return 0


def collect(hours):
    ev_cl, ev_p = ("", ()) if hours <= 0 else (" AND ts >= datetime('now', ?)", (f"-{hours} hours",))
    de_cl, de_p = ("", ()) if hours <= 0 else (" AND last_seen >= datetime('now', ?)", (f"-{hours} hours",))

    if 0 < hours <= 6:       # fine buckets (5 minutes) for short ranges
        bucket = ("strftime('%Y-%m-%d %H:', ts) || "
                  "printf('%02d', (CAST(strftime('%M', ts) AS INTEGER) / 5) * 5)")
    else:
        bucket = "strftime('%Y-%m-%d %H:00', ts)"

    timeline = safe_query(
        f"SELECT {bucket} AS bucket, COUNT(*) AS n FROM events WHERE 1=1{ev_cl} "
        "GROUP BY bucket ORDER BY bucket DESC LIMIT 72", ev_p)[::-1]

    return {
        "summary": {
            "events": one(f"SELECT COUNT(*) FROM events WHERE 1=1{ev_cl}", ev_p),
            "ips": one(f"SELECT COUNT(DISTINCT src_ip) FROM events WHERE 1=1{ev_cl}", ev_p),
            "logins": one(f"SELECT COUNT(*) FROM events WHERE event='login_attempt'{ev_cl}", ev_p),
            "accepted": one(f"SELECT COUNT(*) FROM events WHERE event='login_attempt' "
                            f"AND data='accepted'{ev_cl}", ev_p),
            "detections": one(f"SELECT COUNT(*) FROM detections WHERE 1=1{de_cl}", de_p),
        },
        "timeline": timeline,
        "services": safe_query(
            f"SELECT service AS k, COUNT(*) AS n FROM events WHERE 1=1{ev_cl} "
            "GROUP BY service ORDER BY n DESC", ev_p),
        "top_ips": safe_query(
            f"SELECT src_ip AS k, COUNT(*) AS n FROM events WHERE 1=1{ev_cl} "
            "GROUP BY src_ip ORDER BY n DESC LIMIT 10", ev_p),
        "top_passwords": safe_query(
            f"SELECT password AS k, COUNT(*) AS n FROM events WHERE event='login_attempt' "
            f"AND password IS NOT NULL AND password != ''{ev_cl} "
            "GROUP BY password ORDER BY n DESC LIMIT 10", ev_p),
        "top_usernames": safe_query(
            f"SELECT username AS k, COUNT(*) AS n FROM events WHERE event='login_attempt' "
            f"AND username IS NOT NULL AND username != ''{ev_cl} "
            "GROUP BY username ORDER BY n DESC LIMIT 10", ev_p),
        "labels": safe_query(
            f"SELECT label AS k, SUM(count) AS n FROM detections WHERE 1=1{de_cl} "
            "GROUP BY label ORDER BY n DESC LIMIT 15", de_p),
        "tactics": safe_query(
            f"SELECT tactic AS k, SUM(count) AS n FROM detections WHERE 1=1{de_cl} "
            "GROUP BY tactic ORDER BY n DESC", de_p),
        "techniques": safe_query(
            f"SELECT technique_id, technique_name, COUNT(DISTINCT src_ip) AS ips, SUM(count) AS events "
            f"FROM detections WHERE 1=1{de_cl} GROUP BY technique_id, technique_name "
            "ORDER BY events DESC LIMIT 20", de_p),
        "recent_detections": safe_query(
            f"SELECT last_seen, src_ip, label, technique_id, severity, count, evidence "
            f"FROM detections WHERE 1=1{de_cl} ORDER BY last_seen DESC, id DESC LIMIT 15", de_p),
        "recent_events": safe_query(
            f"SELECT ts, src_ip, service, event, username, password, substr(data, 1, 90) AS data "
            f"FROM events WHERE event NOT IN ('connect', 'disconnect'){ev_cl} "
            "ORDER BY id DESC LIMIT 25", ev_p),
        "iocs": safe_query(
            f"SELECT data AS url, COUNT(*) AS n, COUNT(DISTINCT src_ip) AS ips FROM events "
            f"WHERE event='download_attempt'{ev_cl} GROUP BY data ORDER BY n DESC LIMIT 10", ev_p),
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
    }


# ---------- routes ----------
@app.route("/")
def index():
    nonce = secrets.token_urlsafe(16)
    resp = Response(PAGE.replace("__NONCE__", nonce), mimetype="text/html")
    resp.headers["Content-Security-Policy"] = (
        f"default-src 'none'; script-src 'nonce-{nonce}' https://cdn.jsdelivr.net; "
        "style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/api/data")
def api_data():
    resp = jsonify(collect(parse_hours(request.args.get("hours"))))
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------- the page ----------
PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sundew Dashboard</title>
<style>
  :root { --bg:#0f1115; --panel:#181b22; --line:#2a2f3a; --text:#e6e8ee; --muted:#8b93a7; --accent:#4e9af1; }
  * { box-sizing: border-box; }
  body { margin:0; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background:var(--bg); color:var(--text); }
  header { display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; padding:14px 22px; border-bottom:1px solid var(--line); }
  h1 { margin:0; font-size:20px; letter-spacing:.5px; }
  h1 small { color:var(--muted); font-weight:400; font-size:13px; margin-left:8px; }
  .controls { display:flex; align-items:center; gap:12px; color:var(--muted); font-size:13px; }
  select { background:var(--panel); color:var(--text); border:1px solid var(--line); border-radius:6px; padding:5px 8px; }
  #status.err { color:#eb5757; }
  main { padding:18px 22px 40px; max-width:1500px; margin:0 auto; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; margin-bottom:16px; }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:14px 16px; }
  .card span { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.6px; }
  .card b { display:block; font-size:28px; margin-top:4px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(360px,1fr)); gap:14px; margin-bottom:14px; }
  .box { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:12px 14px; min-width:0; }
  .box h2 { margin:0 0 8px; font-size:13px; color:var(--muted); font-weight:600; text-transform:uppercase; letter-spacing:.6px; }
  .chart { position:relative; height:250px; }
  .wide { grid-column: 1 / -1; }
  .scroll { overflow-x:auto; }
  table { width:100%; border-collapse:collapse; font-size:12.5px; }
  th { text-align:left; color:var(--muted); font-weight:600; padding:6px 8px; border-bottom:1px solid var(--line); white-space:nowrap; }
  td { padding:5px 8px; border-bottom:1px solid #20242d; word-break:break-word; vertical-align:top; }
  td.sev-high { color:#eb5757; font-weight:600; }
  td.sev-medium { color:#f2c94c; }
  td.sev-low { color:#6fcf97; }
  .empty { color:var(--muted); padding:10px 0; font-size:13px; }
</style>
</head>
<body>
<header>
  <h1>Sundew<small>honeypot dashboard</small></h1>
  <div class="controls">
    <label for="range">Time range</label>
    <select id="range">
      <option value="0">All time</option>
      <option value="1">Last hour</option>
      <option value="6">Last 6 hours</option>
      <option value="24">Last 24 hours</option>
      <option value="168">Last 7 days</option>
    </select>
    <span id="status">loading...</span>
  </div>
</header>
<main>
  <div class="cards">
    <div class="card"><span>Events</span><b id="c_events">0</b></div>
    <div class="card"><span>Unique attacker IPs</span><b id="c_ips">0</b></div>
    <div class="card"><span>Login attempts</span><b id="c_logins">0</b></div>
    <div class="card"><span>Logins accepted</span><b id="c_accepted">0</b></div>
    <div class="card"><span>Detections</span><b id="c_detections">0</b></div>
  </div>

  <div class="grid">
    <div class="box wide"><h2>Events over time</h2><div class="chart"><canvas id="ch_timeline"></canvas></div></div>
    <div class="box"><h2>Traffic by service</h2><div class="chart"><canvas id="ch_services"></canvas></div></div>
    <div class="box"><h2>Top attacker IPs</h2><div class="chart"><canvas id="ch_ips"></canvas></div></div>
    <div class="box"><h2>Top passwords tried</h2><div class="chart"><canvas id="ch_passwords"></canvas></div></div>
    <div class="box"><h2>Top usernames tried</h2><div class="chart"><canvas id="ch_usernames"></canvas></div></div>
    <div class="box"><h2>Detections by type</h2><div class="chart"><canvas id="ch_labels"></canvas></div></div>
    <div class="box"><h2>MITRE ATT&amp;CK tactics</h2><div class="chart"><canvas id="ch_tactics"></canvas></div></div>
  </div>

  <div class="grid">
    <div class="box wide"><h2>ATT&amp;CK techniques observed</h2><div class="scroll"><table>
      <thead><tr><th>ID</th><th>Technique</th><th>IPs</th><th>Events</th></tr></thead><tbody id="t_techniques"></tbody></table></div></div>
    <div class="box wide"><h2>Recent detections</h2><div class="scroll"><table>
      <thead><tr><th>Last seen (UTC)</th><th>IP</th><th>Type</th><th>Technique</th><th>Severity</th><th>Count</th><th>Evidence</th></tr></thead><tbody id="t_detections"></tbody></table></div></div>
    <div class="box wide"><h2>Indicators: download URLs captured from fake shells</h2><div class="scroll"><table>
      <thead><tr><th>URL</th><th>Times seen</th><th>IPs</th></tr></thead><tbody id="t_iocs"></tbody></table></div></div>
    <div class="box wide"><h2>Recent events</h2><div class="scroll"><table>
      <thead><tr><th>Time (UTC)</th><th>IP</th><th>Service</th><th>Event</th><th>User</th><th>Password</th><th>Data</th></tr></thead><tbody id="t_events"></tbody></table></div></div>
  </div>
</main>

<script nonce="__NONCE__" src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.js"></script>
<script nonce="__NONCE__">
const palette = ['#4e9af1', '#f1a14e', '#6fcf97', '#eb5757', '#bb6bd9', '#f2c94c', '#56ccf2', '#9b9b9b', '#2d9cdb', '#e0e0e0'];
const charts = {};
const SEVERITIES = ['low', 'medium', 'high'];

function drawChart(id, type, rows, labelKey, valueKey, title, horizontal) {
  const canvas = document.getElementById(id);
  const labels = rows.map(function (r) { return String(r[labelKey]); });
  const values = rows.map(function (r) { return Number(r[valueKey]); });
  const colors = type === 'doughnut' ? labels.map(function (_, i) { return palette[i % palette.length]; }) : palette[0];
  if (charts[id]) {
    const c = charts[id];
    c.data.labels = labels;
    c.data.datasets[0].data = values;
    c.data.datasets[0].backgroundColor = colors;
    c.update('none');
    return;
  }
  const options = {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    plugins: { legend: { display: type === 'doughnut', labels: { color: '#c7cbd6' } } }
  };
  if (type !== 'doughnut') {
    options.scales = {
      x: { ticks: { color: '#8b93a7', maxRotation: 60 }, grid: { color: '#222733' } },
      y: { ticks: { color: '#8b93a7' }, grid: { color: '#222733' }, beginAtZero: true }
    };
    if (horizontal) options.indexAxis = 'y';
  }
  charts[id] = new Chart(canvas, {
    type: type,
    data: { labels: labels, datasets: [{ label: title, data: values, backgroundColor: colors, borderColor: palette[0], tension: 0.25, pointRadius: 2 }] },
    options: options
  });
}

function fillTable(id, rows, cols) {
  const tbody = document.getElementById(id);
  tbody.textContent = '';
  if (!rows.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = cols.length;
    td.className = 'empty';
    td.textContent = 'No data yet.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  rows.forEach(function (r) {
    const tr = document.createElement('tr');
    cols.forEach(function (c) {
      const td = document.createElement('td');
      const v = r[c];
      td.textContent = (v === null || v === undefined) ? '' : String(v);
      if (c === 'severity' && SEVERITIES.indexOf(v) !== -1) td.className = 'sev-' + v;
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
}

function setText(id, value) { document.getElementById(id).textContent = String(value); }

async function refresh() {
  const status = document.getElementById('status');
  try {
    const hours = document.getElementById('range').value;
    const resp = await fetch('/api/data?hours=' + encodeURIComponent(hours), { cache: 'no-store' });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const d = await resp.json();

    setText('c_events', d.summary.events);
    setText('c_ips', d.summary.ips);
    setText('c_logins', d.summary.logins);
    setText('c_accepted', d.summary.accepted);
    setText('c_detections', d.summary.detections);

    drawChart('ch_timeline', 'line', d.timeline, 'bucket', 'n', 'Events', false);
    drawChart('ch_services', 'doughnut', d.services, 'k', 'n', 'Events', false);
    drawChart('ch_ips', 'bar', d.top_ips, 'k', 'n', 'Events', true);
    drawChart('ch_passwords', 'bar', d.top_passwords, 'k', 'n', 'Attempts', true);
    drawChart('ch_usernames', 'bar', d.top_usernames, 'k', 'n', 'Attempts', true);
    drawChart('ch_labels', 'bar', d.labels, 'k', 'n', 'Events', true);
    drawChart('ch_tactics', 'doughnut', d.tactics, 'k', 'n', 'Events', false);

    fillTable('t_techniques', d.techniques, ['technique_id', 'technique_name', 'ips', 'events']);
    fillTable('t_detections', d.recent_detections, ['last_seen', 'src_ip', 'label', 'technique_id', 'severity', 'count', 'evidence']);
    fillTable('t_iocs', d.iocs, ['url', 'n', 'ips']);
    fillTable('t_events', d.recent_events, ['ts', 'src_ip', 'service', 'event', 'username', 'password', 'data']);

    status.className = '';
    status.textContent = 'updated ' + d.generated_at;
  } catch (err) {
    status.className = 'err';
    status.textContent = 'update failed: ' + err.message;
  }
}

document.getElementById('range').addEventListener('change', refresh);
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>
"""


def analyzer_loop(db_path, every):
    while True:
        try:
            analyzer.analyze(db_path)
        except Exception as exc:               # never let the thread die
            print(f"[analyzer] {exc!r}")
        time.sleep(every)


def main():
    p = argparse.ArgumentParser(description="Sundew dashboard")
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--host", default="127.0.0.1", help="keep 127.0.0.1 unless you know why")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--analyze-every", type=int, default=10, metavar="SECONDS",
                   help="how often to rebuild detections (0 = never)")
    args = p.parse_args()

    app.config["DB_PATH"] = args.db
    if not os.path.exists(args.db):
        print(f"[!] {args.db} not found yet. Start sundew.py first (the page will fill in once it exists).")
    if args.analyze_every > 0:
        threading.Thread(target=analyzer_loop, args=(args.db, args.analyze_every), daemon=True).start()
    print(f"[*] Dashboard on http://{args.host}:{args.port}  (Ctrl+C to stop)")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
