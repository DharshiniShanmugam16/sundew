#!/usr/bin/env python3
"""Sundew - Day 4: analyzer.

Reads the `events` table, applies detection rules, maps each finding to a
MITRE ATT&CK technique and stores the results in a `detections` table.

    python analyzer.py                 # analyze once, print a report
    python analyzer.py --watch 10      # re-analyze every 10 seconds

The detections table is rebuilt on every run, so running it repeatedly is safe.
Verify technique IDs at attack.mitre.org before quoting them in your README.
"""
import argparse
import re
import sqlite3
import time
from collections import defaultdict
from urllib.parse import unquote

DB_PATH = "sundew.db"

# ---------- Thresholds (tune these; explain them in your README) ----------
BRUTE_MIN_PASSWORDS = 4    # distinct passwords for ONE username -> brute force
SPRAY_MIN_USERS = 5        # ONE password tried on this many usernames -> spraying
SCAN_MIN_EMPTY = 3         # connections that sent nothing, across 2+ services -> scan
PATH_PROBE_MIN = 6         # distinct URL paths requested by one IP -> path probing

# ---------- Label -> (technique id, tactic, technique name, severity) ----------
TECH = {
    "port_scan":         ("T1595.001", "Reconnaissance",     "Active Scanning: Scanning IP Blocks", "low"),
    "vuln_scan":         ("T1595.002", "Reconnaissance",     "Active Scanning: Vulnerability Scanning", "low"),
    "path_probe":        ("T1595.003", "Reconnaissance",     "Active Scanning: Wordlist Scanning", "low"),
    "brute_force":       ("T1110.001", "Credential Access",  "Brute Force: Password Guessing", "medium"),
    "password_spraying": ("T1110.003", "Credential Access",  "Brute Force: Password Spraying", "medium"),
    "ftp_anonymous":     ("T1078",     "Initial Access",     "Valid Accounts (attempted)", "low"),
    "sqli":              ("T1190",     "Initial Access",     "Exploit Public-Facing Application", "high"),
    "traversal":         ("T1190",     "Initial Access",     "Exploit Public-Facing Application", "high"),
    "xss":               ("T1190",     "Initial Access",     "Exploit Public-Facing Application", "medium"),
    "cmd_injection":     ("T1190",     "Initial Access",     "Exploit Public-Facing Application", "high"),
    "log4shell":         ("T1190",     "Initial Access",     "Exploit Public-Facing Application", "high"),
    "shellshock":        ("T1190",     "Initial Access",     "Exploit Public-Facing Application", "high"),
    "ssh_access":        ("T1021.004", "Lateral Movement",   "Remote Services: SSH", "high"),
    "shell_commands":    ("T1059.004", "Execution",          "Command and Scripting Interpreter: Unix Shell", "high"),
    "discovery_system":  ("T1082",     "Discovery",          "System Information Discovery", "medium"),
    "discovery_user":    ("T1033",     "Discovery",          "System Owner/User Discovery", "medium"),
    "discovery_files":   ("T1083",     "Discovery",          "File and Directory Discovery", "medium"),
    "discovery_accounts":("T1087.001", "Discovery",          "Account Discovery: Local Account", "medium"),
    "tool_download":     ("T1105",     "Command and Control","Ingress Tool Transfer", "high"),
    "persistence_ssh_key":("T1098.004","Persistence",        "Account Manipulation: SSH Authorized Keys", "high"),
    "persistence_cron":  ("T1053.003", "Persistence",        "Scheduled Task/Job: Cron", "high"),
    "history_clearing":  ("T1070.003", "Defense Evasion",    "Indicator Removal: Clear Command History", "medium"),
}

# ---------- Web attack patterns (applied AFTER url-decoding) ----------
WEB_RULES = [
    ("sqli", re.compile(r"(union\s+select|\bor\s+1\s*=\s*1|'\s*or\s*'|sleep\(\d+\)|information_schema|;\s*drop\s+table)", re.I)),
    ("traversal", re.compile(r"(\.\./|\.\.\\|/etc/(passwd|shadow)|win\.ini)", re.I)),
    ("xss", re.compile(r"(<script|onerror\s*=|javascript:)", re.I)),
    ("cmd_injection", re.compile(r"(;\s*(cat|ls|id|wget|curl|sh|bash)\b|\$\(|`|\|\s*(sh|bash)\b)", re.I)),
    ("log4shell", re.compile(r"\$\{\s*jndi\s*:", re.I)),
    ("shellshock", re.compile(r"\(\)\s*\{\s*:\s*;\s*\}\s*;")),
]
CREDENTIAL_RULES = [r for r in WEB_RULES if r[0] in ("sqli", "xss")]
SCANNER_UA = re.compile(r"(sqlmap|nikto|zgrab|masscan|nmap|acunetix|nessus|dirbuster|gobuster|wfuzz|ffuf)", re.I)

# ---------- Post-login command patterns ----------
START = r"(?:^|[;&|]\s*)"
SHELL_RULES = [
    ("discovery_system", re.compile(START + r"(uname|lscpu|hostname|uptime)\b|/proc/(cpuinfo|version)", re.I)),
    ("discovery_user", re.compile(START + r"(whoami|id|w|who|last)\b", re.I)),
    ("discovery_files", re.compile(START + r"(ls|find|pwd)\b", re.I)),
    ("discovery_accounts", re.compile(r"/etc/(passwd|shadow)", re.I)),
    ("tool_download", re.compile(START + r"(wget|curl|tftp|ftpget)\b", re.I)),
    ("persistence_ssh_key", re.compile(r"authorized_keys", re.I)),
    ("persistence_cron", re.compile(r"crontab|/etc/cron", re.I)),
    ("history_clearing", re.compile(r"history\s+-c|unset\s+HISTFILE|HISTFILE=/dev/null|\.bash_history", re.I)),
]


class Collector:
    """Merges findings that share the same (ip, label)."""

    def __init__(self):
        self.items = {}

    def add(self, ip, label, first, last, evidence, count=1):
        key = (ip, label)
        e = self.items.get(key)
        if e is None:
            self.items[key] = {"src_ip": ip, "label": label, "count": count,
                               "first_seen": first, "last_seen": last, "ev": [evidence]}
            return
        e["count"] += count
        e["first_seen"] = min(e["first_seen"], first)
        e["last_seen"] = max(e["last_seen"], last)
        if evidence not in e["ev"] and len(e["ev"]) < 3:
            e["ev"].append(evidence)

    def results(self):
        out = []
        for e in self.items.values():
            tid, tactic, name, sev = TECH[e["label"]]
            out.append({"src_ip": e["src_ip"], "label": e["label"], "technique_id": tid,
                        "tactic": tactic, "technique_name": name, "severity": sev,
                        "count": e["count"], "first_seen": e["first_seen"],
                        "last_seen": e["last_seen"], "evidence": " | ".join(e["ev"])[:300]})
        return out


def split_request(data):
    """'GET /path UA=agent'  ->  (method, path, ua)."""
    method, _, rest = data.partition(" ")
    path, _, ua = rest.rpartition(" UA=")
    if not _:                      # no UA marker found
        path, ua = rest, ""
    return method, path, ua


def detect(rows):
    c = Collector()

    # ----- 1. credential attacks (brute force / spraying / anonymous) -----
    pw_by_user = defaultdict(lambda: {"pw": set(), "n": 0, "first": None, "last": None})
    users_by_pw = defaultdict(lambda: {"users": set(), "first": None, "last": None})
    for r in rows:
        if r["event"] != "login_attempt" or r["username"] is None:
            continue
        ip, svc, user, pw, ts = r["src_ip"], r["service"], r["username"], r["password"] or "", r["ts"]
        a = pw_by_user[(ip, svc, user)]
        a["pw"].add(pw)
        a["n"] += 1
        a["first"] = a["first"] or ts
        a["last"] = ts
        b = users_by_pw[(ip, svc, pw)]
        b["users"].add(user)
        b["first"] = b["first"] or ts
        b["last"] = ts
        if svc == "ftp" and user.lower() in ("anonymous", "ftp"):
            c.add(ip, "ftp_anonymous", ts, ts, "anonymous FTP login attempt")
        if svc == "ssh" and r["data"] == "accepted":
            c.add(ip, "ssh_access", ts, ts, f"{svc} login accepted as {user}")
        if svc == "http":                                   # SQLi/XSS typed into the login form
            blob = unquote(f"{user} {pw}")
            for label, rx in CREDENTIAL_RULES:
                if rx.search(blob):
                    c.add(ip, label, ts, ts, f"in login form: {blob[:60]}")

    for (ip, svc, user), a in pw_by_user.items():
        if len(a["pw"]) >= BRUTE_MIN_PASSWORDS:
            c.add(ip, "brute_force", a["first"], a["last"],
                  f"{svc}: user '{user}' tried with {len(a['pw'])} passwords", a["n"])
    for (ip, svc, pw), b in users_by_pw.items():
        if len(b["users"]) >= SPRAY_MIN_USERS:
            c.add(ip, "password_spraying", b["first"], b["last"],
                  f"{svc}: one password tried on {len(b['users'])} usernames", len(b["users"]))

    # ----- 2. port / service scanning: connections that sent nothing -----
    sessions = defaultdict(list)
    for r in rows:
        sessions[(r["src_ip"], r["src_port"], r["service"])].append(r)
    empty = defaultdict(list)
    for (ip, _port, svc), evs in sessions.items():
        if all(e["event"] in ("connect", "disconnect") for e in evs):
            empty[ip].append((svc, evs[0]["ts"], evs[-1]["ts"]))
    for ip, items in empty.items():
        services = {s for s, _, _ in items}
        if len(items) >= SCAN_MIN_EMPTY and len(services) >= 2:
            c.add(ip, "port_scan", min(t for _, t, _ in items), max(t for _, _, t in items),
                  f"{len(items)} empty connections across {sorted(services)}", len(items))

    # ----- 3. web attacks, scanner user-agents, path probing -----
    paths_by_ip = defaultdict(lambda: {"paths": set(), "n": 0, "first": None, "last": None})
    for r in rows:
        if r["service"] != "http" or r["event"] != "request":
            continue
        ip, ts = r["src_ip"], r["ts"]
        method, path, ua = split_request(r["data"] or "")
        text = unquote(unquote(path)) + " " + ua
        for label, rx in WEB_RULES:
            if rx.search(text):
                c.add(ip, label, ts, ts, f"{method} {unquote(path)[:80]}")
        if SCANNER_UA.search(ua):
            c.add(ip, "vuln_scan", ts, ts, f"scanner user-agent: {ua[:50]}")
        p = paths_by_ip[ip]
        p["paths"].add(path.split("?")[0])
        p["n"] += 1
        p["first"] = p["first"] or ts
        p["last"] = ts
    for ip, p in paths_by_ip.items():
        if len(p["paths"]) >= PATH_PROBE_MIN:
            sample = ", ".join(sorted(p["paths"])[:4])
            c.add(ip, "path_probe", p["first"], p["last"],
                  f"{len(p['paths'])} distinct paths e.g. {sample}", p["n"])

    # ----- 4. post-login behaviour in the fake shell -----
    for r in rows:
        if r["service"] != "ssh":
            continue
        ip, ts, data = r["src_ip"], r["ts"], r["data"] or ""
        if r["event"] == "command":
            c.add(ip, "shell_commands", ts, ts, f"ran: {data[:60]}")
            for label, rx in SHELL_RULES:
                if rx.search(data):
                    c.add(ip, label, ts, ts, f"ran: {data[:60]}")
        elif r["event"] == "download_attempt":
            c.add(ip, "tool_download", ts, ts, f"url: {data[:80]}")

    return c.results()


def save(conn, detections):
    conn.execute("""CREATE TABLE IF NOT EXISTS detections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        src_ip TEXT NOT NULL, label TEXT NOT NULL,
        technique_id TEXT, tactic TEXT, technique_name TEXT, severity TEXT,
        count INTEGER, first_seen TEXT, last_seen TEXT, evidence TEXT)""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_det_ip ON detections (src_ip)")
    conn.execute("DELETE FROM detections")
    conn.executemany(
        "INSERT INTO detections (src_ip, label, technique_id, tactic, technique_name, severity,"
        " count, first_seen, last_seen, evidence) VALUES (?,?,?,?,?,?,?,?,?,?)",
        [(d["src_ip"], d["label"], d["technique_id"], d["tactic"], d["technique_name"],
          d["severity"], d["count"], d["first_seen"], d["last_seen"], d["evidence"])
         for d in detections])
    conn.commit()


def analyze(db_path=DB_PATH):
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT id, ts, src_ip, src_port, service, event, username, password, data "
            "FROM events ORDER BY id").fetchall()
        detections = detect(rows)
        save(conn, detections)
        return len(rows), detections
    finally:
        conn.close()


def report(n_events, detections):
    print(f"\nAnalyzed {n_events} events -> {len(detections)} detections "
          f"from {len({d['src_ip'] for d in detections})} IPs\n")
    by_label = defaultdict(list)
    for d in detections:
        by_label[d["label"]].append(d)
    print(f"{'label':<22}{'technique':<11}{'tactic':<20}{'ips':>4}{'events':>8}")
    print("-" * 65)
    for label, items in sorted(by_label.items(), key=lambda kv: -sum(i["count"] for i in kv[1])):
        tid, tactic, _name, _sev = TECH[label]
        print(f"{label:<22}{tid:<11}{tactic:<20}{len(items):>4}{sum(i['count'] for i in items):>8}")
    print("\nPer-IP summary:")
    by_ip = defaultdict(list)
    for d in detections:
        by_ip[d["src_ip"]].append(d)
    for ip, items in sorted(by_ip.items()):
        print(f"  {ip:<16}{', '.join(sorted(i['label'] for i in items))}")
    print("\nMITRE ATT&CK techniques observed:",
          ", ".join(sorted({d['technique_id'] for d in detections})) or "none")


def main():
    p = argparse.ArgumentParser(description="Sundew analyzer")
    p.add_argument("--db", default=DB_PATH)
    p.add_argument("--watch", type=int, default=0, metavar="SECONDS",
                   help="re-run every N seconds (Ctrl+C to stop)")
    args = p.parse_args()
    try:
        while True:
            n, dets = analyze(args.db)
            report(n, dets)
            if not args.watch:
                break
            time.sleep(args.watch)
    except sqlite3.OperationalError as exc:
        raise SystemExit(f"Database problem: {exc}. Run sundew.py first so the events table exists.")
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
