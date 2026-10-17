"""Sundew - Day 1: multi-service, low-interaction honeypot.

Fake services: FTP, HTTP, SSH (banner only; real SSH is added on Day 2).
Every interaction is logged to SQLite (sundew.db).

High ports are used so no root is needed. Test locally:
    python sundew.py
    nc localhost 2121         (FTP)
    curl localhost:8080       (HTTP)
    nc localhost 2222         (SSH banner)
"""
import socket
import sqlite3
import threading
from datetime import datetime, timezone
from urllib.parse import parse_qs, unquote

# ---------- Config ----------
DB_PATH = "sundew.db"
HOST = "0.0.0.0"
PORTS = {"ftp": 2121, "http": 8080, "ssh": 2222}  # use 21/80/22 on an isolated VM
MAX_CONNECTIONS = 200      # total simultaneous clients across all services
CLIENT_TIMEOUT = 30        # seconds of silence before we hang up
MAX_HTTP_SIZE = 65536      # cap on bytes read per HTTP request

db_lock = threading.Lock()
conn_slots = threading.BoundedSemaphore(MAX_CONNECTIONS)


# ---------- Database / logger ----------
def init_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""CREATE TABLE IF NOT EXISTS events (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        TEXT NOT NULL,
            src_ip    TEXT NOT NULL,
            src_port  INTEGER,
            service   TEXT NOT NULL,
            event     TEXT NOT NULL,
            username  TEXT,
            password  TEXT,
            data      TEXT)""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON events (src_ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_event ON events (event)")
        conn.commit()
    finally:
        conn.close()


def log_event(addr, service, event, data="", username=None, password=None):
    """Store one event. Always uses ? placeholders: attacker text is data, never SQL."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    if username is not None:
        username = username[:200]
    if password is not None:
        password = password[:200]
    with db_lock:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        try:
            conn.execute(
                "INSERT INTO events (ts, src_ip, src_port, service, event, username, password, data) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (ts, addr[0], addr[1], service, event, username, password, data[:2000]),
            )
            conn.commit()
        finally:
            conn.close()
    shown = data or f"user={username} pass={password}"
    print(f"[{ts}] {addr[0]}:{addr[1]} {service} {event} {shown[:80]!r}")


# ---------- Fake FTP ----------
def handle_ftp(conn, addr):
    user = ""
    conn.sendall(b"220 (vsFTPd 3.0.3)\r\n")
    f = conn.makefile("rb")
    try:
        while True:
            line = f.readline(1024)          # capped line length
            if not line:
                break
            text = line.decode(errors="replace").strip()
            cmd, _, arg = text.partition(" ")
            cmd = cmd.upper()
            if cmd == "USER":
                user = arg
                conn.sendall(b"331 Please specify the password.\r\n")
            elif cmd == "PASS":
                log_event(addr, "ftp", "login_attempt", username=user, password=arg)
                conn.sendall(b"530 Login incorrect.\r\n")
            elif cmd == "SYST":
                conn.sendall(b"215 UNIX Type: L8\r\n")
            elif cmd == "FEAT":
                conn.sendall(b"211-Features:\r\n PASV\r\n UTF8\r\n211 End\r\n")
            elif cmd == "PWD":
                conn.sendall(b'257 "/" is the current directory\r\n')
            elif cmd == "TYPE":
                conn.sendall(b"200 Switching to Binary mode.\r\n")
            elif cmd == "QUIT":
                conn.sendall(b"221 Goodbye.\r\n")
                break
            else:
                log_event(addr, "ftp", "command", data=text)
                conn.sendall(b"530 Please login with USER and PASS.\r\n")
    finally:
        f.close()


# ---------- Fake HTTP ----------
LOGIN_PAGE = b"""<html><head><title>Admin Panel</title></head><body>
<h2>Admin Login</h2>
<form method="POST" action="/login">
<input name="username" placeholder="Username"><br>
<input name="password" type="password" placeholder="Password"><br>
<button type="submit">Login</button></form></body></html>"""


def http_response(status, body):
    head = (f"HTTP/1.1 {status}\r\nServer: Apache/2.4.41 (Ubuntu)\r\n"
            f"Content-Type: text/html\r\nContent-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n")
    return head.encode() + body


def read_http_request(conn):
    """Read the full head, then exactly Content-Length body bytes, with size caps."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        buf += chunk
        if len(buf) > MAX_HTTP_SIZE:
            return None
    head, _, body = buf.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        if k.strip().lower() == b"content-length":
            try:
                length = min(int(v.strip()), MAX_HTTP_SIZE)
            except ValueError:
                length = 0
    while len(body) < length:
        chunk = conn.recv(4096)
        if not chunk:
            break
        body += chunk
    return head, body[:length]


def handle_http(conn, addr):
    result = read_http_request(conn)
    if result is None:
        return
    head, body = result
    lines = head.decode(errors="replace").split("\r\n")
    parts = lines[0].split(" ")
    method, path = (parts[0], parts[1]) if len(parts) >= 2 else ("?", "?")
    headers = {}
    for l in lines[1:]:
        k, _, v = l.partition(":")
        headers[k.strip().lower()] = v.strip()
    ua = headers.get("user-agent", "")
    log_event(addr, "http", "request", data=f"{method} {unquote(path)} UA={ua}")

    if method == "POST" and path.startswith("/login"):
        form = parse_qs(body.decode(errors="replace"))
        u = form.get("username", [""])[0]
        p = form.get("password", [""])[0]
        log_event(addr, "http", "login_attempt", username=u, password=p)
        conn.sendall(http_response("401 Unauthorized", b"<h3>Invalid credentials</h3>"))
    else:
        conn.sendall(http_response("200 OK", LOGIN_PAGE))


# ---------- SSH (real handshake via paramiko; see ssh_service.py) ----------
import ssh_service


def handle_ssh(conn, addr):
    ssh_service.handle(conn, addr, log_event)


HANDLERS = {"ftp": handle_ftp, "http": handle_http, "ssh": handle_ssh}


# ---------- Server plumbing ----------
def serve_client(name, handler, conn, addr):
    conn.settimeout(CLIENT_TIMEOUT)
    log_event(addr, name, "connect")
    try:
        handler(conn, addr)
    except (socket.timeout, ConnectionError, OSError):
        pass                                  # scanners drop connections constantly
    except Exception as exc:                  # a bug must never kill the server
        print(f"[!] handler error {name} {addr}: {exc!r}")
    finally:
        log_event(addr, name, "disconnect")
        conn.close()
        conn_slots.release()


def run_service(name, port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, port))
    srv.listen(50)
    print(f"[*] {name.upper()} listening on {port}")
    while True:
        conn, addr = srv.accept()
        if not conn_slots.acquire(blocking=False):   # too many clients: drop this one
            conn.close()
            continue
        threading.Thread(target=serve_client,
                         args=(name, HANDLERS[name], conn, addr),
                         daemon=True).start()


if __name__ == "__main__":
    init_db()
    for svc, port in PORTS.items():
        threading.Thread(target=run_service, args=(svc, port), daemon=True).start()
    print("[*] Sundew running. Ctrl+C to stop.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
