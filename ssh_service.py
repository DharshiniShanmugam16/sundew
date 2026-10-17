"""Sundew - Day 2: SSH service.

Performs a REAL SSH handshake using paramiko so we can read the username and
password an attacker sends. After a few failed attempts from the same IP we
let them in to a FAKE shell and log every command they type.

SAFETY: the fake shell never executes anything. Output comes from a
dictionary lookup only. Never pass attacker input to os.system/subprocess/eval.
"""
import base64
import hashlib
import logging
import os
import re
import threading
import time

import paramiko

logging.getLogger("paramiko").setLevel(logging.CRITICAL)   # keep the console clean

# ---------- Config ----------
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
KEY_FILE = "host_rsa.key"
ACCEPT_AFTER = 3             # reject this many attempts per IP, then accept
MAX_TRACKED_IPS = 5000
SESSION_MAX_SECONDS = 300
SESSION_MAX_COMMANDS = 100
HOSTNAME = "srv01"


# ---------- Host key (generated once, then reused) ----------
def load_host_key():
    if os.path.exists(KEY_FILE):
        return paramiko.RSAKey(filename=KEY_FILE)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(KEY_FILE)
    os.chmod(KEY_FILE, 0o600)
    return key


HOST_KEY = load_host_key()

# ---------- Per-IP failure counter ----------
_fail_counts = {}
_fail_lock = threading.Lock()


def _should_accept(ip):
    with _fail_lock:
        n = _fail_counts.get(ip, 0)
        if n >= ACCEPT_AFTER:
            return True
        if len(_fail_counts) >= MAX_TRACKED_IPS:
            _fail_counts.clear()
        _fail_counts[ip] = n + 1
        return False


# ---------- Fake command output (lookup only, nothing is executed) ----------
FAKE_OUTPUT = {
    "whoami": "root",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "pwd": "/root",
    "hostname": HOSTNAME,
    "uname": "Linux",
    "uname -a": f"Linux {HOSTNAME} 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux",
    "uname -m": "x86_64",
    "ls": "backup.tar.gz  notes.txt",
    "ls -la": ("total 28\r\n"
               "drwx------  3 root root 4096 Oct  2 09:12 .\r\n"
               "drwxr-xr-x 19 root root 4096 Sep 28 18:40 ..\r\n"
               "-rw-------  1 root root  412 Oct  2 09:12 .bash_history\r\n"
               "-rw-r--r--  1 root root 3106 Oct 15  2021 .bashrc\r\n"
               "-rw-r--r--  1 root root 1840 Oct  1 17:03 backup.tar.gz\r\n"
               "-rw-r--r--  1 root root  127 Sep 30 11:21 notes.txt"),
    "cat /etc/passwd": ("root:x:0:0:root:/root:/bin/bash\r\n"
                        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n"
                        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\r\n"
                        "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash"),
    "w": (" 10:14:02 up 41 days,  3:12,  1 user,  load average: 0.00, 0.01, 0.00\r\n"
          "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT"),
    "uptime": " 10:14:02 up 41 days,  3:12,  1 user,  load average: 0.00, 0.01, 0.00",
}
URL_RE = re.compile(r"(?:https?|ftp)://[^\s;|&'\"]+", re.I)
SPLIT_RE = re.compile(r"\s*(?:;|&&|\|\|)\s*")


def fake_run(cmd):
    """Return fake output text for a command line. Pure lookup, no execution."""
    outputs = []
    for part in SPLIT_RE.split(cmd.strip()):
        words = part.split()
        if not words:
            continue
        base = words[0]
        if part in FAKE_OUTPUT:
            outputs.append(FAKE_OUTPUT[part])
        elif base in ("wget", "curl"):
            outputs.append(f"{base}: unable to resolve host address")
        elif base in ("cd", "export", "unset", "history", "chmod", "mkdir", "rm", "nohup"):
            continue
        elif base == "echo":
            outputs.append(part[4:].strip().strip("\"'"))
        else:
            outputs.append(f"-bash: {base}: command not found")
    return "\r\n".join(o for o in outputs if o is not None)


def log_command(addr, log_event, cmd):
    log_event(addr, "ssh", "command", data=cmd)
    for url in URL_RE.findall(cmd):
        log_event(addr, "ssh", "download_attempt", data=url)


# ---------- paramiko server interface ----------
class HoneypotSSH(paramiko.ServerInterface):
    def __init__(self, addr, log_event):
        self.addr = addr
        self.log_event = log_event
        self.ready = threading.Event()   # set when a shell or exec is requested
        self.exec_command = None

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_auth_password(self, username, password):
        accept = _should_accept(self.addr[0])
        self.log_event(self.addr, "ssh", "login_attempt",
                       data="accepted" if accept else "rejected",
                       username=username, password=password)
        return paramiko.AUTH_SUCCESSFUL if accept else paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        fp = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        self.log_event(self.addr, "ssh", "pubkey_offer",
                       data=f"type={key.get_name()} sha256={fp}", username=username)
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height,
                                  pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.ready.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.exec_command = command.decode(errors="replace")
        self.ready.set()
        return True


# ---------- fake interactive shell ----------
def fake_shell(chan, addr, log_event):
    prompt = f"root@{HOSTNAME}:~# ".encode()
    chan.send(b"Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n")
    chan.send(prompt)
    chan.settimeout(60)
    buf = b""
    esc = 0
    started = time.time()
    count = 0
    while time.time() - started < SESSION_MAX_SECONDS and count < SESSION_MAX_COMMANDS:
        data = chan.recv(1024)
        if not data:
            break
        for byte in data:
            ch = bytes([byte])
            if esc:                         # skip arrow-key escape sequences
                esc -= 1
                continue
            if ch == b"\x1b":
                esc = 2
            elif ch in (b"\r", b"\n"):
                cmd = buf.decode(errors="replace").strip()
                buf = b""
                chan.send(b"\r\n")
                if cmd:
                    count += 1
                    log_command(addr, log_event, cmd[:500])
                    if cmd in ("exit", "logout"):
                        return
                    out = fake_run(cmd)
                    if out:
                        chan.send(out.encode() + b"\r\n")
                chan.send(prompt)
            elif ch == b"\x03":             # Ctrl+C
                buf = b""
                chan.send(b"^C\r\n" + prompt)
            elif ch == b"\x04":             # Ctrl+D
                return
            elif ch in (b"\x7f", b"\x08"):  # backspace
                if buf:
                    buf = buf[:-1]
                    chan.send(b"\x08 \x08")
            elif len(buf) < 500:
                buf += ch
                chan.send(ch)               # the server must echo typed characters


# ---------- entry point called from sundew.py ----------
def handle(conn, addr, log_event):
    transport = paramiko.Transport(conn)
    transport.local_version = SSH_BANNER
    transport.add_server_key(HOST_KEY)
    server = HoneypotSSH(addr, log_event)
    try:
        transport.start_server(server=server)
        chan = transport.accept(60)          # wait for the client to open a channel
        if chan is None:
            return                           # bot tried passwords and left, or timed out
        if not server.ready.wait(15):
            return
        if server.exec_command is not None:  # e.g. ssh host 'uname -a'
            log_command(addr, log_event, server.exec_command[:500])
            out = fake_run(server.exec_command)
            if out:
                chan.send(out.encode() + b"\r\n")
            chan.send_exit_status(0)
        else:
            fake_shell(chan, addr, log_event)
    except Exception:
        pass                                 # scanners and resets are normal
    finally:
        transport.close()
