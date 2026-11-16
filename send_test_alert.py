#!/usr/bin/env python3
"""
Tiny client for testing the logger WITHOUT the controller.
It also doubles as a reference for how Part 3 should send alerts.

  python3 send_test_alert.py --host 127.0.0.1 --event BLOCK --src 10.0.0.3 \
          --dst 10.0.0.10 --dport 5000 --reason "rate limit" --timeout 30
  python3 send_test_alert.py --host 127.0.0.1 --count 50 --interval 0.01
  python3 send_test_alert.py --host 127.0.0.1 --stats
  python3 send_test_alert.py --host 127.0.0.1 --raw "plain text alert"
"""
import argparse
import json
import socket
import sys
import time

try:
    import config
except ImportError:
    config = None


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=config.LOGGER_IP if config else "10.0.0.100")
    p.add_argument("--port", type=int, default=config.LOGGER_PORT if config else 9999)
    p.add_argument("--event", default="ALERT")
    p.add_argument("--src", default="10.0.0.3")
    p.add_argument("--dst", default="10.0.0.10")
    p.add_argument("--dport", type=int, default=5000)
    p.add_argument("--proto", default="TCP")
    p.add_argument("--reason", default="test alert")
    p.add_argument("--timeout", type=int, default=None, help="rule timeout in seconds")
    p.add_argument("--count", type=int, default=1)
    p.add_argument("--interval", type=float, default=0.0)
    p.add_argument("--stats", action="store_true")
    p.add_argument("--ping", action="store_true")
    p.add_argument("--raw", default=None, help="send a plain-text line instead of JSON")
    a = p.parse_args()

    try:
        s = socket.create_connection((a.host, a.port), timeout=5)
    except OSError as exc:
        print(f"FAIL: cannot connect to logger {a.host}:{a.port}: {exc}")
        return 1
    f = s.makefile("rw", encoding="utf-8", newline="\n")

    def rpc(text):
        f.write(text + "\n")
        f.flush()
        return f.readline().strip()

    if a.stats:
        print(rpc(json.dumps({"cmd": "stats"})))
        return 0
    if a.ping:
        print(rpc(json.dumps({"cmd": "ping"})))
        return 0
    ok = 0
    for i in range(a.count):
        if a.raw is not None:
            reply = rpc(a.raw)
        else:
            msg = {"event": a.event, "src_ip": a.src, "dst_ip": a.dst,
                   "dst_port": a.dport, "proto": a.proto,
                   "reason": a.reason, "ts": time.time()}
            if a.timeout is not None:
                msg["timeout"] = a.timeout
            reply = rpc(json.dumps(msg))
        if '"ok"' in reply:
            ok += 1
        if a.count <= 5:
            print(reply)
        if a.interval:
            time.sleep(a.interval)
    print(f"sent={a.count} acked={ok}")
    s.close()
    return 0 if ok == a.count else 2


if __name__ == "__main__":
    sys.exit(main())
