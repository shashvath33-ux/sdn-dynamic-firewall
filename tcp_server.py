#!/usr/bin/env python3
"""
TCP application server  (Project 1 - Part 2)

Line-based text protocol over a plain TCP socket (one command per '\n'):

    HELLO <name>   -> WELCOME <name>
    ECHO <text>    -> ECHO <text>
    TIME           -> TIME <unix timestamp>
    STATS          -> STATS {json}      (accepted / rejected_busy / active / messages)
    BYE            -> BYE               (server closes)

The server is deliberately resource-limited: at most --max-clients connections
are served at the same time. Extra connections are accepted, told "BUSY" and
closed. That bounded capacity is what makes a connection flood harmful, and
therefore what the SDN firewall has to protect (see run_experiments.py).
Connections that stay silent for --idle-timeout seconds are reaped.

    python3 tcp_server.py --host 0.0.0.0 --port 5000
"""
import argparse
import json
import signal
import socket
import sys
import threading
import time

try:
    import config
except ImportError:
    config = None

MAX_LINE = 4096


class Stats:
    def __init__(self):
        self._lock = threading.Lock()
        self.accepted = 0
        self.rejected_busy = 0
        self.active = 0
        self.messages = 0

    def inc(self, field, n=1):
        with self._lock:
            setattr(self, field, getattr(self, field) + n)

    def snapshot(self):
        with self._lock:
            return {"accepted": self.accepted, "rejected_busy": self.rejected_busy,
                    "active": self.active, "messages": self.messages}


def reply(conn, text):
    try:
        conn.sendall((text + "\n").encode("utf-8"))
        return True
    except OSError:
        return False


def handle(conn, addr, stats, slots, stop, idle_timeout, verbose):
    peer = f"{addr[0]}:{addr[1]}"
    conn.settimeout(idle_timeout)
    buf = b""
    try:
        while not stop.is_set():
            try:
                chunk = conn.recv(1024)
            except socket.timeout:
                if verbose:
                    print(f"[-] {peer} idle, closing", flush=True)
                break
            if not chunk:
                break
            buf += chunk
            if len(buf) > MAX_LINE and b"\n" not in buf:
                reply(conn, "ERR line too long")
                break
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                line = raw.decode("utf-8", "replace").strip()
                if not line:
                    continue
                stats.inc("messages")
                cmd, _, arg = line.partition(" ")
                cmd = cmd.upper()
                if cmd == "HELLO":
                    ok = reply(conn, f"WELCOME {arg or 'anonymous'}")
                elif cmd == "ECHO":
                    ok = reply(conn, f"ECHO {arg}")
                elif cmd == "TIME":
                    ok = reply(conn, f"TIME {time.time():.3f}")
                elif cmd == "STATS":
                    ok = reply(conn, "STATS " + json.dumps(stats.snapshot()))
                elif cmd == "BYE":
                    reply(conn, "BYE")
                    return
                else:
                    ok = reply(conn, f"ERR unknown command '{cmd}'")
                if not ok:
                    return
    except OSError:
        pass
    finally:
        try:
            conn.close()
        finally:
            stats.inc("active", -1)
            slots.release()
            if verbose:
                print(f"[-] {peer} closed", flush=True)


def serve(args):
    stats = Stats()
    stop = threading.Event()
    slots = threading.BoundedSemaphore(args.max_clients)
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(128)
    srv.settimeout(1.0)
    print(f"[server] listening on {args.host}:{args.port} "
          f"(max_clients={args.max_clients}, idle_timeout={args.idle_timeout}s)", flush=True)
    try:
        while not stop.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not slots.acquire(blocking=False):
                stats.inc("rejected_busy")
                reply(conn, "BUSY")
                conn.close()
                continue
            stats.inc("accepted")
            stats.inc("active")
            if args.verbose:
                print(f"[+] {addr[0]}:{addr[1]} connected", flush=True)
            threading.Thread(target=handle, daemon=True,
                             args=(conn, addr, stats, slots, stop,
                                   args.idle_timeout, args.verbose)).start()
    finally:
        srv.close()
        print(f"[server] stopped. stats: {json.dumps(stats.snapshot())}", flush=True)


def main():
    c = config
    p = argparse.ArgumentParser(description="Resource-limited TCP application server")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=c.APP_PORT if c else 5000)
    p.add_argument("--max-clients", type=int, default=c.SERVER_MAX_CLIENTS if c else 20)
    p.add_argument("--idle-timeout", type=float,
                   default=c.SERVER_IDLE_TIMEOUT_S if c else 6.0)
    p.add_argument("--verbose", action="store_true", help="print every connect/close")
    serve(p.parse_args())


if __name__ == "__main__":
    sys.exit(main())
