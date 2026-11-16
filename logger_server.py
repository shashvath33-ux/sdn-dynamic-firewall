#!/usr/bin/env python3
"""
Centralised Security-Event Logger  (Project 1 - Part 1)

A multi-threaded TCP server built on low-level sockets. The SDN firewall
controller (Part 3) connects to it and sends one JSON object per line, e.g.

    {"event":"BLOCK","src_ip":"10.0.0.3","dst_ip":"10.0.0.10","dst_port":5000,
     "proto":"TCP","reason":"rate limit exceeded","timeout":30,
     "ts":1760000000.123,"first_seen_ts":1760000000.020}

For every message the logger replies with one JSON line:  {"status":"ok","id":17}
(or {"status":"error","error":"..."} for malformed input).

Two files are written (append mode, flushed on every event):
    logs/security_events.log     human readable, one line per event
    logs/security_events.jsonl   machine readable, used by analyze_log.py

Control commands (also one JSON line):
    {"cmd":"ping"}    -> {"status":"ok","pong":true}
    {"cmd":"stats"}   -> counters of events seen so far

Plain text lines (not JSON) are accepted too and stored as event "RAW".

Run standalone:   python3 logger_server.py --host 0.0.0.0 --port 9999
Inside Mininet:   started automatically on the 'logger' host by topology.py
"""

import argparse
import json
import os
import signal
import socket
import sys
import threading
import time
from collections import Counter
from datetime import datetime

try:
    import config
except ImportError:  # allow running the file on its own
    config = None

MAX_LINE_BYTES = 64 * 1024          # drop clients that never send '\n'
KNOWN_EVENTS = {"ALLOW", "DENY", "BLOCK", "UNBLOCK", "ALERT", "INFO", "RAW"}


class EventStore:
    """Thread-safe writer + counters shared by all connection threads."""

    def __init__(self, log_dir, text_name, jsonl_name, quiet=False):
        os.makedirs(log_dir, exist_ok=True)
        self.text_path = os.path.join(log_dir, text_name)
        self.jsonl_path = os.path.join(log_dir, jsonl_name)
        self._text = open(self.text_path, "a", buffering=1, encoding="utf-8")
        self._jsonl = open(self.jsonl_path, "a", buffering=1, encoding="utf-8")
        self._lock = threading.Lock()
        self.quiet = quiet
        self.start_time = time.time()
        self.next_id = 0
        self.by_event = Counter()
        self.by_src = Counter()
        self.malformed = 0
        self.connections = 0

    # ---- bookkeeping -----------------------------------------------------
    def note_connection(self):
        with self._lock:
            self.connections += 1

    def note_malformed(self, peer, reason, raw):
        with self._lock:
            self.malformed += 1
            self._write_text(f"{_now()} | MALFORMED | from={peer} | {reason} | raw={raw[:120]!r}")

    # ---- main entry ------------------------------------------------------
    def record(self, rec, peer):
        """Store one validated event. Returns the assigned event id."""
        recv = time.time()
        with self._lock:
            self.next_id += 1
            rec["id"] = self.next_id
            rec["recv_ts"] = round(recv, 6)
            rec["recv_time"] = _iso(recv)
            rec["sender"] = peer
            ctrl_ts = rec.get("ts")
            if isinstance(ctrl_ts, (int, float)):
                rec["alert_latency_ms"] = round((recv - ctrl_ts) * 1000.0, 3)
            self.by_event[rec["event"]] += 1
            if rec.get("src_ip"):
                self.by_src[rec["src_ip"]] += 1
            self._write_text(self._format(rec))
            self._jsonl.write(json.dumps(rec, sort_keys=True) + "\n")
            return rec["id"]

    def stats(self):
        with self._lock:
            return {
                "uptime_s": round(time.time() - self.start_time, 1),
                "total_events": sum(self.by_event.values()),
                "by_event": dict(self.by_event),
                "top_sources": dict(self.by_src.most_common(5)),
                "malformed": self.malformed,
                "connections": self.connections,
            }

    def close(self):
        with self._lock:
            self._write_text(f"{_now()} | LOGGER_STOP | {json.dumps(self._stats_nolock())}")
            self._text.close()
            self._jsonl.close()

    # ---- helpers (call with lock held) ----------------------------------
    def _stats_nolock(self):
        return {"total_events": sum(self.by_event.values()),
                "by_event": dict(self.by_event), "malformed": self.malformed}

    def _write_text(self, line):
        self._text.write(line + "\n")
        if not self.quiet:
            print(line, flush=True)

    @staticmethod
    def _format(r):
        parts = [
            _iso_to_text(r["recv_time"]),
            f"{r['event']:<7}",
            f"src={r.get('src_ip', '-')} dst={r.get('dst_ip', '-')} "
            f"dport={r.get('dst_port', '-')} proto={r.get('proto', '-')}",
            f"reason={r.get('reason', r.get('message', '-'))}",
        ]
        if "timeout" in r:
            parts.append(f"timeout={r['timeout']}s")
        if "alert_latency_ms" in r:
            parts.append(f"latency={r['alert_latency_ms']}ms")
        parts.append(f"from={r['sender']}")
        return " | ".join(parts)


def _iso(ts):
    return datetime.fromtimestamp(ts).isoformat(timespec="milliseconds")


def _iso_to_text(iso):
    return iso.replace("T", " ")


def _now():
    return _iso_to_text(_iso(time.time()))


# ---------------------------------------------------------------------------
def parse_message(line):
    """Return ('event'|'cmd', dict) or raise ValueError."""
    line = line.strip()
    if not line:
        raise ValueError("empty line")
    if not line.startswith("{"):
        return "event", {"event": "RAW", "message": line}
    try:
        obj = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc.msg}")
    if not isinstance(obj, dict):
        raise ValueError("JSON message must be an object")
    if "cmd" in obj:
        return "cmd", obj
    ev = obj.get("event")
    if not isinstance(ev, str) or not ev.strip():
        raise ValueError("missing 'event' field")
    obj["event"] = ev.strip().upper()
    if obj["event"] not in KNOWN_EVENTS:
        obj["unknown_event_type"] = True      # kept, just flagged
    return "event", obj


def handle_client(conn, addr, store, stop, idle_timeout, slots):
    peer = f"{addr[0]}:{addr[1]}"
    store.note_connection()
    conn.settimeout(idle_timeout)
    buf = b""
    try:
        while not stop.is_set():
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                break                          # idle client, free the thread
            if not chunk:
                break                          # client closed
            buf += chunk
            if len(buf) > MAX_LINE_BYTES and b"\n" not in buf:
                store.note_malformed(peer, "line too long", buf.decode("utf-8", "replace"))
                _send(conn, {"status": "error", "error": "line too long"})
                break
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                reply = process_line(raw.decode("utf-8", "replace"), peer, store)
                if not _send(conn, reply):
                    return
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        try:
            conn.close()
        finally:
            slots.release()


def process_line(text, peer, store):
    try:
        kind, obj = parse_message(text)
    except ValueError as exc:
        store.note_malformed(peer, str(exc), text)
        return {"status": "error", "error": str(exc)}
    if kind == "cmd":
        cmd = obj["cmd"]
        if cmd == "ping":
            return {"status": "ok", "pong": True}
        if cmd == "stats":
            return {"status": "ok", "stats": store.stats()}
        return {"status": "error", "error": f"unknown cmd '{cmd}'"}
    return {"status": "ok", "id": store.record(obj, peer)}


def _send(conn, obj):
    try:
        conn.sendall((json.dumps(obj) + "\n").encode())
        return True
    except OSError:
        return False


def serve(args):
    store = EventStore(args.log_dir, args.text_log, args.jsonl_log, args.quiet)
    stop = threading.Event()
    slots = threading.BoundedSemaphore(args.max_clients)

    def _shutdown(signum, _frame):
        stop.set()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(64)
    srv.settimeout(1.0)                        # lets us notice `stop`
    print(f"[logger] listening on {args.host}:{args.port}  "
          f"(logs: {store.text_path}, {store.jsonl_path})", flush=True)

    try:
        while not stop.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not slots.acquire(blocking=False):
                _send(conn, {"status": "error", "error": "server busy"})
                conn.close()
                continue
            threading.Thread(target=handle_client, daemon=True,
                             args=(conn, addr, store, stop, args.idle_timeout, slots)).start()
    finally:
        srv.close()
        summary = store.stats()
        store.close()
        print(f"[logger] stopped. summary: {json.dumps(summary)}", flush=True)


def main():
    d = config
    p = argparse.ArgumentParser(description="Centralised TCP security-event logger")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=d.LOGGER_PORT if d else 9999)
    p.add_argument("--log-dir", default=d.LOG_DIR if d else "logs")
    p.add_argument("--text-log", default=d.TEXT_LOG if d else "security_events.log")
    p.add_argument("--jsonl-log", default=d.JSONL_LOG if d else "security_events.jsonl")
    p.add_argument("--idle-timeout", type=float, default=120.0,
                   help="close a connection after this many idle seconds")
    p.add_argument("--max-clients", type=int, default=100)
    p.add_argument("--quiet", action="store_true", help="do not echo events to stdout")
    serve(p.parse_args())


if __name__ == "__main__":
    sys.exit(main())
