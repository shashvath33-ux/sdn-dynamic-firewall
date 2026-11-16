#!/usr/bin/env python3
"""
TCP client / traffic generator  (Project 1 - Part 2)

Modes
  normal      one connection: HELLO, a few ECHOs, BYE (functional test)
  bench       legitimate user: every --interval s open a connection, send one
              ECHO, time the reply, close. Records per-request latency/status.
              Prints a JSON summary (and optionally the raw samples).
  flood       attacker: --rate new connections per second for --duration s,
              each held open for --hold s (exhausts the server's slots).
  restricted  unauthorised access: repeatedly connect to a restricted port.
  stats       ask the server for its counters.

Examples
  python3 tcp_client.py --mode normal     --ip 10.0.0.10
  python3 tcp_client.py --mode bench      --ip 10.0.0.10 --duration 30
  python3 tcp_client.py --mode flood      --ip 10.0.0.10 --rate 20 --duration 15
  python3 tcp_client.py --mode restricted --ip 10.0.0.10 --count 10
  python3 tcp_client.py --mode stats      --ip 10.0.0.10
"""
import argparse
import json
import socket
import sys
import threading
import time

try:
    import config
except ImportError:
    config = None

APP_PORT = config.APP_PORT if config else 5000
RESTRICTED_PORT = config.RESTRICTED_PORT if config else 6000
SERVER_IP = config.SERVER_IP if config else "10.0.0.10"


def recv_line(sock, timeout):
    sock.settimeout(timeout)
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(1024)
        if not chunk:
            break
        buf += chunk
    return buf.decode("utf-8", "replace").strip()


def classify_error(exc):
    if isinstance(exc, socket.timeout):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, ConnectionResetError):
        return "reset"
    return "error"


# ------------------------------------------------------------------ normal
def mode_normal(a):
    try:
        s = socket.create_connection((a.ip, a.port), timeout=a.timeout)
    except OSError as exc:
        print(f"[-] connect failed ({classify_error(exc)}): {exc}")
        print("    firewall may have denied/blocked this host, or the server is down")
        return 1
    with s:
        for cmd in ("HELLO tester", "ECHO hello from the client", "TIME", "STATS", "BYE"):
            s.sendall((cmd + "\n").encode())
            print(f"> {cmd}\n< {recv_line(s, a.timeout)}")
    return 0


# ------------------------------------------------------------------- bench
def one_request(ip, port, timeout):
    """Returns (status, latency_s)."""
    t0 = time.time()
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
    except OSError as exc:
        return classify_error(exc), time.time() - t0
    try:
        s.sendall(b"ECHO ping\n")
        line = recv_line(s, timeout)
        dt = time.time() - t0
        if line.startswith("ECHO"):
            return "ok", dt
        if line.startswith("BUSY"):
            return "busy", dt
        return "error", dt
    except OSError as exc:
        return classify_error(exc), time.time() - t0
    finally:
        s.close()


def pct(vals, q):
    if not vals:
        return None
    v = sorted(vals)
    return v[min(len(v) - 1, int(round(q * (len(v) - 1))))]


def mode_bench(a):
    samples = []
    t_start = time.time()
    while time.time() - t_start < a.duration:
        t = time.time()
        status, lat = one_request(a.ip, a.port, a.timeout)
        samples.append({"t": round(t, 3), "status": status, "latency_ms": round(lat * 1000, 2)})
        time.sleep(max(0.0, a.interval - (time.time() - t)))
    ok = [s["latency_ms"] for s in samples if s["status"] == "ok"]
    summary = {
        "mode": "bench", "t_start": round(t_start, 3), "t_end": round(time.time(), 3),
        "requests": len(samples), "ok": len(ok),
        "success_rate": round(len(ok) / len(samples), 4) if samples else 0,
        "avg_latency_ms": round(sum(ok) / len(ok), 2) if ok else None,
        "p95_latency_ms": pct(ok, 0.95),
        "by_status": {k: sum(1 for s in samples if s["status"] == k)
                      for k in sorted({s["status"] for s in samples})},
    }
    if a.samples:
        summary["samples"] = samples
    print(json.dumps(summary))
    return 0


# ------------------------------------------------------------------- flood
def mode_flood(a):
    lock = threading.Lock()
    counts = {"attempts": 0, "connected": 0, "held": 0, "busy": 0,
              "timeout": 0, "refused": 0, "reset": 0, "error": 0}

    def bump(k):
        with lock:
            counts[k] += 1

    def attempt():
        bump("attempts")
        try:
            s = socket.create_connection((a.ip, a.port), timeout=a.connect_timeout)
        except OSError as exc:
            bump(classify_error(exc))
            return
        bump("connected")
        try:
            s.sendall(b"HELLO flooder\n")
            line = recv_line(s, a.connect_timeout)
            if line.startswith("BUSY"):
                bump("busy")
                return
            bump("held")
            time.sleep(a.hold)          # keep the server slot occupied
        except OSError as exc:
            bump(classify_error(exc))
        finally:
            s.close()

    if a.start_delay:
        time.sleep(a.start_delay)
    t_start = time.time()
    interval = 1.0 / a.rate
    threads, n = [], 0
    while time.time() - t_start < a.duration:
        th = threading.Thread(target=attempt, daemon=True)
        th.start()
        threads.append(th)
        n += 1
        nxt = t_start + n * interval
        time.sleep(max(0.0, nxt - time.time()))
    t_end = time.time()
    for th in threads:
        th.join(timeout=a.hold + a.connect_timeout + 1)
    print(json.dumps({"mode": "flood", "rate": a.rate, "t_start": round(t_start, 3),
                      "t_end": round(t_end, 3), **counts}))
    return 0


# -------------------------------------------------------------- restricted
def mode_restricted(a):
    port = a.restricted_port
    results = []
    for i in range(1, a.count + 1):
        t0 = time.time()
        try:
            s = socket.create_connection((a.ip, port), timeout=a.timeout)
            s.close()
            status = "connected"          # would mean the firewall let it through
        except OSError as exc:
            status = classify_error(exc)
        results.append(status)
        print(f"attempt {i}/{a.count} to {a.ip}:{port} -> {status}")
        time.sleep(max(0.0, a.interval - (time.time() - t0)))
    print(json.dumps({"mode": "restricted", "port": port,
                      "by_status": {k: results.count(k) for k in sorted(set(results))}}))
    return 0


# ------------------------------------------------------------------- stats
def mode_stats(a):
    try:
        s = socket.create_connection((a.ip, a.port), timeout=a.timeout)
    except OSError as exc:
        print(json.dumps({"error": classify_error(exc)}))
        return 1
    with s:
        s.sendall(b"STATS\n")
        line = recv_line(s, a.timeout)
    print(line.replace("STATS ", "", 1))
    return 0


def main():
    p = argparse.ArgumentParser(description="TCP client / traffic generator")
    p.add_argument("--mode", choices=["normal", "bench", "flood", "restricted", "stats"],
                   default="normal")
    p.add_argument("--ip", default=SERVER_IP)
    p.add_argument("--port", type=int, default=APP_PORT)
    p.add_argument("--timeout", type=float, default=2.0, help="socket timeout (s)")
    # bench
    p.add_argument("--duration", type=float, default=20.0)
    p.add_argument("--interval", type=float, default=0.5, help="bench: gap between requests")
    p.add_argument("--samples", action="store_true", help="bench: include raw samples in output")
    # flood
    p.add_argument("--rate", type=float, default=20.0, help="flood: new connections / second")
    p.add_argument("--hold", type=float, default=8.0, help="flood: seconds each connection is held")
    p.add_argument("--connect-timeout", type=float, default=2.0)
    p.add_argument("--start-delay", type=float, default=0.0)
    # restricted
    p.add_argument("--restricted-port", type=int, default=RESTRICTED_PORT)
    p.add_argument("--count", type=int, default=10)
    a = p.parse_args()
    return {"normal": mode_normal, "bench": mode_bench, "flood": mode_flood,
            "restricted": mode_restricted, "stats": mode_stats}[a.mode](a)


if __name__ == "__main__":
    sys.exit(main())
