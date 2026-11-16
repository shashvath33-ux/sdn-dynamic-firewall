#!/usr/bin/env python3
"""
Automated evaluation for the Dynamic Firewall project  (must run as root)

  sudo python3 run_experiments.py bench       # performance: no firewall / static / dynamic
  sudo python3 run_experiments.py scenarios   # challenging scenarios + pass/fail checks
  sudo python3 run_experiments.py all

bench
  For every condition (firewall mode x attack rate) a fresh Mininet network and
  a fresh Ryu controller are started. h1 (legitimate user) sends one request
  every 0.5 s for --duration seconds while h3 (attacker) floods the TCP server
  with new connections at the given rate. Reported per condition:
    * legitimate success rate and latency before / during / after the attack
    * time from attack start to the BLOCK decision, number of BLOCK/UNBLOCK
    * attacker connections that actually reached the server (network impact)
  Baselines: mode "none" (plain switch) and "static" (static DENY rules only,
  no rate-based blocking). "dynamic" is the proposed approach.

scenarios (dynamic mode, pass/fail)
  S1 unauthorised access -> DENY events -> escalation to BLOCK -> automatic recovery
  S2 controller failure  -> fail-secure (new connections refused) -> recovery on restart

Results go to results/  (summary.csv, summary.md, per-run logs and JSON).
"""
import argparse
import csv
import json
import os
import shlex
import shutil
import socket
import statistics
import subprocess
import sys
import time
from argparse import Namespace

from mininet.log import setLogLevel
from mininet.clean import cleanup

import config
import topology

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
CLIENT = os.path.join(HERE, "tcp_client.py")
SERVER = os.path.join(HERE, "tcp_server.py")
CONTROLLER_APP = os.path.join(HERE, "firewall_controller.py")
RESULTS = os.path.join(HERE, "results")

ATTACK_START = 5.0          # seconds after the bench starts
HOLD = 8.0                  # seconds each attacker connection is held open
EXP_BLOCK_TIMEOUT = 10      # short block so recovery is visible inside one run


# ----------------------------------------------------------------- helpers
def port_open(ip, port):
    try:
        socket.create_connection((ip, port), timeout=0.5).close()
        return True
    except OSError:
        return False


def start_controller(mode, outfile, env_extra=None):
    env = dict(os.environ, FW_MODE=mode, FW_BLOCK_TIMEOUT_S=str(EXP_BLOCK_TIMEOUT))
    env.update(env_extra or {})
    exe = os.environ.get("RYU_MANAGER") or shutil.which("ryu-manager")
    cmd = ([exe] if exe else [PY, "-c", "from ryu.cmd.manager import main; main()"])
    cmd += ["--ofp-tcp-listen-port", str(config.CONTROLLER_PORT), CONTROLLER_APP]
    proc = subprocess.Popen(cmd, env=env, stdout=open(outfile, "a"), stderr=subprocess.STDOUT)
    for _ in range(60):
        if port_open(config.CONTROLLER_IP, config.CONTROLLER_PORT):
            return proc
        if proc.poll() is not None:
            break
        time.sleep(0.25)
    raise RuntimeError(f"controller did not start - see {outfile}")


def stop_proc(proc, sig=2, wait=3):
    if proc is None or proc.poll() is not None:
        return
    proc.send_signal(sig)
    try:
        proc.wait(timeout=wait)
    except subprocess.TimeoutExpired:
        proc.kill()


class Lab:
    """One Mininet network + controller + logger + app server."""

    def __init__(self, mode, outdir, datapath, env_extra=None):
        self.mode, self.outdir = mode, outdir
        shutil.rmtree(outdir, ignore_errors=True)
        os.makedirs(outdir)
        self.env_extra = env_extra
        self.ctrl_out = os.path.join(outdir, "controller.log")
        self.ctrl = start_controller(mode, self.ctrl_out, env_extra)
        try:
            self._build(datapath, outdir)
        except Exception:
            stop_proc(self.ctrl, wait=5)
            raise

    def _build(self, datapath, outdir):
        args = Namespace(controller_ip=config.CONTROLLER_IP, controller_port=config.CONTROLLER_PORT,
                         of_version=config.OF_VERSION, bw=None, delay=None, loss=None,
                         datapath=datapath, log_dir=outdir)
        self.net, self.root, self.s1 = topology.build_network(args)
        self.net.start()
        if datapath == "user":
            topology.disable_offload(self.net, self.root)
        topology.install_alert_path_flows(self.s1, config.OF_VERSION)
        self.logger_proc = topology.start_logger(self.net, outdir)
        for _ in range(20):                       # wait for the OpenFlow handshake
            if self.s1.connected():
                break
            time.sleep(0.5)
        self.server = self.net.get(config.SERVER_NAME).popen(
            [PY, SERVER, "--host", "0.0.0.0", "--port", str(config.APP_PORT)],
            stdout=open(os.path.join(outdir, "server.log"), "a"), stderr=subprocess.STDOUT)
        time.sleep(1.0)
        self.h = {n: self.net.get(n) for n in config.CLIENTS}
        self.h["h1"].cmd(f"ping -c 2 -W 1 {config.SERVER_IP}")   # warm-up (ARP)

    def client(self, host, *extra):
        """argv list for tcp_client.py (paths may contain spaces)."""
        args = [w for x in extra for w in str(x).split()]   # "--mode normal" -> two argv entries
        return [PY, CLIENT, "--ip", config.SERVER_IP] + args

    def run(self, host, *extra):
        """Run tcp_client.py to completion on a host, return stdout."""
        return self.h[host].cmd(shlex.join(self.client(host, *extra)))

    def popen(self, host, *extra):
        return self.h[host].popen(self.client(host, *extra), stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True)

    def events(self):
        path = os.path.join(self.outdir, config.JSONL_LOG)
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as fh:
            return [json.loads(x) for x in fh if x.strip()]

    def close(self):
        topology.stop_logger(self.logger_proc)
        stop_proc(self.server)
        try:
            self.net.stop()
        finally:
            stop_proc(self.ctrl, wait=5)
            cleanup()


def last_json(text):
    for line in reversed(text.strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except ValueError:
                pass
    return {}


def phase_stats(samples, lo, hi):
    sel = [s for s in samples if lo <= s["t"] < hi]
    ok = [s["latency_ms"] for s in sel if s["status"] == "ok"]
    return {"n": len(sel), "success": round(len(ok) / len(sel), 3) if sel else None,
            "avg_ms": round(statistics.mean(ok), 1) if ok else None}


# ------------------------------------------------------------------- bench
def run_condition(mode, rate, duration, datapath):
    name = f"{mode}_rate{int(rate)}"
    outdir = os.path.join(RESULTS, name)
    print(f"\n=== condition {name} ===", flush=True)
    lab = Lab(mode, outdir, datapath)
    try:
        attack = max(0.0, duration - ATTACK_START - 10.0)      # leave 10 s for recovery
        bench = lab.popen("h1", "--mode bench", "--duration", duration, "--samples")
        flood = None
        if rate > 0:
            flood = lab.popen("h3", "--mode flood", "--rate", rate, "--duration", attack,
                              "--hold", HOLD, "--start-delay", ATTACK_START)
        b = last_json(bench.communicate(timeout=duration + 30)[0])
        f = last_json(flood.communicate(timeout=duration + 60)[0]) if flood else {}
        srv = last_json(lab.run("h1", "--mode stats"))
        ev = lab.events()
    finally:
        lab.close()

    samples = b.get("samples", [])
    t0 = b.get("t_start", 0)
    for s in samples:
        s["t"] = s["t"] - t0
    a0, a1 = ATTACK_START, ATTACK_START + (duration - ATTACK_START - 10.0)
    row = {"mode": mode, "attack_rate": rate,
           "legit_success": b.get("success_rate"), "legit_avg_ms": b.get("avg_latency_ms"),
           "legit_p95_ms": b.get("p95_latency_ms")}
    if rate > 0:
        during = phase_stats(samples, a0 + 1.0, a1)            # skip the 1 s detection transient
        row.update({"before_success": phase_stats(samples, 0, a0)["success"],
                    "during_success": during["success"], "during_avg_ms": during["avg_ms"],
                    "after_success": phase_stats(samples, a1 + config.SERVER_IDLE_TIMEOUT_S, duration)["success"]})
    blocks = [e for e in ev if e["event"] == "BLOCK" and e.get("src_ip") == config.CLIENTS["h3"]["ip"]]
    unblocks = [e for e in ev if e["event"] == "UNBLOCK"]
    if f.get("t_start") and blocks:
        row["time_to_block_s"] = round(blocks[0]["ts"] - f["t_start"], 3)
        if "first_seen_ts" in blocks[0]:
            row["block_decision_ms"] = round((blocks[0]["ts"] - blocks[0]["first_seen_ts"]) * 1000, 1)
    row.update({"blocks": len(blocks), "unblocks": len(unblocks),
                "attacker_conns_reached_server": f.get("connected"),
                "attacker_conns_held": f.get("held"),
                "server_rejected_busy": srv.get("rejected_busy"),
                "alert_latency_ms": round(statistics.median(
                    [e["alert_latency_ms"] for e in ev if "alert_latency_ms" in e]), 2)
                if any("alert_latency_ms" in e for e in ev) else None})
    with open(os.path.join(outdir, "result.json"), "w") as fh:
        json.dump({"row": row, "bench": {k: v for k, v in b.items() if k != "samples"},
                   "flood": f, "server": srv}, fh, indent=2)
    print(json.dumps(row), flush=True)
    return row


def write_summary(rows):
    os.makedirs(RESULTS, exist_ok=True)
    cols = ["mode", "attack_rate", "legit_success", "legit_avg_ms", "legit_p95_ms",
            "before_success", "during_success", "during_avg_ms", "after_success",
            "time_to_block_s", "block_decision_ms", "blocks", "unblocks",
            "attacker_conns_reached_server", "attacker_conns_held", "server_rejected_busy",
            "alert_latency_ms"]
    with open(os.path.join(RESULTS, "summary.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    md = ["| mode | attack conn/s | legit success (all) | legit success during attack | "
          "legit avg latency during attack (ms) | time to block (s) | attacker conns reached server |",
          "|---|---|---|---|---|---|---|"]
    for r in rows:
        md.append("| {mode} | {attack_rate:g} | {a} | {b} | {c} | {d} | {e} |".format(
            a=r.get("legit_success"), b=r.get("during_success", "-"),
            c=r.get("during_avg_ms", r.get("legit_avg_ms")),
            d=r.get("time_to_block_s", "-"), e=r.get("attacker_conns_reached_server", "-"), **r))
    with open(os.path.join(RESULTS, "summary.md"), "w") as fh:
        fh.write("\n".join(md) + "\n")
    print("\n" + "\n".join(md))
    print(f"\nWritten: {RESULTS}/summary.csv and summary.md")


def cmd_bench(a):
    conds = [("none", 0)] + [(m, r) for m in ("static", "dynamic") for r in a.rates]
    if a.modes:
        conds = [(m, r) for m, r in conds if m in a.modes]
    rows = [run_condition(m, r, a.duration, a.datapath) for m, r in conds]
    write_summary(rows)
    return 0


# --------------------------------------------------------------- scenarios
def poll_ok(lab, host, timeout):
    """Run the normal-mode client until it succeeds; return seconds it took or None."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        out = lab.run(host, "--mode normal", "--timeout", 2)
        if "< BYE" in out:
            return round(time.time() - t0, 1)
        time.sleep(1)
    return None


def cmd_scenarios(a):
    results = []

    def check(name, ok, detail=""):
        results.append((name, bool(ok), detail))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name} {detail}", flush=True)

    # ---- S1 unauthorised access -> block -> recovery
    print("\n=== S1: unauthorised access, escalation to BLOCK, automatic recovery ===")
    lab = Lab("dynamic", os.path.join(RESULTS, "scenario_unauthorized"), a.datapath)
    try:
        attacker = config.CLIENTS["h3"]["ip"]
        check("h1 normal access works before the attack", poll_ok(lab, "h1", 5) is not None)
        out = lab.run("h3", "--mode restricted", "--count", 8, "--interval", 1, "--timeout", 1)
        res = last_json(out)
        check("restricted-port attempts never connect", "connected" not in res.get("by_status", {}),
              str(res.get("by_status")))
        time.sleep(1.5)
        ev = lab.events()
        denies = [e for e in ev if e["event"] == "DENY" and e.get("src_ip") == attacker]
        blocks = [e for e in ev if e["event"] == "BLOCK" and e.get("src_ip") == attacker]
        check("DENY events logged centrally", len(denies) >= config.DENY_ESCALATE_COUNT, f"n={len(denies)}")
        check("repeated denials escalate to BLOCK", len(blocks) >= 1,
              blocks[0]["reason"] if blocks else "")
        check("blocked host cannot use the allowed app port either",
              "connect failed" in lab.run("h3", "--mode normal", "--timeout", 1))
        check("other client unaffected during the block", poll_ok(lab, "h1", 5) is not None)
        t = poll_ok(lab, "h3", EXP_BLOCK_TIMEOUT + 15)
        check("automatic recovery after the block timeout", t is not None,
              f"(~{t}s after first retry)" if t is not None else "")
        time.sleep(1.0)
        check("UNBLOCK event logged",
              any(e["event"] == "UNBLOCK" and e.get("src_ip") == attacker for e in lab.events()))
    finally:
        lab.close()

    # ---- S2 controller failure
    print("\n=== S2: controller failure (switch is fail-secure) and recovery ===")
    lab = Lab("dynamic", os.path.join(RESULTS, "scenario_controller_failure"), a.datapath)
    try:
        check("h1 works with the controller up", poll_ok(lab, "h1", 5) is not None)
        stop_proc(lab.ctrl, wait=5)
        time.sleep(a.idle_wait)       # let the cached per-connection flows idle out
        out = lab.run("h1", "--mode normal", "--timeout", 2)
        check("new connections fail while the controller is down (fail-secure)",
              "< BYE" not in out)
        lab.ctrl = start_controller("dynamic", lab.ctrl_out, lab.env_extra)
        t = poll_ok(lab, "h1", 40)
        check("service recovers after the controller restarts", t is not None,
              f"(~{t}s)" if t is not None else "")
    finally:
        lab.close()

    ok = all(r[1] for r in results)
    os.makedirs(RESULTS, exist_ok=True)
    with open(os.path.join(RESULTS, "scenarios.json"), "w") as fh:
        json.dump([{"check": n, "pass": p, "detail": d} for n, p, d in results], fh, indent=2)
    print(f"\nScenarios: {sum(r[1] for r in results)}/{len(results)} checks passed")
    return 0 if ok else 1


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("what", choices=["bench", "scenarios", "all"], nargs="?", default="all")
    p.add_argument("--duration", type=float, default=30.0, help="bench: seconds per condition (>=20)")
    p.add_argument("--rates", type=float, nargs="+", default=[0, 5, 20, 50],
                   help="bench: attacker connection rates (conn/s); 0 = no attack")
    p.add_argument("--modes", nargs="+", choices=["none", "static", "dynamic"],
                   help="bench: restrict to these modes")
    p.add_argument("--datapath", choices=["kernel", "user"], default="kernel")
    p.add_argument("--idle-wait", dest="idle_wait", type=float, default=12.0,
                   help="scenarios: wait after killing the controller (> flow idle timeout)")
    a = p.parse_args()
    if os.geteuid() != 0:
        sys.exit("Run with sudo:  sudo python3 run_experiments.py")
    if a.duration < 20:
        sys.exit("--duration must be at least 20 s")
    setLogLevel("warning")
    cleanup()
    rc = 0
    if a.what in ("bench", "all"):
        rc |= cmd_bench(a)
    if a.what in ("scenarios", "all"):
        rc |= cmd_scenarios(a)
    return rc


if __name__ == "__main__":
    sys.exit(main())
