# Dynamic Firewall with Security Event Logger

SDN-Socket Programming (Jackfruit mini project) - **Project 1**, protocol **TCP**.
Stack: Python low-level sockets, Mininet, Open vSwitch (OpenFlow 1.3), Ryu controller.

An SDN firewall watches the TCP traffic that a socket application generates, classifies every new
connection by *(source, destination, port)*, and installs allow / deny / block rules on the switch
on the fly. Every security decision is reported over a TCP socket to a centralised logger. A host
that floods the server or keeps probing forbidden ports is **blocked automatically** and
**recovers automatically** when the block expires.

## 1. Architecture

```
 h1 10.0.0.1 (client)     h2 10.0.0.2 (client)     h4 10.0.0.4 (client)
 h3 10.0.0.3 (attacker)   srv 10.0.0.10 (TCP app :5000)   logger 10.0.0.100 (:9999)
      \        \               |               /             /
       +--------+--------------+--------------+-------------+--- s1 (OVS, OpenFlow 1.3, fail-secure)
                                                                |   \__ root namespace 10.0.0.254
                                       OpenFlow (127.0.0.1:6653)|
                                                  Ryu: firewall_controller.py  -- alerts (TCP :9999) --> logger
```

| Component | File | Role |
|---|---|---|
| TCP application server | `tcp_server.py` | line protocol (HELLO/ECHO/TIME/STATS/BYE), thread per client, **bounded capacity** (20 slots) so a flood really hurts, idle reaping |
| TCP client / traffic generator | `tcp_client.py` | modes `normal`, `bench` (legit user, measures latency), `flood` (attacker), `restricted` (unauthorised access), `stats` |
| SDN controller | `firewall_controller.py` | classification, rule installation, rate based blocking, automatic recovery, alert queue |
| Security logger | `logger_server.py` | multi-threaded TCP server, JSON-lines in, `logs/security_events.log` + `.jsonl` out |
| Topology | `topology.py` | Mininet: 4 clients, server, logger, one OVS switch, remote controller, root-namespace port |
| Shared settings | `config.py` | IPs, ports and every policy threshold (override with `FW_<NAME>` env vars) |
| Evaluation | `run_experiments.py`, `analyze_log.py` | automated benchmark + scenarios, log analysis |
| Tests | `tests/test_controller_logic.py` | offline unit tests of the controller (no Mininet needed) |

### Policy (classification)

| New TCP connection | Verdict | Rule installed |
|---|---|---|
| any host -> restricted port (6000) | **DENY** | drop `(src,dst,dport)`, priority 500, 1 s |
| any host -> server on a port other than 5000 | **DENY** | same (default deny to the server) |
| any client -> logger (only the controller may report) | **DENY** | same |
| client -> server:5000, everything else | **ALLOW** | forward flows for both directions, priority 10, idle 10 s |

### Dynamic behaviour (mode `dynamic`)

* **Flood / scan detection**: >= 10 new connections (TCP SYN) from one source within 3 s -> **BLOCK**.
* **Unauthorised access**: 3 DENY decisions for one source within 30 s -> **BLOCK**.
* **BLOCK** = drop all IP traffic from that source, priority 1000, `hard_timeout` 30 s, `SEND_FLOW_REM`.
* **Recovery**: the switch deletes the block flow when the timeout expires; the controller receives
  `FlowRemoved` and sends `UNBLOCK` to the logger. No operator action.
* The server, logger and controller addresses are exempt from blocking.
* **Fail-secure**: with `failMode=secure` a dead controller means *no new connections*, never an implicit allow.

### Modes (for the baseline comparison) - environment variable `FW_MODE`

| Mode | Behaviour |
|---|---|
| `dynamic` (default) | everything above |
| `static` | only the static DENY rules (what a conventional ACL does); no rate based blocking |
| `none` | plain learning switch, no firewall |

### Logger protocol (controller -> logger)

TCP to `10.0.0.100:9999`, one JSON object per line, reply `{"status":"ok","id":N}`.
Events: `ALLOW` (sampled, max one per flow key per 30 s), `DENY`, `BLOCK`, `UNBLOCK`, `INFO`.
`BLOCK` carries `ts` (decision time) and `first_seen_ts` (first suspicious packet) so the response
time can be computed; `UNBLOCK` closes the recovery interval. Details: `README_part1.md`.

## 2. Setup on Ubuntu (20.04 / 22.04 / 24.04, VM or native)

```bash
unzip dynamic-firewall.zip && cd dynamic-firewall
bash setup_ubuntu.sh          # Mininet + OVS (apt) and Ryu in ~/ryu-venv (Python 3.9)
sudo mn --test pingall        # Mininet sanity check (expect 0% dropped)
~/ryu-venv/bin/python tests/test_controller_logic.py     # 10 offline tests, expect OK
```

Why a separate Ryu virtualenv: Ryu does not install on Python >= 3.11 (Ubuntu 22.04+/24.04 ship
3.10/3.12), so `setup_ubuntu.sh` fetches a private Python 3.9 with `uv`. Mininet itself stays on the
system Python and is run with `sudo python3`.

If `sudo modprobe openvswitch` fails (some VMs, WSL2) add `--datapath user` to `topology.py` and
`run_experiments.py`; it is slower but behaves the same.

## 3. Run it manually (3 terminals)

```bash
# terminal 1 - controller (add FW_MODE=static to see the baseline)
source ~/ryu-venv/bin/activate
cd dynamic-firewall && ryu-manager --ofp-tcp-listen-port 6653 firewall_controller.py

# terminal 2 - network + logger
cd dynamic-firewall && sudo python3 topology.py          # opens the Mininet CLI

# terminal 3 - live security events
tail -f dynamic-firewall/logs/security_events.log
```

In the Mininet CLI:

```
mininet> srv python3 tcp_server.py > logs/server.log 2>&1 &
mininet> h1 python3 tcp_client.py --mode normal --ip 10.0.0.10            # ALLOW: full conversation
mininet> h1 python3 tcp_client.py --mode normal --ip 10.0.0.10 --port 22   # DENY: port not exposed
mininet> h3 python3 tcp_client.py --mode restricted --ip 10.0.0.10 --count 8   # DENY x3 -> BLOCK
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep priority=1000     # the block rule
mininet> h3 python3 tcp_client.py --mode normal --ip 10.0.0.10             # fails: blocked
mininet> h1 python3 tcp_client.py --mode normal --ip 10.0.0.10             # still works
   ... wait 30 s ...                                                       # UNBLOCK appears in the log
mininet> h3 python3 tcp_client.py --mode normal --ip 10.0.0.10             # works again
mininet> h1 python3 tcp_client.py --mode bench --ip 10.0.0.10 --duration 25 &
mininet> h3 python3 tcp_client.py --mode flood --ip 10.0.0.10 --rate 20 --duration 10   # flood -> BLOCK in <1 s
mininet> srv python3 tcp_client.py --mode stats --ip 10.0.0.10
```

Repeat the flood with the controller restarted as `FW_MODE=static` and watch `h1`'s success rate collapse.
Network impact tests: `sudo python3 topology.py --bw 10 --delay 20ms --loss 2`.
Clean up after a crash: `sudo mn -c`.

## 4. Automated evaluation

```bash
# Mininet needs the SYSTEM python (/usr/bin/python3); Ryu lives in the venv, so pass its path:
export RYU_MANAGER="$HOME/ryu-venv/bin/ryu-manager"
sudo mn -c                                  # clean any old Mininet / Ryu state first
sudo -E /usr/bin/python3 run_experiments.py all      # ~7 min
#   bench      9 runs: none/static/dynamic x attack rate 0/5/20/50 connections per second
#   scenarios  S1 unauthorised access -> BLOCK -> recovery, S2 controller failure -> recovery (11 checks)
python3 analyze_log.py results/dynamic_rate20/security_events.jsonl --csv events.csv
```

Output: `results/summary.csv`, `results/summary.md`, `results/scenarios.json`, and per-run logs,
controller output and raw JSON in `results/<mode>_rate<N>/`.

For every run a fresh network and controller are started. `h1` is a legitimate user (one request per
0.5 s for 30 s). `h3` floods the server from t=5 s to t=20 s; every flood connection is held open 8 s.
The block timeout is shortened to 10 s for the experiments so recovery happens within a run.

### Results (our run on the VirtualBox VM)

Raw data: `results/` (summary.csv, summary.md, scenarios.json, one folder per run). Scenarios: **11/11 checks passed**.
(*latency during the attack for attack rows; no-attack latency for the rate-0 rows)

| mode | attack conn/s | legit success (all) | legit success during attack | legit avg latency (ms)* | time to block (s) | attacker conns reached server |
|---|---|---|---|---|---|---|
| none | 0 | 1.0 | - | 11.69 | - | - |
| static | 0 | 1.0 | - | 10.5 | - | - |
| static | 5 | 0.8302 | 0.654 | 11.3 | - | 75 |
| static | 20 | 0.4833 | 0.107 | 12.2 | - | 300 |
| static | 50 | 0.3793 | 0.0 | n/a | - | 750 |
| dynamic | 0 | 1.0 | - | 10.65 | - | - |
| dynamic | 5 | 1.0 | 1.0 | 10.6 | 1.806 | 17 |
| dynamic | 20 | 1.0 | 1.0 | 11.3 | 0.46 | 18 |
| dynamic | 50 | 1.0 | 1.0 | 9.7 | 0.194 | 18 |

How to read it: the server has 20 slots. With only static rules the flood fills them, so legitimate
requests get `BUSY` and the success rate collapses. With the dynamic firewall the attacker is blocked
after at most ~10 connections (fewer than the 20 slots), so the legitimate user is unaffected, and the
rule disappears by itself 10 s later (the attacker is re-blocked if it keeps flooding, hence 2 blocks
per run). `time to block` is measured from the first flood connection to the controller's BLOCK
decision; it shrinks as the attack rate rises because the threshold is reached sooner. The firewall's
overhead on normal traffic is the three rate-0 rows (`none` vs `static` vs `dynamic`): the
differences are a few milliseconds and within run-to-run noise, because forwarding flows are cached
in the switch after the first packet of each connection.

The same pattern (dynamic keeps 100%, static collapses) was also obtained during development in a Linux sandbox with Open vSwitch's userspace datapath; those raw results are in `sample_results_userspace_ovs/`. Absolute latencies depend on the machine. The write-ups with screenshots, charts and discussion are in `docs/` (D1 and D2).

### Known limits (state these honestly in the viva)

* Detection is per source IP over a sliding window. An attacker slower than ~3 new connections/s
  stays under the default threshold; lower `FW_SYN_THRESHOLD` / widen `FW_SYN_WINDOW_S` to tighten.
  Keep `SYN_THRESHOLD` below the server's slot count (20) or a flood can fill the server before the block lands.
* Spoofed source addresses, ARP spoofing and non-TCP floods are out of scope.
* A BLOCK drops all IP traffic from the host (not just port 5000) and the packet that triggers it.
* Controller state (counters, block table) is in memory; after a controller restart it starts clean.
* One switch only; the alert path to the logger is pre-installed (priority 65000) so alerts survive strict rules.

## 5. Rubric mapping

| Rubric item | Marks | Where |
|---|---|---|
| Problem understanding & architecture | 2 | sections 1 (diagram, policy, protocol); `config.py` |
| TCP socket implementation | 4 | `tcp_server.py` (threads, bounded slots, idle timeout, framing, errors), `tcp_client.py`, `logger_server.py` |
| Mininet + SDN implementation | 4 | `topology.py` (OVS, remote controller, fail-secure), `firewall_controller.py` (flow rules, priorities, timeouts) |
| Socket-SDN integration | 3 | socket connection attempts (SYNs) drive classification and blocking; controller reports over a socket that itself crosses the switch |
| Initial testing & demo | 2 | section 3 walkthrough, `tests/test_controller_logic.py`, `topology.py --test` |
| Complete application functionality | 4 | multiple clients (h1,h2,h4), allow/deny/block/recovery, central logger |
| Dynamic SDN functionality | 6 | rate based BLOCK, escalation from repeated DENY, hard-timeout recovery via FlowRemoved, monitoring counters |
| Challenging scenario / robustness | 4 | connection flood (bench), unauthorised access (S1), controller failure (S2), logger down (by design alerts are queued and sent by a background thread, so packet-in handling never waits on the logger; not part of the automated checks), `--bw/--delay/--loss` |
| Performance evaluation & comparison | 5 | `run_experiments.py bench`: none vs static vs dynamic, several attack rates, success rate/latency/time-to-block/attacker reach |
| Documentation, final demo & viva | 6 | this README; everyone should be able to explain section 1 and the limits |

## 6. Troubleshooting

| Symptom | Fix |
|---|---|
| `ryu-manager` fails with `ALREADY_HANDLED` / `get_script_args` | you are not using `~/ryu-venv` (Python 3.9, eventlet 0.30.2) |
| Switch connects but nothing is forwarded | controller not running (`fail_mode=secure`), or still on an old topology: `sudo mn -c` |
| `ModuleNotFoundError: mininet` or `ryu-manager: command not found` (run_experiments) | run it with the system Python and tell it where Ryu is: `export RYU_MANAGER=$HOME/ryu-venv/bin/ryu-manager; sudo -E /usr/bin/python3 run_experiments.py all` (do not run it with the venv's python) |
| `no controller listening on 127.0.0.1:6653` | start Ryu with `--ofp-tcp-listen-port 6653` |
| Results all `null` / many checks FAIL | an old controller or Mininet is still running (`sudo mn -c; sudo pkill -f ryu-manager`), or you are using an old `run_experiments.py` (folder names with spaces need the fixed version) |
| `rm: Permission denied` on `logs/` or `results/` | those files are created by `sudo`; use `sudo rm -rf logs results` |
| `Controller did not start` | see `results/<run>/controller.log` |
| TCP hangs but ping works with `--datapath user` | offloads: `topology.py`/`run_experiments.py` already disable them; do not start the network by other means |
| No events in the log | check `logs/logger_stdout.txt`; `h1 ping srv` first so the switch learns MACs |
| Stale state between runs | `sudo mn -c` and restart the controller |

## 7. Repository checklist (for the final demo)

`git init`, add everything except `logs/` (see `.gitignore`), commit `results/`, `evidence/` (the manual-run logs), `docs/` (D1 and D2 with screenshots) and keep this README as the documentation. Files superseded by this code and safe to delete from your earlier drafts:
`logging_server.py` (replaced by `logger_server.py`), the old `tcp_server.py`, `tcp_client.py`,
`firewall_controller.py` and the first `topology.py` (they used different ports/hosts than `config.py`).
