# Part 1 - Virtual Network & Security Logger
(See README.md for the complete project. This file documents the alert contract between
the controller and the logger.)

## Alert contract (controller -> logger)
TCP connect to `10.0.0.100:9999`, send **one JSON object per line**, read one JSON reply line.
```json
{"event":"BLOCK","src_ip":"10.0.0.3","dst_ip":"10.0.0.10","dst_port":5000,
 "proto":"TCP","reason":"rate limit exceeded","timeout":30,
 "ts":1760000000.123,"first_seen_ts":1760000000.020}
```
* `event` (required): `ALLOW | DENY | BLOCK | UNBLOCK | ALERT | INFO`
* optional: `src_ip dst_ip dst_port proto reason timeout ts first_seen_ts` (+ any extra fields are kept)
* `ts` = `time.time()` when the controller made the decision -> logger computes delivery latency
* `first_seen_ts` on BLOCK = first suspicious packet -> `analyze_log.py` computes blocking response time
* `UNBLOCK` is sent when the block timeout expires (recovery metric)
* Reply: `{"status":"ok","id":N}` or `{"status":"error","error":"..."}`
* Commands: `{"cmd":"ping"}`, `{"cmd":"stats"}`

Alert path: `topology.py` pre-installs priority-65000 flows for root-ns <-> logger only,
so alerts keep flowing even when firewall rules are strict.

## Standalone tests (no controller needed)
1. `sudo python3 topology.py --test` -> alert-path and logger checks PASS.
2. `python3 logger_server.py --port 19999` then `python3 send_test_alert.py --port 19999 --host 127.0.0.1 --count 50`.
3. `python3 send_test_alert.py --raw "{bad"` returns an error, `--stats` shows counters.
