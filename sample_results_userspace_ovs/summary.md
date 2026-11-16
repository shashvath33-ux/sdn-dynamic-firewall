| mode | attack conn/s | legit success (all) | legit success during attack | legit avg latency during attack (ms) | time to block (s) | attacker conns reached server |
|---|---|---|---|---|---|---|
| none | 0 | 1.0 | - | 7.56 | - | None |
| static | 0 | 1.0 | - | 9.32 | - | None |
| static | 5 | 0.85 | 0.679 | 9.5 | - | 75 |
| static | 20 | 0.4667 | 0.107 | 12.1 | - | 300 |
| static | 50 | 0.4 | 0.0 | None | - | 750 |
| dynamic | 0 | 1.0 | - | 7.16 | - | None |
| dynamic | 5 | 1.0 | 1.0 | 8.6 | 1.806 | 18 |
| dynamic | 20 | 1.0 | 1.0 | 8.5 | 0.453 | 18 |
| dynamic | 50 | 1.0 | 1.0 | 8.0 | 0.182 | 18 |
