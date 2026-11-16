| mode | attack conn/s | legit success (all) | legit success during attack | legit avg latency during attack (ms) | time to block (s) | attacker conns reached server |
|---|---|---|---|---|---|---|
| none | 0 | 1.0 | - | 11.69 | - | None |
| static | 0 | 1.0 | - | 10.5 | - | None |
| static | 5 | 0.8302 | 0.654 | 11.3 | - | 75 |
| static | 20 | 0.4833 | 0.107 | 12.2 | - | 300 |
| static | 50 | 0.3793 | 0.0 | None | - | 750 |
| dynamic | 0 | 1.0 | - | 10.65 | - | None |
| dynamic | 5 | 1.0 | 1.0 | 10.6 | 1.806 | 17 |
| dynamic | 20 | 1.0 | 1.0 | 11.3 | 0.46 | 18 |
| dynamic | 50 | 1.0 | 1.0 | 9.7 | 0.194 | 18 |
