# `simulator.py` — Attack Traffic Simulation Engine

## Overview

`simulator.py` drives the **Traffic Simulation** feature in the dashboard. It runs in the background as an async task, generating HTTP request objects from pre-defined scenario payloads (or live from the dataset generator) and routing them through `waf_engine.analyze()` — exactly as real requests would flow.

This allows you to **demonstrate the WAF in action** without needing an actual attacking client.

---

## Architecture

```
User clicks "▶ Start Simulation" in dashboard
    │
    ▼
POST /simulate/start {scenario, n_requests, delay}
    │
    ▼
simulator.start(scenario, analyze_fn, broadcast_fn, n, delay)
    │
    └──► asyncio.create_task(run_simulation(...))
                │
                ├── for each request:
                │       method, url, headers, body = random.choice(payloads)
                │       result = await analyze_fn({method, url, headers, body, ip})
                │       await broadcast_fn({'type': 'request', 'data': result})
                │       await asyncio.sleep(delay)
                │
                └── notify broadcast_fn when done
```

The `analyze_fn` and `broadcast_fn` are dependency-injected from `main.py`, keeping the simulator decoupled from FastAPI specifics.

---

## Scenarios

| Scenario | Description | Mix |
|---|---|---|
| `normal` | Benign e-commerce traffic | 100% normal |
| `sqli` | SQL injection attacks | 100% SQLi |
| `xss` | Cross-site scripting | 100% XSS |
| `path_traversal` | Directory traversal | 100% path traversal |
| `log4shell` | Log4j RCE exploit | 100% Log4Shell headers |
| `bot_scan` | Automated scanner fingerprints | 100% known bots |
| `nosql` | MongoDB operator injection | 100% NoSQL |
| `jwt_abuse` | JWT tampering | 100% JWT attacks |
| `ssrf` | Server-side request forgery | 100% SSRF |
| `xxe` | XML external entity | 100% XXE |
| `idor` | Insecure direct object reference | 100% IDOR |
| `juice_shop` | OWASP Juice Shop payloads | Mixed attack types |
| `mixed` | Realistic mixed traffic | 60% normal + 40% random attacks |
| `apt` | Advanced persistent threat | Multi-stage attack chain |
| `ddos` | Flood / rate limit test | High-volume normal requests |
| `full_dataset` | Random sample from generated dataset | Truly random mix |

---

## `full_dataset` Scenario

The `full_dataset` scenario is unique — instead of using hardcoded payloads, it:

1. Calls `dataset_generator.generate_dataset()` to produce the full 13,100-sample DataFrame
2. Takes a random sample of `n_requests` rows (default 100)
3. Routes each row through `waf_engine.analyze()`

This produces the most realistic simulation because the requests are drawn from the same distribution the model was trained on — and yet the model should still catch them because it learned to generalise, not memorise.

---

## Payload Realism

Payloads include realistic metadata:
- **Random source IPs** from a diverse pool (simulating global attackers)
- **Realistic User-Agents** for normal traffic (Chrome, Firefox, Safari)
- **Attack-appropriate User-Agents** for bot scenarios (sqlmap, nikto, etc.)
- **Correct Content-Type headers** for POST requests with JSON or form bodies

```python
_IPS = [
    '203.0.113.42', '45.33.32.156', '198.51.100.10',
    '91.195.240.126', '5.188.206.26', '185.220.101.3',
    ...
]
```

---

## State Management

The simulator uses a global `_running` flag for lifecycle control:

```python
_running = False

def start(scenario, analyze_fn, broadcast_fn, n_requests, delay):
    global _running
    _running = True
    asyncio.create_task(run_simulation(...))

def stop():
    global _running
    _running = False
```

The running loop checks `_running` before each request, allowing `POST /simulate/stop` to cleanly interrupt mid-simulation.

---

## Interaction with Other Files

| File | Relationship |
|---|---|
| `app/main.py` | Calls `simulator.start()` / `simulator.stop()` / `simulator.get_scenarios()` |
| `app/waf_engine.py` | `analyze_fn` parameter is `waf_engine.analyze` |
| `ml/dataset_generator.py` | Imported for `generate_dataset()` in `full_dataset` scenario |
| `static/index.html` | Dashboard calls `GET /simulate/scenarios` to populate the scenario selector |

---

## open-appsec Equivalent

open-appsec provides a **traffic replay tool** in its CI/CD integration that can replay recorded PCAP files through the WAF engine for regression testing. This simulator serves a similar purpose but generates traffic algorithmically rather than replaying captures. The advantage is that no real attack traffic needs to be recorded — everything runs from the included payloads.
