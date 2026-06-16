# `simulator.py` — Attack Traffic Simulation Engine

## Overview

`simulator.py` drives the **Traffic Simulation** feature in the dashboard. It runs as an async background task, generating HTTP request objects from pre-defined scenario payloads and routing them through `waf_engine.analyze()` — exactly as real requests would flow. This allows you to demonstrate the WAF in action without needing an actual attacking client.

---

## Architecture

```
User clicks "▶ Start Simulation" in dashboard
    │
    ▼
POST /simulate/start {scenario, n_requests, delay}
    │
    ▼
simulator.start(scenario, analyze_fn, broadcast_fn, n_requests, delay)
    │
    └──► asyncio.create_task(run_simulation(...))
                │
                ├─ For each request (up to n_requests):
                │     method, url, headers, body = random.choice(scenario_payloads)
                │     ip = random.choice(_IPS)
                │     result = await analyze_fn({method, url, headers, body, ip})
                │     await broadcast_fn({'type': 'request', 'data': _slim(result)})
                │     await asyncio.sleep(delay)
                │
                └─ Sets _running = False when done (or on stop())
```

`analyze_fn` and `broadcast_fn` are injected from `main.py`, keeping the simulator decoupled from FastAPI.

---

## Scenarios

| Scenario | Description | Mix |
|---|---|---|
| `normal` | Benign e-commerce API traffic | 100% normal |
| `sqli` | SQL injection attacks | 100% SQLi |
| `xss` | Cross-site scripting | 100% XSS |
| `path_traversal` | Directory traversal | 100% path traversal |
| `log4shell` | Log4j RCE (CVE-2021-44228) via HTTP headers | 100% Log4Shell |
| `bot_scan` | Automated scanner fingerprints (sqlmap, nikto, ffuf) | 100% bots |
| `nosql` | MongoDB operator injection | 100% NoSQL |
| `jwt_abuse` | JWT alg:none + tampered tokens | 100% JWT attacks |
| `ssrf` | Server-side request forgery | 100% SSRF |
| `xxe` | XML external entity injection | 100% XXE |
| `idor` | Insecure direct object reference | 100% IDOR |
| `juice_shop` | OWASP Juice Shop payloads (mixed) | Mixed attack types |
| `mixed` | Realistic multi-vector traffic | Normal + all attack types |
| `apt` | APT-style multi-stage attack chain | NoSQL + JWT + SSRF + XXE + IDOR + Juice Shop |
| `ddos` | Flood / rate-limit stress test | High-volume normal requests |
| `full_dataset` | Dynamic sample from generated dataset | Truly random mix |

---

## `full_dataset` Scenario

This scenario is unique — instead of using hardcoded payloads, it:

1. Calls `dataset_generator.generate_dataset()` to produce the full ~13,800-sample synthetic dataset
2. Takes a random sample of `n_requests` rows
3. Routes each through `waf_engine.analyze()`

This produces the most realistic simulation because the requests come from the same distribution the model was trained on — spanning all 13 attack categories plus normal traffic.

---

## Source IP Pool

The simulator uses a fixed pool of IPs that covers both private ranges (for rate-limiter testing) and a known-bad public range:

```python
_IPS = (
    ['10.0.0.{}'.format(i) for i in range(1, 100)] +
    ['192.168.1.{}'.format(i) for i in range(1, 50)] +
    ['185.220.101.{}'.format(i) for i in range(1, 20)]  # known bad range
)
```

---

## Result Slimming

`_slim(result)` reduces the full `waf_engine.analyze()` response to only what the dashboard WebSocket needs, keeping message size small:

```python
{
    'id', 'timestamp', 'method', 'url' (80 chars max), 'ip',
    'decision', 'confidence', 'attack_type', 'blocked_by',
    'ml_score', 'unsupervised_score',
    'features': {10 key features for sparkline display}
}
```

---

## State Management

```python
_running: bool = False
_task: Optional[asyncio.Task] = None

def start(...):   _running = True;  _task = asyncio.create_task(run_simulation(...))
def stop():       _running = False; _task.cancel()
def is_running(): return _running
```

The `run_simulation` loop checks `_running` before each request — `POST /simulate/stop` sets it to False, cleanly interrupting mid-simulation without crashing.

---

## Interaction with Other Files

| File | Relationship |
|---|---|
| `app/main.py` | Calls `start()`, `stop()`, `get_scenarios()`, `is_running()` |
| `app/waf_engine.py` | `analyze_fn` is `waf_engine.analyze` — all simulated requests flow through the full pipeline |
| `ml/dataset_generator.py` | Imported for `generate_dataset()` in the `full_dataset` scenario |
| `static/index.html` | Calls `GET /simulate/scenarios` to populate the scenario selector; `POST /simulate/start` and `POST /simulate/stop` for lifecycle control |

---

## open-appsec Equivalent

open-appsec provides a **traffic replay tool** in its CI/CD integration that replays recorded PCAP files through the WAF engine for regression testing. This simulator serves a similar purpose but generates traffic algorithmically. The advantage is that no real attack traffic needs to be captured — everything runs from the included scenario payloads and the synthetic dataset generator.
