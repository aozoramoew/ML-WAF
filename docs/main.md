# `main.py` — FastAPI Application Entry Point

## Overview

`main.py` is the **API server** — the entry point for the entire ML-WAF system. It exposes all REST endpoints, manages the WebSocket connection pool, and orchestrates the interaction between the WAF engine, policy manager, simulator, and dashboard.

---

## Role in the System

```
Browser / Client
    │
    │   HTTP REST         WebSocket
    ▼                        ▼
┌─────────────────────────────────────────────────────┐
│                  app/main.py (FastAPI)               │
│                                                      │
│  /analyze         ─────► waf_engine.analyze()        │
│  /simulate/start  ─────► simulator.start()           │
│  /policy          ─────► policy.get_policy()         │
│  /model/info      ─────► waf_engine.get_metrics()    │
│  /modules/info    ─────► waf_engine.get_module_info()|
│  /ml/retrain      ─────► subprocess ml.train         │
│  /ws              ─────► ConnectionManager (WS pool) │
│  /                ─────► static/index.html (SPA)     │
└─────────────────────────────────────────────────────┘
```

---

## WebSocket Architecture

The WebSocket endpoint (`/ws`) powers the real-time dashboard. Every time the WAF engine makes a decision, the result is broadcast to all connected clients:

```python
class ConnectionManager:
    active: List[WebSocket] = []

    async def connect(ws): ...
    def disconnect(ws): ...
    async def broadcast(data: dict): ...
```

### Message Types

| `type` | Trigger | Payload |
|---|---|---|
| `init` | On WebSocket connect | Current stats + policy |
| `stats_update` | Every 3s via background task | Aggregate counters |
| `request` | After each WAF decision | Full request result dict |

### Dead Connection Cleanup

The broadcast loop automatically removes dead connections:

```python
async def broadcast(data):
    dead = []
    for ws in self.active:
        try:
            await ws.send_text(json.dumps(data))
        except Exception:
            dead.append(ws)   # broken pipe / closed tab
    for ws in dead:
        self.disconnect(ws)
```

---

## Startup / Lifecycle

```python
@app.on_event('startup')
async def startup_event():
    policy.load()              # Load config/policy.json
    waf_engine.load_models()   # Load models/waf_model.pkl
    asyncio.create_task(       # Background stats broadcast
        broadcast_stats_loop()
    )
```

The **background stats loop** runs every 3 seconds and pushes a `stats_update` message to all connected dashboard clients, keeping the counters and charts live even when no requests are flowing.

---

## Hot Retrain Endpoint

```python
@app.post('/ml/retrain')
async def retrain():
    # Run training in a subprocess (non-blocking)
    subprocess.Popen(
        [sys.executable, '-m', 'ml.train'],
        cwd=ROOT
    )
    return {'status': 'training_started'}
```

After training completes, the new `waf_model.pkl` is automatically picked up by `waf_engine.load_models()` — called periodically or triggered manually. No server restart needed.

---

## Key Endpoints Summary

### Analysis
- `POST /analyze` — Analyze one request dict, returns full decision
- `GET /stats` — Current aggregate statistics
- `POST /stats/reset` — Reset all counters

### ML
- `GET /model/info` — Metrics + feature importances
- `POST /ml/retrain` — Trigger background retraining
- `POST /learn/toggle` — Pause/resume unsupervised learning
- `POST /learn/save` — Persist Isolation Forest baseline

### Simulation
- `POST /simulate/start` — Start background simulation
- `POST /simulate/stop` — Stop simulation
- `GET /simulate/scenarios` — List available scenario names + metadata

### Policy
- `GET /policy` — Current policy JSON
- `PUT /policy/mode` — Update operating mode
- `PUT /policy/thresholds` — Update ML score thresholds
- `POST /policy/rules` — Add IP/path rule
- `DELETE /policy/rules` — Remove rule
- `POST /policy/reload` — Reload from disk

### Modules
- `GET /modules/info` — List all WAF stages + their status

### API Discovery
- See `app/api_discovery.py` — stats are included in `/stats`

### Integrations
- `GET /integrations/{lang}` — Returns copy-paste middleware snippet for `nodejs`, `python`, `php`, `java`, `go`, `docker`, `kubernetes`

### Dashboard
- `GET /` — Serves `static/index.html`
- `WS /ws` — WebSocket live event stream

---

## Pydantic Request Models

FastAPI uses Pydantic for request validation. Key schemas:

```python
class RequestSnapshot(BaseModel):
    method:  str   = 'GET'
    url:     str   = '/'
    headers: dict  = {}
    body:    str   = ''
    ip:      str   = '127.0.0.1'

class SimulateRequest(BaseModel):
    scenario:   str   = 'mixed'
    n_requests: int   = 60
    delay:      float = 0.25

class PolicyRule(BaseModel):
    rule_type: str  # ip_allowlist | ip_blocklist | path_allowlist | path_blocklist
    value:     str
```

---

## Interaction with Other Files

| Import | Usage |
|---|---|
| `app.waf_engine` | Core analysis, stats, model loading |
| `app.simulator` | Simulation lifecycle |
| `app.policy` | All policy CRUD operations |
| `app.api_discovery` | Endpoint statistics |
| `app.middleware.ips_engine` | Module info for `/modules/info` |
| `app.middleware.crowd_wisdom` | Module info for `/modules/info` |
| `ml.unsupervised` | Learning control |

---

## open-appsec Equivalent

In open-appsec, this role is split between:
- **Management API** (Go): handles policy CRUD, user auth, dashboard serving
- **Nano-Agent** (C++): handles request analysis, embedded in the web server

This implementation merges both into a single FastAPI service — simpler for development, but would need to be split for production deployments at scale.
