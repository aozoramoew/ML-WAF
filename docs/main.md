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
│  POST /analyze          ──► waf_engine.analyze()    │
│  ANY  /waf_check        ──► waf_engine.analyze()    │
│  POST /simulate/start   ──► simulator.start()        │
│  GET  /policy           ──► policy.get_policy()      │
│  GET  /model/info       ──► waf_engine.get_metrics() │
│  POST /ml/retrain       ──► BackgroundTask(ml.train) │
│  POST /ml/upload_labeled──► augment + save jsonl     │
│  WS   /ws               ──► ConnectionManager        │
│  GET  /                 ──► static/index.html (SPA)  │
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
| `request` | After each WAF decision | Slimmed request result dict |

### Dead Connection Cleanup

The broadcast loop automatically removes dead connections:

```python
async def broadcast(data):
    dead = []
    for ws in self.active:
        try:
            await ws.send_text(json.dumps(data, default=str))
        except Exception:
            dead.append(ws)
    for ws in dead:
        self.disconnect(ws)
```

---

## Startup / Lifecycle

On startup (via `@app.on_event('startup')`), the server:
1. Loads `config/policy.json` via `policy.load()`
2. Loads `models/waf_model.pkl` via `waf_engine.load_models()`
3. Starts a background task that pushes `stats_update` every 3 seconds

---

## Hot Retrain Endpoint

```python
@app.post('/ml/retrain')
async def retrain_model(background_tasks: BackgroundTasks):
    def run_training():
        subprocess.run([sys.executable, '-m', 'ml.train'], check=True, cwd=ROOT)
        waf_engine.load_models()   # hot-reload model after training
    background_tasks.add_task(run_training)
    return {'status': 'training_started'}
```

Training runs in a FastAPI `BackgroundTask` (a threadpool task, not a subprocess Popen). After `subprocess.run` completes, `waf_engine.load_models()` is called to hot-reload the new `waf_model.pkl` — no server restart needed.

---

## Upload Labeled Data Endpoint

`POST /ml/upload_labeled` accepts a file (`.json`, `.jsonl`, or `.csv`) of site-specific labeled requests:

1. Parses and validates: each row must have `method`, `url`, and `label` (0 or 1).
2. Augments via `dataset_generator.augment_labeled_samples()` (5 variants per sample by default).
3. Appends originals + variants to `data/custom_labeled.jsonl`.
4. Returns a summary — does **not** auto-retrain. Call `POST /ml/retrain` afterward.

---

## Key Endpoints Summary

### Analysis
- `POST /analyze` — Full WAF pipeline, returns detailed JSON
- `ANY /waf_check` — Status-code gate for nginx `auth_request` (200/403)
- `GET /stats` — Current aggregate statistics
- `POST /stats/reset` — Reset all counters

### ML
- `GET /model/info` — Metrics + feature importances from `models/metrics.json`
- `POST /ml/retrain` — Trigger background retraining (auto-reloads when done)
- `POST /ml/upload_labeled` — Upload labeled requests (JSON/JSONL/CSV) to augment training
- `POST /learn/toggle` — Pause/resume unsupervised Isolation Forest learning

### Simulation
- `POST /simulate/start` — Start background simulation
- `POST /simulate/stop` — Stop simulation
- `GET /simulate/scenarios` — List available scenario names + metadata

### Policy
- `GET /policy` — Current policy JSON
- `PUT /policy/mode` — Update operating mode (prevent/detect/monitor)
- `PUT /policy/thresholds` — Update ML score thresholds
- `POST /policy/rules` — Add single IP/path rule
- `POST /policy/rules/bulk` — Add multiple rules at once
- `POST /policy/rules/import` — Import rules from uploaded JSON file
- `DELETE /policy/rules` — Remove rule
- `POST /policy/reload` — Reload policy from disk

### Other
- `GET /modules/info` — List all WAF pipeline stages + their status
- `GET /integrations/{lang}` — Copy-paste middleware snippet (`nodejs`, `python`, `php`, `java`, `go`, `docker`, `kubernetes`, `nginx`)
- `POST /upload` — Test file upload through the file security module
- `GET /health` — Health check (used by Docker / Kubernetes liveness probes)
- `GET /` — Serves `static/index.html`
- `WS /ws` — WebSocket live event stream

---

## Pydantic Request Models

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
    rule_type: str   # ip_allowlist | ip_blocklist | path_allowlist | path_blocklist
    value:     str

class PolicyRuleBulk(BaseModel):
    rule_type: str
    values:    List[str]

class ThresholdUpdate(BaseModel):
    ml_block_score:           Optional[float] = None
    unsupervised_block_score: Optional[float] = None
    combined_block_score:     Optional[float] = None
```

---

## Interaction with Other Files

| Import | Usage |
|---|---|
| `app.waf_engine` | Core analysis pipeline, stats, model loading |
| `app.simulator` | Simulation lifecycle |
| `app.policy` | All policy CRUD operations |
| `app.api_discovery` | Endpoint stats included in `/stats` |
| `app.middleware.ips_engine` | Signature count for `/stats` |
| `app.middleware.crowd_wisdom` | Stats for `/stats` |
| `ml.unsupervised` | Baseline stats for `/model/info` and `/stats` |
| `ml.dataset_generator` | `augment_labeled_samples` for `/ml/upload_labeled` |

---

## open-appsec Equivalent

In open-appsec, this role is split between:
- **Management API** (Go): handles policy CRUD, user auth, dashboard serving
- **Nano-Agent** (C++): handles request analysis, embedded in the web server

This implementation merges both into a single FastAPI service — simpler for development, but would need to be split for production deployments at scale.
