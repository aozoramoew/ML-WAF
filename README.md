# ML-WAF — Machine Learning Web Application Firewall

> **A Python clone of the [open-appsec](https://www.openappsec.io/) architecture** — a real-time, ML-powered Web Application Firewall with a live analytics dashboard.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Architecture Diagram](#architecture-diagram)
- [Key Features](#key-features)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [How It Works](#how-it-works)
- [Datasets Used](#datasets-used)
- [Dashboard](#dashboard)
- [API Reference](#api-reference)
- [Integration Guide](#integration-guide)
- [File Documentation](#file-documentation)
- [Comparison to open-appsec](#comparison-to-open-appsec)

---

## Project Overview

ML-WAF is a **Python implementation** of the open-appsec WAF engine. It provides:

- **Dual ML engine**: supervised (Random Forest / Gradient Boosting) + unsupervised (Isolation Forest) working in concert — exactly mirroring open-appsec's preemptive architecture.
- **10-stage request pipeline**: every HTTP request passes through rule-based middleware modules before reaching the ML models.
- **Live dashboard**: a single-page application showing real-time blocked requests, attack distributions, ML model metrics, and policy controls.
- **Pluggable middleware**: modular detection stages for Rate Limiting, Anti-Bot, IPS, File Security, NoSQL, JWT, and more.
- **Simulation engine**: replay realistic attack traffic from 16 scenarios to demonstrate WAF behavior interactively.
- **Real CSIC 2010 data**: CSIC files are already in `data/` and are auto-detected at training time.

---

## Architecture Diagram

```
Incoming HTTP Request
        │
        ▼
┌─────────────────────────────────────────────────────────────────┐
│                    app/main.py  (FastAPI)                        │
│  POST /analyze  or  ANY /waf_check  ──────────────────────────► │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                  app/waf_engine.py  (Pipeline)                   │
│                                                                  │
│  Stage 0 ── Policy check         app/policy.py                  │
│  [Feature extraction runs here — used by all stages below]      │
│  Stage 1 ── Rate Limiter         middleware/rate_limiter.py      │
│  Stage 2 ── Anti-Bot             middleware/anti_bot.py          │
│  Stage 3 ── Crowd Wisdom         middleware/crowd_wisdom.py      │
│  Stage 4 ── IPS Engine           middleware/ips_engine.py        │
│  Stage 5 ── File Security        middleware/file_security.py     │
│  Stage 6 ── NoSQL Injection      middleware/nosql_injection.py   │
│  Stage 7 ── JWT Abuse            middleware/jwt_abuse.py         │
│  Stage 8 ── ML (Supervised)      ml/feature_extractor.py +       │
│                                  models/waf_model.pkl            │
│  Stage 9 ── ML (Unsupervised)    ml/unsupervised.py              │
│  Stage 10 ─ API Discovery        app/api_discovery.py (passive)  │
│                                                                  │
│  Policy thresholds govern ML block decisions (PUT /policy/thresholds) │
└───────────────────────────┬─────────────────────────────────────┘
                            │
              ┌─────────────┴────────────┐
              ▼                          ▼
        BLOCK (403)                ALLOW (pass-through)
              │                          │
              └──────────┬───────────────┘
                         ▼
              WebSocket broadcast to dashboard
              (static/index.html)
```

---

## Key Features

| Feature | Description |
|---|---|
| **Supervised ML** | Best of Random Forest / Gradient Boosting, trained on CSIC 2010 + 13,800 synthetic samples — realistic AUC ~0.997 |
| **Unsupervised ML** | Isolation Forest learns the *specific* traffic baseline of your app — catches zero-days |
| **Real-time dashboard** | WebSocket-powered live events, attack charts, block-rate gauge |
| **Attack simulation** | 16 scenarios (SQLi, XSS, SSRF, APT, DDoS, Full Dataset, etc.) |
| **Explainability** | Every blocked request shows *which* ML features triggered it |
| **Policy engine** | IP/path allow/blocklists, three modes (Prevent / Detect / Monitor), live threshold sliders |
| **Integration snippets** | Copy-paste middleware for Node.js, Python, PHP, Java, Go, Docker, Kubernetes, Nginx |
| **Hot retrain** | Trigger model retraining from the UI without server restart |
| **Upload labeled data** | Feed site-specific labeled requests to augment the model via `POST /ml/upload_labeled` |
| **Bulk policy rules** | Import IP/path rules in bulk via `POST /policy/rules/bulk` |

---

## Technology Stack

| Layer | Technology |
|---|---|
| API Server | FastAPI + Uvicorn |
| ML Models | scikit-learn (RandomForestClassifier, GradientBoostingClassifier, IsolationForest) |
| Serialization | joblib (supervised model), pickle (unsupervised baseline) |
| Real-time | WebSockets (native FastAPI) |
| Frontend | Vanilla HTML/CSS/JS + Chart.js |
| Fonts | Inter, JetBrains Mono (Google Fonts) |

---

## Project Structure

```
ML-WAF/
├── app/
│   ├── main.py              # FastAPI entry point — all HTTP routes + WebSocket
│   ├── waf_engine.py        # Core 10-stage ML pipeline orchestrator
│   ├── policy.py            # JSON-based policy engine (rules, modes, thresholds)
│   ├── simulator.py         # Attack traffic simulation engine (16 scenarios)
│   ├── api_discovery.py     # Passive endpoint mapping and anomaly detection
│   └── middleware/
│       ├── rate_limiter.py  # Token-bucket rate limiter
│       ├── anti_bot.py      # User-Agent bot fingerprinting
│       ├── crowd_wisdom.py  # IP reputation (CrowdSec-style)
│       ├── ips_engine.py    # CVE/exploit signature matching (Log4Shell, Text4Shell, etc.)
│       ├── file_security.py # Magic-byte file validation + EICAR detection
│       ├── nosql_injection.py  # MongoDB operator injection detection
│       └── jwt_abuse.py     # JWT tampering and alg:none detection
├── ml/
│   ├── feature_extractor.py # HTTP request → 74-feature numerical vector
│   ├── train.py             # Model training (RF vs GradientBoosting, selects best by AUC)
│   ├── dataset_generator.py # Synthetic dataset generator (13 categories, ~13,800 samples)
│   └── unsupervised.py      # Isolation Forest baseline learner (online, per-environment)
├── config/
│   └── policy.json          # Persisted policy configuration
├── data/
│   ├── cisc_normalTraffic_train.txt   # CSIC 2010 normal traffic (training)
│   ├── cisc_normalTraffic_test.txt    # CSIC 2010 normal traffic (test)
│   └── cisc_anomalousTraffic_test.txt # CSIC 2010 attack traffic
├── models/
│   ├── waf_model.pkl                  # Trained classifier (joblib)
│   ├── metrics.json                   # Training metrics (accuracy, F1, AUC, importances)
│   └── unsupervised_baseline.pkl      # Isolation Forest baseline (saved via dashboard)
├── static/
│   └── index.html           # Full-featured SPA dashboard
├── demo-app/                # Intentionally vulnerable Flask shop (Docker demo)
├── nginx/
│   └── nginx.conf           # Reverse-proxy config with auth_request /waf_check
├── docker-compose.yml       # 3-service stack: ml-waf (8000) + demo-app + nginx (8090)
└── requirements.txt
```

---

## Getting Started

### Prerequisites

- Python 3.9+
- pip

### Installation

```bash
git clone https://github.com/yourname/ML-WAF
cd ML-WAF
pip install -r requirements.txt
```

### Train the model

CSIC 2010 files are already in `data/` and are auto-detected:

```bash
# Auto-detects data/cisc_normalTraffic_*.txt + data/cisc_anomalousTraffic_test.txt
python -m ml.train
```

To specify files explicitly:

```bash
python -m ml.train \
  --csic-normal data/cisc_normalTraffic_train.txt \
  --csic-attack data/cisc_anomalousTraffic_test.txt
```

Expected output (with real CSIC data):
```
Best model: Gradient Boosting  (AUC=0.9968)
  Accuracy : 97.33%
  Precision: 98.78%
  Recall   : 92.15%
  F1-Score : 95.35%
```

### Run the server

```bash
# Using the project venv:
ml-waf\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000

# Or system Python if dependencies are installed:
python -m uvicorn app.main:app --reload --port 8000
```

Open **http://localhost:8000** in your browser.

### Run with Docker (full demo stack)

```bash
docker compose up -d --build

# Normal request — passes through to demo-app (200 OK)
curl http://localhost:8090/products?id=1

# SQLi attack — blocked by ML-WAF, nginx returns 403
curl "http://localhost:8090/login?user=admin&pass=' OR '1'='1"

# Live dashboard
open http://localhost:8090/waf-dashboard/
```

---

## How It Works

### Request Evaluation Flow

1. A request arrives at `POST /analyze` or `ANY /waf_check`.
2. `waf_engine.analyze()` runs the policy check (Stage 0), then extracts the 74-feature vector.
3. Stages 1–7 are rule-based (rate limiter, bot detection, IPS signatures, etc.). Any block short-circuits the pipeline.
4. Stage 8: the trained classifier scores the feature vector → probability 0–1. Block if `ml_score >= ml_block_score` (from policy).
5. Stage 9: the Isolation Forest scores anomaly vs. learned baseline. If anomalous, the fused score `0.7×ml + 0.3×anomaly` is checked against `combined_block_score`.
6. Stage 10: API Discovery passively records the endpoint. Allowed requests teach the Isolation Forest baseline.
7. The result (including all feature values) is broadcast to WebSocket clients (the dashboard).

### ML Feature Engineering

The 74-feature vector captures:
- **Structural**: URL length, path depth, query parameter count, body length
- **Entropy**: Shannon entropy of URL, body, query (high entropy = encoded/obfuscated payload)
- **SQL Injection**: keyword count, UNION/SELECT/DROP presence, tautology pattern, hex encoding
- **XSS**: pattern count, script tag, event handler, JavaScript URI, template injection
- **Path Traversal**: `../` sequences, encoded traversal, `/etc/passwd`, null byte
- **Command Injection**: shell metacharacters (`;`, `|`, backtick, `$(`)
- **NoSQL**: MongoDB operator count (`$where`, `$ne`, `$regex`), JSON operator patterns
- **SSRF**: internal IP, cloud metadata URL, non-HTTP protocols
- **XXE**: XML DOCTYPE/ENTITY declarations
- **JWT Abuse**: alg:none detection, missing signature segment
- **Behavioral**: bot User-Agent, header presence flags, parameter pollution

---

## Datasets Used

| Dataset | Source | Size | Attack Types |
|---|---|---|---|
| CSIC 2010 (normal) | ISTE/CSIC — in `data/` | ~78,000 requests | — |
| CSIC 2010 (attack) | ISTE/CSIC — in `data/` | ~27,000 requests | SQLi, XSS, path traversal |
| Synthetic (CSIC-style) | Generated | 1,500 SQLi + 1,500 XSS + 800 PT + 600 CMDi | Classic web attacks |
| Synthetic (Juice Shop) | Generated | 600 SQLi + 600 XSS + 500 IDOR | OWASP CTF patterns |
| Synthetic (HTTPParams) | Generated | 500 | Parameter pollution |
| Synthetic (modern) | Generated | 400 NoSQL + 300 JWT + 300 SSRF + 200 XXE | Modern attack types |
| Custom labeled | Via `POST /ml/upload_labeled` | Variable | Site-specific |

---

## Dashboard

The dashboard (`static/index.html`) is a pure HTML/CSS/JS SPA served directly by FastAPI. It requires no build step.

**Tabs:**
- **Overview** — Live counters, traffic time-series chart, block-rate gauge, attack-type donut
- **Live Events** — Real-time table with filterable/searchable events; click any row for full pipeline explanation + feature values
- **ML Models** — Model metrics, feature importances, retrain button, upload labeled data, live request analyzer
- **Modules** — Toggle individual WAF stages on/off
- **API Discovery** — Auto-mapped endpoint inventory
- **Policy Manager** — Mode switching, threshold sliders, IP/path rules (single + bulk)
- **Simulate** — Launch 16 different attack scenarios
- **Integration** — Copy-paste middleware snippets (Node.js, Python, PHP, Java, Go, Nginx, Docker, Kubernetes)

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Serve dashboard SPA |
| `POST` | `/analyze` | Analyze a single request snapshot — returns full JSON |
| `ANY` | `/waf_check` | nginx `auth_request` gate — returns 200 (allow) or 403 (block) |
| `GET` | `/stats` | Real-time WAF statistics |
| `POST` | `/stats/reset` | Reset counters |
| `GET` | `/model/info` | Model metrics + feature importances |
| `POST` | `/ml/retrain` | Trigger background retraining |
| `POST` | `/ml/upload_labeled` | Upload labeled requests (JSON/CSV/JSONL) to augment training data |
| `GET` | `/modules/info` | List all WAF modules |
| `POST` | `/simulate/start` | Start a traffic simulation |
| `POST` | `/simulate/stop` | Stop the simulation |
| `GET` | `/simulate/scenarios` | List available scenarios |
| `GET` | `/policy` | Get current policy |
| `PUT` | `/policy/mode` | Set mode (prevent/detect/monitor) |
| `POST` | `/policy/rules` | Add single IP/path rule |
| `POST` | `/policy/rules/bulk` | Add multiple rules at once |
| `POST` | `/policy/rules/import` | Import rules from JSON file |
| `DELETE` | `/policy/rules` | Remove rule |
| `PUT` | `/policy/thresholds` | Update ML score thresholds |
| `POST` | `/policy/reload` | Reload policy from disk |
| `POST` | `/learn/toggle` | Pause/resume unsupervised learning |
| `GET` | `/integrations/{lang}` | Get integration snippet |
| `GET` | `/health` | Health check |
| `WS` | `/ws` | WebSocket live event stream |

---

## Integration Guide

For detailed instructions on placing ML-WAF in front of a real web application (Reverse Proxy via `/waf_check`, Application Middleware via `/analyze`, or Kubernetes sidecar), read the [Integration Guide](docs/integration_guide.md).

The verified demo (`docker compose up -d --build`) uses nginx `auth_request /waf_check` on port 8090 in front of an intentionally vulnerable Flask shop.

---

## File Documentation

Each source file has a companion markdown document:

| File | Documentation |
|---|---|
| `app/main.py` | [main.md](docs/main.md) |
| `app/waf_engine.py` | [waf_engine.md](docs/waf_engine.md) |
| `app/policy.py` | [policy.md](docs/policy.md) |
| `app/simulator.py` | [simulator.md](docs/simulator.md) |
| `app/api_discovery.py` | [api_discovery.md](docs/api_discovery.md) |
| `app/middleware/rate_limiter.py` | [rate_limiter.md](docs/rate_limiter.md) |
| `app/middleware/anti_bot.py` | [anti_bot.md](docs/anti_bot.md) |
| `app/middleware/ips_engine.py` | [ips_engine.md](docs/ips_engine.md) |
| `app/middleware/nosql_injection.py` | [nosql_injection.md](docs/nosql_injection.md) |
| `app/middleware/jwt_abuse.py` | [jwt_abuse.md](docs/jwt_abuse.md) |
| `ml/feature_extractor.py` | [feature_extractor.md](docs/feature_extractor.md) |
| `ml/train.py` | [train.md](docs/train.md) |
| `ml/dataset_generator.py` | [dataset_generator.md](docs/dataset_generator.md) |
| `ml/unsupervised.py` | [unsupervised.md](docs/unsupervised.md) |

---

## Comparison to open-appsec

| Concept | open-appsec | This project |
|---|---|---|
| Language | C++ (engine) + Go (management) | Python |
| Feature engineering | Proprietary 100+ features | 74 engineered features |
| Supervised model | Global crowd-sourced training | Local training on CSIC 2010 + synthetic |
| Best model selection | Internal | RF vs. GradientBoosting, chosen by AUC |
| Policy engine | YAML/REST | JSON/REST |
| Modes | Prevent / Detect / Transparent | Prevent / Detect / Monitor |
| Deployment | eBPF / K8s sidecar | Reverse-proxy / middleware / Docker Compose |
| Crowd intelligence | CrowdSec integration | Simulated crowd wisdom module |
| API discovery | Yes | Yes (passive endpoint mapper) |
| Real-time learning | Yes | Yes (Isolation Forest online learning) |
| IPS signatures | 2,800+ CVEs (Premium) | ~18 hand-picked CVEs including Log4Shell, Text4Shell |
| File security | Premium feature | Implemented (magic bytes, EICAR, dangerous extensions) |
| ML metrics (realistic) | Not published | AUC 0.997, Accuracy 97.3% on CSIC 2010 |
