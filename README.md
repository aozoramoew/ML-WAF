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

- **Dual ML engine**: supervised (Random Forest) + unsupervised (Isolation Forest) working in concert — exactly mirroring open-appsec's preemptive architecture.
- **10-stage request pipeline**: every HTTP request passes through rule-based middleware modules before reaching the ML models.
- **Live dashboard**: a single-page application showing real-time blocked requests, attack distributions, ML model metrics, and policy controls.
- **Pluggable middleware**: modular detection stages for Rate Limiting, Anti-Bot, IPS, File Security, NoSQL, JWT, and more.
- **Simulation engine**: replay realistic attack traffic from mixed datasets to demonstrate WAF behavior interactively.

---

## Architecture Diagram

```
Incoming HTTP Request
        │
        ▼
┌─────────────────────────────────────────────────────────────────┐
│                    app/main.py  (FastAPI)                        │
│  POST /analyze  ──────────────────────────────────────────────► │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                  app/waf_engine.py  (Pipeline)                   │
│                                                                  │
│  Stage 1 ── Rate Limiter        middleware/rate_limiter.py       │
│  Stage 2 ── Anti-Bot            middleware/anti_bot.py           │
│  Stage 3 ── Crowd Wisdom        middleware/crowd_wisdom.py       │
│  Stage 4 ── IPS Engine          middleware/ips_engine.py         │
│  Stage 5 ── File Security       middleware/file_security.py      │
│  Stage 6 ── NoSQL Injection     middleware/nosql_injection.py    │
│  Stage 7 ── JWT Abuse           middleware/jwt_abuse.py          │
│  Stage 8 ── ML (Supervised)     ml/feature_extractor.py +        │
│                                 models/waf_model.pkl             │
│  Stage 9 ── ML (Unsupervised)   ml/unsupervised.py               │
│  Stage 10 ─ API Discovery       app/api_discovery.py (passive)   │
│                                                                  │
│  Policy check runs on EVERY stage ── app/policy.py              │
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
| 🤖 **Supervised ML** | Random Forest trained on 13,800+ samples from CSIC 2010, OWASP Juice Shop, HTTPParams, NoSQL/JWT/SSRF/XXE/IDOR datasets |
| 🧠 **Unsupervised ML** | Isolation Forest learns the *specific* traffic baseline of your app — catches zero-days |
| ⚡ **Real-time dashboard** | WebSocket-powered live events, attack charts, block-rate gauge |
| 🎯 **Attack simulation** | 14 scenarios (SQLi, XSS, SSRF, APT, DDoS, Full Dataset) |
| 🔍 **Explainability** | Every blocked request shows *which* ML features triggered it |
| 📋 **Policy engine** | IP/path allowlists and blocklists, three modes (Prevent / Detect / Monitor) |
| 🔌 **Integration snippets** | Copy-paste middleware for Node.js, Python, PHP, Java, Go, Docker, K8s |
| 🔄 **Hot retrain** | Trigger model retraining from the UI without server restart |

---

## Technology Stack

| Layer | Technology |
|---|---|
| API Server | FastAPI + Uvicorn |
| ML Models | scikit-learn (RandomForestClassifier, IsolationForest) |
| Serialization | joblib |
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
│   ├── simulator.py         # Attack traffic simulation engine
│   ├── api_discovery.py     # Passive endpoint mapping and anomaly detection
│   └── middleware/
│       ├── rate_limiter.py  # Token-bucket rate limiter
│       ├── anti_bot.py      # User-Agent bot fingerprinting
│       ├── crowd_wisdom.py  # IP reputation (CrowdSec-style)
│       ├── ips_engine.py    # CVE/exploit signature matching (Log4Shell, etc.)
│       ├── file_security.py # Magic-byte file validation + EICAR detection
│       ├── nosql_injection.py  # MongoDB operator injection detection
│       └── jwt_abuse.py     # JWT tampering and alg:none detection
├── ml/
│   ├── feature_extractor.py # HTTP request → 75-feature numerical vector
│   ├── train.py             # Model training pipeline (RF + metrics export)
│   ├── dataset_generator.py # Synthetic attack dataset generator (13 categories)
│   └── unsupervised.py      # Isolation Forest baseline learner
├── config/
│   └── policy.json          # Persisted policy configuration
├── data/                    # Place CSIC 2010 dataset files here
├── models/
│   ├── waf_model.pkl        # Trained Random Forest model (joblib)
│   ├── metrics.json         # Training metrics (accuracy, F1, AUC, importances)
│   └── unsupervised_baseline.pkl  # Isolation Forest baseline (saved periodically, created on first save)
├── static/
│   └── index.html           # Full-featured SPA dashboard
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

```bash
# With synthetic data only (auto-generated):
python -m ml.train

# With real CSIC 2010 dataset (download separately):
python -m ml.train \
  --csic-normal data/normalTrafficTraining.txt \
  --csic-attack data/anomalousTrafficTest.txt
```

### Run the server

```bash
python -m uvicorn app.main:app --reload --port 8000
```

Open **http://localhost:8000** in your browser.

---

## How It Works

### Request Evaluation Flow

1. A request arrives at `POST /analyze` or is injected by the simulator.
2. `waf_engine.analyze()` runs the request through **10 sequential stages**.
3. Each stage returns `{block: bool, reason: str}`. If any stage blocks, the pipeline short-circuits.
4. If the request reaches Stage 8, `feature_extractor.extract_features()` converts the raw request into a 75-dimensional numerical vector.
5. The trained Random Forest scores the vector → confidence score (0–1).
6. Stage 9 asks the Isolation Forest whether the request is anomalous relative to the learned baseline.
7. The final decision combines both scores via a weighted formula from `policy.get_thresholds()`.
8. The result is broadcast to all connected WebSocket clients (the dashboard).

### ML Feature Engineering

The feature vector captures:
- **Structural features**: URL length, parameter count, body length, header count
- **Entropy features**: Shannon entropy of URL, body (high entropy = encoded/obfuscated payload)
- **Attack-pattern counts**: occurrences of SQL keywords, XSS patterns, path traversal sequences, etc.
- **Behavioral features**: known bot UA strings, suspicious header combinations
- **Encoding features**: presence of base64, URL-encoding, hex sequences

---

## Datasets Used

| Dataset | Source | Size | Attack Types |
|---|---|---|---|
| CSIC 2010 | ISTE/CSIC | ~36,000 | SQLi, XSS, path traversal |
| OWASP Juice Shop | Synthetic from payloads | 2,800 | Auth bypass, JWT, SSRF, XSS |
| HTTPParams Fuzzing | Synthetic | 2,000 | Param pollution, boundary cases |
| NoSQL Injection | Synthetic | 1,200 | MongoDB operators |
| JWT Abuse | Synthetic | 800 | alg:none, claim tampering |
| SSRF | Synthetic | 600 | Cloud metadata, SSRF |
| XXE | Synthetic | 400 | XML entity injection |
| IDOR | Synthetic | 600 | Object reference manipulation |

---

## Dashboard

The dashboard (`static/index.html`) is a pure HTML/CSS/JS SPA served directly by FastAPI. It requires no build step.

**Tabs:**
- **Overview** — Live counters, traffic time-series chart, block-rate gauge, attack-type donut
- **Live Events** — Real-time table with filterable/searchable events; click any row for full pipeline explanation
- **ML Models** — Model metrics, feature importances, retrain button, live request analyzer
- **Modules** — Toggle individual WAF stages on/off
- **API Discovery** — Auto-mapped endpoint inventory
- **Policy Manager** — Mode switching, threshold sliders, IP/path rules
- **Simulate** — Launch 14 different attack scenarios
- **Integration** — Copy-paste middleware snippets

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Serve dashboard SPA |
| `POST` | `/analyze` | Analyze a single request snapshot |
| `GET` | `/stats` | Real-time WAF statistics |
| `POST` | `/stats/reset` | Reset counters |
| `GET` | `/model/info` | Model metrics + feature importances |
| `POST` | `/ml/retrain` | Trigger background retraining |
| `GET` | `/modules/info` | List all WAF modules |
| `POST` | `/simulate/start` | Start a traffic simulation |
| `POST` | `/simulate/stop` | Stop the simulation |
| `GET` | `/simulate/scenarios` | List available scenarios |
| `GET` | `/policy` | Get current policy |
| `PUT` | `/policy/mode` | Set mode (prevent/detect/monitor) |
| `POST` | `/policy/rules` | Add IP/path rule |
| `DELETE` | `/policy/rules` | Remove rule |
| `PUT` | `/policy/thresholds` | Update ML score thresholds |
| `POST` | `/learn/toggle` | Pause/resume unsupervised learning |
| `GET` | `/integrations/{lang}` | Get integration snippet |
| `WS` | `/ws` | WebSocket live event stream |

## Integration Guide

For detailed instructions and architectural diagrams on how to actually place this ML-WAF in front of a real web application (using Reverse Proxy, Middleware, or Sidecar patterns), please read the [Integration Guide](docs/integration_guide.md).

---

## File Documentation

Each source file has a companion markdown document explaining its architecture and open-appsec mapping:

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
| Feature engineering | Proprietary 100+ features | 75 engineered features |
| Policy engine | YAML/REST | JSON/REST |
| Modes | Prevent / Detect / Transparent | Prevent / Detect / Monitor |
| Deployment | eBPF / K8s sidecar | Reverse-proxy / middleware |
| Crowd intelligence | CrowdSec integration | Simulated crowd wisdom module |
| API discovery | ✅ | ✅ (passive endpoint mapper) |
| Real-time learning | ✅ | ✅ (Isolation Forest online learning) |
