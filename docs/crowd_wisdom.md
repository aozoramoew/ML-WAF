# `crowd_wisdom.py` — Crowd Wisdom Middleware

## Overview

`crowd_wisdom.py` is **Stage 3** of the WAF pipeline. It leverages external threat intelligence to block requests from known malicious actors, botnets, and proxy networks before they reach deeper layers of the WAF. It supports both an embedded offline blocklist and real-time API queries.

---

## Capabilities

### 1. Offline Embedded Blocklist
To ensure fast execution even without an API key or internet access, the module contains a hardcoded list of known-bad CIDR ranges (`_OFFLINE_BLOCKLIST_CIDRS`). This includes Tor exit nodes, Shodan/Censys scanner ranges, and known malicious botnet IPs.

### 2. CrowdSec CTI Integration (Live Threat Intel)
If a `CROWDSEC_API_KEY` is provided, the module makes a real-time asynchronous request to the [CrowdSec Cyber Threat Intelligence (CTI) API](https://app.crowdsec.net/). CrowdSec aggregates attack reports from over 64,000 servers worldwide.
- If the API classifies the IP as highly aggressive or untrustworthy (`trust < 0.1` or `composite score > 0.7`), the request is blocked.
- Results are cached in memory for 1 hour (`CACHE_TTL`) to avoid slowing down subsequent requests from the same IP.
- The API call has a strict 2.0s timeout and "fails open" (allows the request through) if the API is unreachable, ensuring the WAF never blocks legitimate traffic due to a third-party outage.

---

## Integration in the Pipeline

This module runs early in the pipeline (Stage 3). Blocking known bad actors based on IP reputation is extremely computationally efficient. It acts as a shield, preventing known scanners and botnets from ever touching the IPS engine or ML models.

---

## open-appsec Equivalent

open-appsec integrates natively with **CrowdSec** as its primary source of "Crowd Wisdom." This Python module is a direct, simplified replication of that architecture, querying the exact same upstream threat intelligence feed to provide proactive defense based on global community signals.
