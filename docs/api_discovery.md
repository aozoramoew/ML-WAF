# `api_discovery.py` — API Discovery & Schema Validation

## Overview

`api_discovery.py` is Stage 10 of the WAF pipeline. It is a **passive mapping module** that does not block requests by default (except for egregious admin probes). Its primary purpose is to build an inventory of all API endpoints accessed and infer their expected schemas based on observed traffic.

---

## Capabilities

1. **Endpoint Inventory**: Automatically builds a list of all accessed URLs.
2. **Dynamic Path Normalization**: Detects UUIDs and numeric IDs in paths and collapses them into templates (e.g., `/api/users/123` and `/api/users/456` both become `/api/users/{id}`).
3. **Schema Inference**: Records which HTTP methods (`GET`, `POST`, etc.) and query parameters are used on each endpoint.
4. **Anomaly Detection**: Flags requests that use new methods or unexpected parameters on known endpoints.

---

## Data Structure

The module maintains an in-memory dictionary `_endpoints` mapping the normalized path to its inferred schema:

```python
_endpoints['/api/users/{id}'] = {
    'methods': {'GET', 'PUT', 'DELETE'},
    'params': {'include_deleted', 'format'},
    'seen': 1542,
    'first_seen': 1717420000.0,
    'last_seen': 1717425000.0,
    'is_new': False
}
```

---

## Anomaly Detection

When a request arrives, `api_discovery.record()` compares it against the known schema for that endpoint:

- **New Method Anomaly**: If a `DELETE` request is sent to an endpoint that has only ever seen `GET` and `POST` traffic.
- **Unexpected Parameter Anomaly**: If a request includes `?admin=true` on an endpoint where that parameter has never been seen before.
- **Suspicious Probes**: Automatically detects common brute-force paths (`/wp-admin`, `/.env`, `/.git`) and blocks them if they are accessed fewer than 3 times (preventing automated scanners from discovering sensitive files).

---

## Integration in the Pipeline

This module runs at the **very end** of `waf_engine.analyze()`. Unlike other stages, it always runs, even if the request was blocked by an earlier stage. This ensures that the WAF maintains a complete picture of both legitimate usage and attacker reconnaissance.

---

## Dashboard Integration

The dashboard's **API Discovery** tab polls `/stats` to retrieve the `endpoint_map`. It renders a sorted list of the most frequently accessed endpoints and highlights any that have triggered schema anomalies.

---

## open-appsec Equivalent

open-appsec includes an **API Discovery** feature that builds an OpenAPI (Swagger) schema from traffic. It can then enforce that schema, blocking requests that contain undefined parameters or use incorrect HTTP methods. This module implements a lightweight version of that same concept, focusing on visibility and basic anomaly detection without requiring an upfront OpenAPI spec.
