# `anti_bot.py` — Anti-Bot Middleware

## Overview

`anti_bot.py` is **Stage 2** in the WAF pipeline. Its role is to quickly identify and block automated vulnerability scanners, scrapers, and malicious bots before they consume downstream resources (like ML inference). 

---

## Detection Mechanisms

The module uses a multi-layered approach to bot detection:

### 1. Known Scanner Signatures
It matches the `User-Agent` header against a curated list of over 30 known malicious tool fingerprints (e.g., `sqlmap`, `nikto`, `masscan`, `dirbuster`, `nuclei`). If a match is found, the request is blocked with 97%+ confidence.

### 2. Missing/Empty User-Agent
Legitimate web browsers always send a User-Agent. If this header is entirely missing or empty, the request is flagged with 75% confidence.

### 3. Suspicious Header Absence
Real browsers typically send a predictable set of headers, including `Accept` and `Accept-Language`. If a request is missing two or more of these standard headers, it strongly suggests a poorly written custom script (e.g., a simple `curl` or `requests.get()` call without customized headers). This adds 65% confidence.

### 4. Behavioral Velocity & Path Scanning
Even if a bot spoofs a legitimate User-Agent, its behavior often gives it away. The module tracks request history per IP over a 10-second sliding window (`VELOCITY_WINDOW`). 
- **Volume:** >50 requests in 10s flags as a bot.
- **Path Scanning (Directory Brute-Forcing):** Accessing >20 *distinct* paths in 10s is a classic sign of directory enumeration (e.g., `dirbuster` or `gobuster`).

### 5. Suspicious Path Probes
Accessing sensitive administrative paths (e.g., `/wp-admin`, `/.env`, `/.git`) combined with a non-standard User-Agent increases the bot confidence score.

---

## Output

If the accumulated confidence score exceeds 0.70, the request is blocked:

```python
return {
    'block': block,
    'confidence': round(confidence, 3),
    'reason': '; '.join(reasons) if reasons else 'OK',
    'is_bot': block,
    'ua': ua[:80],
}
```

---

## Integration in the Pipeline

Placed immediately after the Rate Limiter, the Anti-Bot module acts as a fast, cheap pre-filter. By dropping scanner traffic early, it saves the computationally more expensive ML models in Stages 8 and 9 from having to evaluate blatant automated attacks.

---

## open-appsec Equivalent

open-appsec includes an **Anti-Bot** blade that uses both signature-based and behavioral mechanisms to differentiate between humans and bots. While open-appsec's implementation is far more advanced—utilizing JavaScript injection to verify browser environment execution, mouse movement tracking, and advanced CAPTCHAs—this Python module implements the core server-side heuristic components of bot detection.
