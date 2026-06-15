# Deployment Guide: Putting ML-WAF in Front of an Existing Website

This guide walks through adapting the repository's verified demo stack
(`demo-app/` + `nginx/nginx.conf` + `docker-compose.yml`) to protect a real
backend, plus a Kubernetes sidecar alternative.

If you can't front your app with a reverse proxy (e.g. you only control
application code), see the **Application Middleware** section in
[`integration_guide.md`](integration_guide.md) instead.

---

## Option A: Docker Compose (recommended)

The repo's `docker-compose.yml` already defines the full reverse-proxy
stack used by the verified demo:

```yaml
services:
  ml-waf:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./data:/app/data
      - ./models:/app/models

  demo-app:
    build: ./demo-app
    expose:
      - "5000"

  nginx:
    image: nginx:1.27-alpine
    ports:
      - "8090:80"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - ml-waf
      - demo-app
```

To point this at your real application instead of `demo-app`:

### 1. Replace the `demo-app` service

Either point `nginx` at a service running outside this Compose file
(remove the `demo-app` service entirely and add your backend's
host:port), or add your app as a service the same way `demo-app` is
defined:

```yaml
services:
  ml-waf:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./data:/app/data
      - ./models:/app/models

  your-app:
    build: ./your-app          # or image: your-registry/your-app:tag
    expose:
      - "8080"                  # whatever port your app listens on

  nginx:
    image: nginx:1.27-alpine
    ports:
      - "8090:80"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - ml-waf
      - your-app
```

If your app already runs elsewhere (not in this Compose file), drop the
`your-app` service and `depends_on` entry — nginx can `proxy_pass` to any
reachable host:port.

### 2. Update `nginx/nginx.conf`

Change the backend `proxy_pass` target in the `location /` block from
`demo-app:5000` to your service:

```nginx
location / {
    auth_request /waf_check;
    error_page 403 = /blocked;

    proxy_pass http://your-app:8080;     # <-- was http://demo-app:5000
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

The `/waf_check` location block (which gates every request through
ML-WAF) and the `/blocked` and `/waf-dashboard/` locations don't need to
change — they already reference the `ml-waf` service by its Compose
hostname.

### 3. Bring it up

```bash
docker compose up -d --build

# Sanity check: normal traffic passes through
curl http://localhost:8090/

# Sanity check: obvious attack payload gets 403
curl "http://localhost:8090/?q=<script>alert(1)</script>"

# Watch live decisions
open http://localhost:8090/waf-dashboard/
```

### 4. Reduce false positives for your site

Your application's URL patterns, headers, and "normal" traffic shape will
differ from the demo shop. Use the **Tuning Thresholds** workflow in
[`integration_guide.md`](integration_guide.md) — adjust
`PUT /policy/thresholds`, upload a sample of your real (labeled) traffic
via `POST /ml/upload_labeled`, and retrain — to adapt the model to your
site before going to production.

---

## Option B: Kubernetes Sidecar

Run ML-WAF as an additional container in the same Pod as your
application, and gate ingress traffic through it.

### 1. Deploy ML-WAF

Fetch the reference manifest:

```bash
curl http://localhost:8000/integrations/kubernetes
```

This defines a `Deployment` (2 replicas, with `/health` liveness and
readiness probes on port 8000) and a `ClusterIP` `Service` named
`ml-waf`. Apply it to your cluster, adjusting the `image`, resource
limits, and `volumeMounts` (for `models/` and `data/` persistence) to
match your environment.

### 2. Gate ingress traffic via `/waf_check`

If you're using `nginx-ingress`, add an `auth-url` annotation to your
application's `Ingress` pointing at `/waf_check`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: your-app
  annotations:
    nginx.ingress.kubernetes.io/auth-url: "http://ml-waf.default.svc.cluster.local:8000/waf_check"
    nginx.ingress.kubernetes.io/auth-response-headers: "X-Real-IP"
spec:
  rules:
    - host: your-app.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: your-app
                port:
                  number: 8080
```

`/waf_check` returns 200 (allow) or 403 (block), matching what
`nginx-ingress`'s `auth-url` annotation expects — the same contract used
by the Docker Compose demo's `auth_request /waf_check` block.

### 3. Sidecar variant (same Pod)

For tighter latency, run `ml-waf` as a second container in your app's Pod
spec (rather than a separate Deployment), so your app's own
proxy/middleware can call it over `localhost:8000`. Use the container
spec from the `kubernetes` snippet above as the second `containers:`
entry in your existing Pod template, and have your app's middleware call
`http://localhost:8000/analyze` (see [`integration_guide.md`](integration_guide.md)
§2 for middleware examples).

---

## Cross-references

- [`integration_guide.md`](integration_guide.md) — architectural
  patterns, language-specific middleware snippets, troubleshooting, and
  threshold tuning.
- Dashboard **Integration** tab (`/`) — copy-paste snippets for Node.js,
  Python, PHP, Java, Go, Docker, Kubernetes, and Nginx, served from
  `GET /integrations/{lang}`.
