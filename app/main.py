"""
ML-WAF — FastAPI Application Entry Point (open-appsec clone)

Endpoints:
  GET  /                        → Serves the dashboard SPA
  POST /analyze                 → Analyze a single HTTP request snapshot
  ANY  /waf_check                → nginx auth_request gate (200=allow, 403=block)
  POST /simulate/start          → Start a traffic simulation scenario
  POST /simulate/stop           → Stop current simulation
  GET  /simulate/scenarios      → List available scenarios
  GET  /stats                   → Real-time WAF statistics
  POST /stats/reset             → Reset statistics
  GET  /model/info              → ML model metadata and feature importances
  GET  /modules/info            → Info about all active WAF modules
  POST /upload                  → Test file upload security
  POST /ml/upload_labeled       → Upload labeled requests, augment, queue for retrain
  GET  /policy                  → Get current security policy
  POST /policy/rules            → Add a policy rule
  POST /policy/rules/bulk       → Add multiple IP/path rules at once
  POST /policy/rules/import     → Import IP/path rules from a JSON file
  DELETE /policy/rules          → Remove a policy rule
  PUT  /policy/mode             → Set WAF mode (prevent/detect/monitor)
  PUT  /policy/thresholds       → Update ML score thresholds
  POST /policy/reload           → Reload policy from disk
  POST /learn/toggle            → Toggle unsupervised learning
  GET  /integrations/{lang}     → Get integration snippet for a language
  GET  /health                  → Health check for integration clients
  WS   /ws                      → WebSocket live event stream
"""

import csv
import io
import json
import time
import asyncio
import json
import logging
import sys
import subprocess  # nosec B404 — used only to invoke the project's own training script
from pathlib import Path
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, Request, BackgroundTasks, WebSocket, WebSocketDisconnect, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from websockets.exceptions import ConnectionClosedOK

# ── App setup ─────────────────────────────────────────────────────────────────
app = FastAPI(
    title='ML-WAF API — open-appsec clone',
    description='ML-integrated Web Application Firewall with real-time analytics. '
                'Implements supervised + unsupervised ML models, 10-stage pipeline, '
                'and full integration support.',
    version='2.0.0',
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_methods=['*'],
    allow_headers=['*'],
)

ROOT        = Path(__file__).parent.parent
STATIC_DIR  = ROOT / 'static'
INTEG_DIR   = ROOT / 'app' / 'integration'

# ── WebSocket connection manager ───────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, data: dict):
        msg = json.dumps(data, default=str)
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()

# ── Import WAF modules (lazy — model loaded on first request) ─────────────────
from app import waf_engine, simulator, policy
from app.middleware import ips_engine, crowd_wisdom
from app import api_discovery
from ml.unsupervised import get_baseline


# ── Pydantic schemas ───────────────────────────────────────────────────────────
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


class PolicyModeUpdate(BaseModel):
    mode: str  # prevent | detect | monitor


class ThresholdUpdate(BaseModel):
    ml_block_score:          Optional[float] = None
    unsupervised_block_score: Optional[float] = None
    combined_block_score:    Optional[float] = None


class PolicyRuleBulk(BaseModel):
    rule_type: str   # ip_allowlist | ip_blocklist | path_allowlist | path_blocklist
    values:    List[str]


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get('/', response_class=HTMLResponse, include_in_schema=False)
async def dashboard():
    """Serve the SPA dashboard."""
    html_path = STATIC_DIR / 'index.html'
    if not html_path.exists():
        return HTMLResponse('<h1>Dashboard not found. Check static/index.html</h1>', status_code=404)
    return HTMLResponse(html_path.read_text(encoding='utf-8'))


@app.post('/analyze')
async def analyze_request(snapshot: RequestSnapshot):
    """
    Analyze a single HTTP request snapshot through the full WAF pipeline.

    Returns the decision (ALLOW/BLOCK), confidence, attack type,
    per-module results, and extracted ML features.
    """
    result = await waf_engine.analyze(snapshot.model_dump())
    await manager.broadcast({'type': 'request', 'data': _slim(result)})
    return result


@app.api_route('/waf_check', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
async def waf_check(request: Request):
    """
    Reverse-proxy gate for nginx `auth_request` (or any proxy that only
    understands HTTP status codes).

    Reads the original request from headers/body forwarded by nginx:
      X-Original-URI, X-Original-Method, X-Real-IP (set these in nginx config)

    Returns:
      200 → ALLOW (nginx proxies the request to the backend)
      403 → BLOCK (nginx returns 403 to the client)
    """
    body_bytes = await request.body()
    snapshot = {
        'method':  request.headers.get('x-original-method', request.method),
        'url':     request.headers.get('x-original-uri', str(request.url.path)),
        'headers': dict(request.headers),
        'body':    body_bytes.decode('utf-8', errors='ignore'),
        'ip':      request.headers.get('x-real-ip', request.headers.get('x-forwarded-for', '0.0.0.0')),  # nosec B104 — default for missing header, not a bind address
    }

    result = await waf_engine.analyze(snapshot)
    await manager.broadcast({'type': 'request', 'data': _slim(result)})

    if result['decision'] == 'BLOCK':
        return JSONResponse(
            status_code=403,
            content={'block': True, 'reason': result.get('attack_type'), 'id': result['id']},
        )
    return JSONResponse(status_code=200, content={'block': False, 'id': result['id']})


@app.post('/simulate/start')
async def start_simulation(req: SimulateRequest):
    """Start a traffic simulation scenario."""
    if simulator.is_running():
        simulator.stop()
        await asyncio.sleep(0.1)

    async def broadcast(data):
        await manager.broadcast(data)

    simulator.start(
        scenario=req.scenario,
        analyze_fn=waf_engine.analyze,
        broadcast_fn=broadcast,
        n_requests=req.n_requests,
        delay=req.delay,
    )
    return {'status': 'started', 'scenario': req.scenario, 'n_requests': req.n_requests}


@app.post('/simulate/stop')
async def stop_simulation():
    """Stop any running simulation."""
    simulator.stop()
    return {'status': 'stopped'}


@app.get('/simulate/scenarios')
async def list_scenarios():
    return simulator.get_scenarios()


@app.get('/stats')
async def get_stats():
    """Real-time WAF statistics for the dashboard."""
    stats = waf_engine.get_stats()
    return {
        **stats,
        'rate_limiter':      __import__('app.middleware.rate_limiter', fromlist=['get_stats']).get_stats(),
        'api_discovery':     api_discovery.get_stats(),
        'crowd_wisdom':      crowd_wisdom.get_stats(),
        'ips_signatures':    ips_engine.get_signature_count(),
        'simulation_running': simulator.is_running(),
        'policy_mode':       policy.get_policy().get('mode', 'prevent'),
        'unsupervised':      get_baseline().get_stats(),
    }


@app.post('/stats/reset')
async def reset_stats():
    waf_engine.reset_stats()
    return {'status': 'reset'}


@app.get('/model/info')
async def model_info():
    """ML model metadata, feature importances, and training metrics."""
    metrics = waf_engine.get_metrics()
    if not metrics:
        return JSONResponse(
            {'error': 'Model not trained yet. Run: python -m ml.train'},
            status_code=503,
        )
    return {
        **metrics,
        'unsupervised': get_baseline().get_stats(),
    }


@app.post('/ml/retrain')
async def retrain_model(background_tasks: BackgroundTasks):
    """Trigger the ML training script in the background."""
    def run_training():
        try:
            # We use the same python interpreter running this FastAPI server
            subprocess.run([sys.executable, '-m', 'ml.train'], check=True, cwd=str(Path(__file__).parent.parent))  # nosec B603 — fixed arg list, no user input
            # Reload metrics into the engine after training
            waf_engine.load_models()
        except Exception as e:
            logging.error(f"Training failed: {e}")

    background_tasks.add_task(run_training)
    return {'status': 'training_started', 'message': 'Model is retraining in the background. It will reload automatically when finished.'}


@app.post('/ml/upload_labeled')
async def upload_labeled_data(file: UploadFile = File(...), variants_per_sample: int = 5):
    """
    Upload site-specific labeled requests (JSON or CSV), augment them into
    synthetic variants, and append them to data/custom_labeled.jsonl for
    inclusion in the next `/ml/retrain` run.

    JSON: a list of objects with method, url, headers, body, ip (optional),
          label (0/1), attack_type (optional).
    CSV:  columns method,url,headers,body,label,attack_type — `headers` is a
          JSON-encoded object string.

    Does NOT trigger retraining — call /ml/retrain afterward.
    """
    from ml.dataset_generator import augment_labeled_samples

    raw = await file.read()
    filename = (file.filename or '').lower()

    if filename.endswith('.csv'):
        text = raw.decode('utf-8', errors='ignore')
        reader = csv.DictReader(io.StringIO(text))
        rows = list(reader)
        for row in rows:
            if 'headers' in row and row['headers']:
                try:
                    row['headers'] = json.loads(row['headers'])
                except json.JSONDecodeError:
                    row['headers'] = {}
            else:
                row['headers'] = {}
    elif filename.endswith('.json') or filename.endswith('.jsonl'):
        text = raw.decode('utf-8', errors='ignore')
        try:
            if filename.endswith('.jsonl'):
                rows = [json.loads(line) for line in text.splitlines() if line.strip()]
            else:
                rows = json.loads(text)
        except json.JSONDecodeError as e:
            raise HTTPException(status_code=400, detail=f'Invalid JSON: {e}')
        if not isinstance(rows, list):
            raise HTTPException(status_code=400, detail='JSON file must contain a list of request objects')
    else:
        raise HTTPException(status_code=400, detail='Unsupported file type — use .json, .jsonl, or .csv')

    if not rows:
        raise HTTPException(status_code=400, detail='No rows found in uploaded file')

    parsed = []
    for i, row in enumerate(rows):
        if 'method' not in row or 'url' not in row:
            raise HTTPException(status_code=400, detail=f'Row {i}: missing required field "method" or "url"')
        try:
            label = int(row.get('label', 0))
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail=f'Row {i}: "label" must be 0 or 1')
        if label not in (0, 1):
            raise HTTPException(status_code=400, detail=f'Row {i}: "label" must be 0 or 1')

        attack_type = row.get('attack_type') or ('normal' if label == 0 else 'custom')
        parsed.append({
            'method': str(row.get('method', 'GET')).upper(),
            'url': str(row.get('url', '/')),
            'headers': row.get('headers') or {},
            'body': str(row.get('body', '') or ''),
            'ip': str(row.get('ip', '0.0.0.0')),  # nosec B104 — default for missing field, not a bind address
            'label': label,
            'attack_type': attack_type,
        })

    augmented = augment_labeled_samples(parsed, variants_per_sample=variants_per_sample)

    data_dir = Path(__file__).parent.parent / 'data'
    data_dir.mkdir(exist_ok=True)
    custom_path = data_dir / 'custom_labeled.jsonl'
    with open(custom_path, 'a', encoding='utf-8') as f:
        for row in augmented:
            f.write(json.dumps(row) + '\n')

    return {
        'status': 'uploaded',
        'rows_parsed': len(parsed),
        'rows_augmented': len(augmented) - len(parsed),
        'total_written': len(augmented),
    }


@app.get('/modules/info')
async def modules_info():
    """Information about all active WAF modules."""
    return {
        'modules': [
            {
                'id':          'ml_waf',
                'name':        'ML WAF (Supervised)',
                'description': 'Random Forest classifier trained on CSIC 2010 + OWASP Juice Shop + HTTPParams. Detects OWASP Top-10 and zero-day threats without signatures.',
                'active':      True,
                'icon':        '🤖',
                'category':    'ml',
            },
            {
                'id':          'unsupervised',
                'name':        'Behavioral Baseline (Unsupervised)',
                'description': 'Isolation Forest that learns your app\'s normal traffic patterns in real-time. Flags requests that deviate from the baseline even if the supervised model misses them.',
                'active':      True,
                'icon':        '🧠',
                'category':    'ml',
                'stats':       get_baseline().get_stats(),
            },
            {
                'id':          'nosql_injection',
                'name':        'NoSQL Injection',
                'description': 'Detects MongoDB operator injection ($where, $gt, $ne), JavaScript injection, JSON-based attacks, and Redis protocol injection.',
                'active':      True,
                'icon':        '🗄️',
                'category':    'detection',
            },
            {
                'id':          'jwt_abuse',
                'name':        'JWT Abuse Detection',
                'description': 'Identifies JWT manipulation: alg:none attacks, expired token replay, tampered role claims, algorithm confusion (RS256→HS256), and injection in JWT payloads.',
                'active':      True,
                'icon':        '🔑',
                'category':    'detection',
            },
            {
                'id':          'anti_bot',
                'name':        'Anti-Bot',
                'description': 'Identifies automated scanners via UA fingerprinting, header analysis, and velocity/path-scanning detection.',
                'active':      True,
                'icon':        '🚫',
                'category':    'detection',
            },
            {
                'id':          'ips',
                'name':        'Intrusion Prevention (IPS)',
                'description': f'Matches against {ips_engine.get_signature_count()} CVE-based signatures including Log4Shell, Spring4Shell, Shellshock, and more.',
                'active':      True,
                'icon':        '🛡️',
                'category':    'detection',
            },
            {
                'id':          'rate_limiter',
                'name':        'Rate Limiting',
                'description': 'Sliding-window per-IP rate limiting with burst detection and automatic temporary banning.',
                'active':      True,
                'icon':        '⏱️',
                'category':    'protection',
            },
            {
                'id':          'file_security',
                'name':        'File Security',
                'description': 'Validates uploaded files: magic byte verification, dangerous extension blocking, EICAR detection, embedded script scanning.',
                'active':      True,
                'icon':        '📁',
                'category':    'protection',
            },
            {
                'id':          'crowd_wisdom',
                'name':        'Crowd Wisdom',
                'description': 'Blocks known-malicious IPs using an offline blocklist + optional CrowdSec CTI API (64,000+ contributing servers).',
                'active':      True,
                'icon':        '🌐',
                'category':    'intelligence',
            },
            {
                'id':          'api_discovery',
                'name':        'API Discovery',
                'description': 'Automatically maps your API attack surface, detects probes of undiscovered endpoints, and flags schema anomalies.',
                'active':      True,
                'icon':        '🔍',
                'category':    'discovery',
            },
        ]
    }


@app.post('/upload')
async def upload_file(file: UploadFile = File(...)):
    """Test file upload security scanning."""
    from app.middleware.file_security import scan_file
    content = await file.read()
    result = scan_file(file.filename or 'unknown', content)
    if result['block']:
        raise HTTPException(status_code=400, detail=result)
    return {
        'status': 'accepted',
        'filename': file.filename,
        'size': len(content),
        'details': result.get('details', {}),
    }


# ── Policy endpoints ───────────────────────────────────────────────────────────

@app.get('/policy')
async def get_policy():
    """Get current security policy."""
    return policy.get_policy()


@app.post('/policy/rules')
async def add_policy_rule(rule: PolicyRule):
    """Add a policy rule (allowlist/blocklist)."""
    try:
        updated = policy.add_rule(rule.rule_type, rule.value)
        return {'status': 'added', 'policy': updated}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete('/policy/rules')
async def remove_policy_rule(rule: PolicyRule):
    """Remove a policy rule."""
    updated = policy.remove_rule(rule.rule_type, rule.value)
    return {'status': 'removed', 'policy': updated}


@app.post('/policy/rules/bulk')
async def add_policy_rules_bulk(rule: PolicyRuleBulk):
    """Add multiple IP/path allowlist or blocklist rules at once."""
    try:
        added_count, skipped_count, updated = policy.add_rules_bulk(rule.rule_type, rule.values)
        return {
            'status': 'added',
            'added_count': added_count,
            'skipped_count': skipped_count,
            'policy': updated,
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post('/policy/rules/import')
async def import_policy_rules(file: UploadFile = File(...)):
    """
    Bulk-import IP/path rules from an uploaded JSON file.

    Expected format: an object whose keys are rule types and whose values
    are lists of strings, e.g.:
      {
        "ip_allowlist": ["10.0.0.1", "10.0.0.2"],
        "ip_blocklist": ["1.2.3.4"],
        "path_allowlist": ["/health", "/static/.*"],
        "path_blocklist": ["/admin"]
      }

    Any subset of the four keys may be present; unknown keys are rejected.
    """
    valid_types = ['ip_allowlist', 'ip_blocklist', 'path_allowlist', 'path_blocklist']

    raw = await file.read()
    try:
        data = json.loads(raw.decode('utf-8', errors='ignore'))
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f'Invalid JSON: {e}')

    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail='File must contain a JSON object mapping rule types to lists of values')

    unknown = [k for k in data if k not in valid_types]
    if unknown:
        raise HTTPException(status_code=400, detail=f'Unknown rule type(s): {unknown}. Must be one of {valid_types}')

    results = {}
    updated = policy.get_policy()
    for rule_type, values in data.items():
        if not isinstance(values, list):
            raise HTTPException(status_code=400, detail=f'Value for "{rule_type}" must be a list of strings')
        added_count, skipped_count, updated = policy.add_rules_bulk(rule_type, [str(v) for v in values])
        results[rule_type] = {'added': added_count, 'skipped': skipped_count}

    return {'status': 'imported', 'results': results, 'policy': updated}


@app.put('/policy/mode')
async def set_policy_mode(update: PolicyModeUpdate):
    """Set WAF mode: prevent | detect | monitor."""
    valid_modes = ['prevent', 'detect', 'monitor']
    if update.mode not in valid_modes:
        raise HTTPException(status_code=400, detail=f'Mode must be one of {valid_modes}')
    updated = policy.update_policy({'mode': update.mode})
    return {'status': 'updated', 'mode': update.mode, 'policy': updated}


@app.put('/policy/thresholds')
async def update_thresholds(update: ThresholdUpdate):
    """Update ML score thresholds."""
    thresholds = {}
    if update.ml_block_score is not None:
        thresholds['ml_block_score'] = update.ml_block_score
    if update.unsupervised_block_score is not None:
        thresholds['unsupervised_block_score'] = update.unsupervised_block_score
    if update.combined_block_score is not None:
        thresholds['combined_block_score'] = update.combined_block_score

    updated = policy.update_policy({'thresholds': thresholds})
    return {'status': 'updated', 'thresholds': updated.get('thresholds')}


@app.post('/policy/reload')
async def reload_policy():
    """Reload policy from disk."""
    p = policy.load()
    return {'status': 'reloaded', 'policy': p}


# ── Learning control ───────────────────────────────────────────────────────────

@app.post('/learn/toggle')
async def toggle_learning():
    """Toggle the unsupervised learning on/off."""
    current = waf_engine.is_learning()
    waf_engine.set_learning(not current)
    return {
        'status': 'toggled',
        'learning_enabled': waf_engine.is_learning(),
        'baseline_stats': get_baseline().get_stats(),
    }


@app.post('/learn/save')
async def save_baseline():
    """Save the current unsupervised model to disk."""
    from ml.unsupervised import save_baseline as _save
    _save()
    return {'status': 'saved', 'stats': get_baseline().get_stats()}


# ── Integration snippets ───────────────────────────────────────────────────────

INTEGRATION_SNIPPETS = {
    'nodejs': '''// ML-WAF Integration — Node.js / Express
const axios = require('axios');

const WAF_URL = '{waf_url}';

/**
 * Express middleware — forwards request to ML-WAF for analysis.
 * Block malicious requests before they reach your app logic.
 */
async function mlWafMiddleware(req, res, next) {
  try {
    const snapshot = {
      method: req.method,
      url: req.originalUrl,
      headers: req.headers,
      body: req.body ? JSON.stringify(req.body) : '',
      ip: req.ip || req.connection.remoteAddress,
    };

    const { data } = await axios.post(`${WAF_URL}/analyze`, snapshot, {
      timeout: 500,   // don't block your app if WAF is slow
    });

    // Attach WAF result to request for logging
    req.waf = data;

    if (data.decision === 'BLOCK') {
      return res.status(403).json({
        error: 'Request blocked by ML-WAF',
        attack_type: data.attack_type,
        reference: data.id,
      });
    }

    next();
  } catch (err) {
    // Fail-open: if WAF is unreachable, allow the request
    console.error('[ML-WAF] Middleware error:', err.message);
    next();
  }
}

// Mount the middleware
app.use(mlWafMiddleware);
''',

    'python': '''# ML-WAF Integration — Python / FastAPI or Flask
import httpx
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

WAF_URL = '{waf_url}'

class MLWafMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware — sends each request to ML-WAF for analysis."""

    async def dispatch(self, request: Request, call_next):
        try:
            body = await request.body()
            snapshot = {
                'method': request.method,
                'url': str(request.url),
                'headers': dict(request.headers),
                'body': body.decode('utf-8', errors='replace'),
                'ip': request.client.host if request.client else '0.0.0.0',
            }

            async with httpx.AsyncClient(timeout=0.5) as client:
                resp = await client.post(f'{WAF_URL}/analyze', json=snapshot)
                result = resp.json()

            if result.get('decision') == 'BLOCK':
                raise HTTPException(
                    status_code=403,
                    detail={
                        'error': 'Blocked by ML-WAF',
                        'attack_type': result.get('attack_type'),
                        'reference': result.get('id'),
                    }
                )
        except httpx.TimeoutException:
            pass  # Fail-open

        return await call_next(request)

# Mount in your FastAPI app:
# from fastapi import FastAPI
# app = FastAPI()
# app.add_middleware(MLWafMiddleware)
''',

    'php': '''<?php
// ML-WAF Integration — PHP

define('WAF_URL', '{waf_url}');

function ml_waf_check(array $request_data): bool {{
    $payload = json_encode([
        'method'  => $request_data['method']  ?? $_SERVER['REQUEST_METHOD'],
        'url'     => $request_data['url']     ?? $_SERVER['REQUEST_URI'],
        'headers' => $request_data['headers'] ?? getallheaders(),
        'body'    => $request_data['body']    ?? file_get_contents('php://input'),
        'ip'      => $request_data['ip']      ?? $_SERVER['REMOTE_ADDR'],
    ]);

    $ch = curl_init(WAF_URL . '/analyze');
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $payload,
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT_MS     => 500,
    ]);

    $response = curl_exec($ch);
    $error    = curl_error($ch);
    curl_close($ch);

    if ($error || !$response) return true;  // Fail-open

    $result = json_decode($response, true);
    if ($result && $result['decision'] === 'BLOCK') {{
        http_response_code(403);
        header('Content-Type: application/json');
        echo json_encode([
            'error'       => 'Blocked by ML-WAF',
            'attack_type' => $result['attack_type'],
            'reference'   => $result['id'],
        ]);
        exit();
    }}
    return true;
}}

// Call at top of each PHP script or in a global bootstrap:
// ml_waf_check([]);
?>
''',

    'java': '''// ML-WAF Integration — Java Spring Boot
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

@Component
public class MLWafFilter implements Filter {{

    private static final String WAF_URL = "{waf_url}/analyze";
    private final RestTemplate restTemplate = new RestTemplate();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {{

        HttpServletRequest httpReq = (HttpServletRequest) request;
        HttpServletResponse httpResp = (HttpServletResponse) response;

        try {{
            Map<String, Object> snapshot = Map.of(
                "method",  httpReq.getMethod(),
                "url",     httpReq.getRequestURI(),
                "ip",      httpReq.getRemoteAddr(),
                "body",    new String(httpReq.getInputStream().readAllBytes()),
                "headers", Map.of("User-Agent", httpReq.getHeader("User-Agent"))
            );

            @SuppressWarnings("unchecked")
            Map<String, Object> result = restTemplate.postForObject(WAF_URL, snapshot, Map.class);

            if (result != null && "BLOCK".equals(result.get("decision"))) {{
                httpResp.setStatus(403);
                httpResp.setContentType("application/json");
                httpResp.getWriter().write("{{\\"error\\":\\"Blocked by ML-WAF\\"}}");
                return;
            }}
        }} catch (Exception e) {{
            // Fail-open: proceed if WAF is unreachable
        }}

        chain.doFilter(request, response);
    }}
}}
''',

    'go': '''// ML-WAF Integration — Go
package mlwaf

import (
    "bytes"
    "encoding/json"
    "io"
    "net/http"
    "time"
)

const WafURL = "{waf_url}"

type RequestSnapshot struct {
    Method  string            `json:"method"`
    URL     string            `json:"url"`
    Headers map[string]string `json:"headers"`
    Body    string            `json:"body"`
    IP      string            `json:"ip"`
}

type WafResult struct {
    Decision   string  `json:"decision"`
    AttackType string  `json:"attack_type"`
    Confidence float64 `json:"confidence"`
    ID         string  `json:"id"`
}

var client = &http.Client{Timeout: 500 * time.Millisecond}

// Middleware wraps an http.Handler and checks requests via ML-WAF.
func Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        body, _ := io.ReadAll(r.Body)
        r.Body = io.NopCloser(bytes.NewBuffer(body))

        snapshot := RequestSnapshot{
            Method:  r.Method,
            URL:     r.RequestURI,
            Headers: map[string]string{"User-Agent": r.UserAgent()},
            Body:    string(body),
            IP:      r.RemoteAddr,
        }

        payload, _ := json.Marshal(snapshot)
        resp, err := client.Post(WafURL+"/analyze", "application/json", bytes.NewBuffer(payload))
        if err == nil && resp != nil {
            defer resp.Body.Close()
            var result WafResult
            if json.NewDecoder(resp.Body).Decode(&result) == nil && result.Decision == "BLOCK" {
                w.Header().Set("Content-Type", "application/json")
                w.WriteHeader(http.StatusForbidden)
                json.NewEncoder(w).Encode(map[string]string{
                    "error":       "Blocked by ML-WAF",
                    "attack_type": result.AttackType,
                    "reference":   result.ID,
                })
                return
            }
        }
        next.ServeHTTP(w, r)
    })
}
''',

    'docker': '''# ML-WAF Docker Compose — Sidecar Deployment
#
# Add this to your existing docker-compose.yml to protect any web app.
# Your app only needs to be on the same Docker network.

version: "3.9"

services:
  # Your existing application
  myapp:
    image: your-app-image:latest
    environment:
      - MLWAF_URL=http://mlwaf:8000
    networks:
      - waf-net

  # ML-WAF sidecar
  mlwaf:
    image: python:3.11-slim
    working_dir: /app
    volumes:
      - ./ml-waf:/app
      - waf-models:/app/models
    command: >
      bash -c "pip install -r requirements.txt -q &&
               python -m ml.train &&
               uvicorn app.main:app --host 0.0.0.0 --port 8000"
    ports:
      - "8000:8000"    # Dashboard accessible on host
    environment:
      - CROWDSEC_API_KEY=${CROWDSEC_API_KEY:-}
    networks:
      - waf-net
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  waf-models:

networks:
  waf-net:
    driver: bridge
''',

    'nginx': '''# ML-WAF reverse-proxy via Nginx auth_request
#
# Gates all traffic to your backend through ML-WAF's /waf_check endpoint.
# /waf_check returns 200 (allow) or 403 (block) — see the verified demo
# in nginx/nginx.conf and docker-compose.yml for a working example.

worker_processes auto;

events {
    worker_connections 1024;
}

http {
    client_body_buffer_size 128k;
    client_max_body_size 10m;

    server {
        listen 80;
        server_name _;

        # Ask ML-WAF if the request is safe
        location = /waf_check {
            internal;
            proxy_pass {waf_url}/waf_check;
            proxy_pass_request_body on;
            proxy_set_header Content-Length $content_length;
            proxy_set_header Content-Type $content_type;
            proxy_set_header X-Original-URI $request_uri;
            proxy_set_header X-Original-Method $request_method;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        # Your application — replace with your backend host:port
        location / {
            auth_request /waf_check;
            error_page 403 = /blocked;

            proxy_pass http://your-backend:8080;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        location = /blocked {
            internal;
            default_type application/json;
            return 403 '{"error": "Request blocked by ML-WAF"}';
        }
    }
}
''',

    'kubernetes': '''# ML-WAF Kubernetes Deployment
# Deploy as a DaemonSet sidecar alongside your application pods.

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ml-waf
  labels:
    app: ml-waf
spec:
  replicas: 2
  selector:
    matchLabels:
      app: ml-waf
  template:
    metadata:
      labels:
        app: ml-waf
    spec:
      containers:
      - name: ml-waf
        image: python:3.11-slim
        command: ["/bin/bash", "-c"]
        args:
          - "pip install -r /app/requirements.txt -q && uvicorn app.main:app --host 0.0.0.0 --port 8000"
        workingDir: /app
        ports:
        - containerPort: 8000
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 5
        volumeMounts:
        - name: app-code
          mountPath: /app
        - name: waf-models
          mountPath: /app/models
      volumes:
      - name: app-code
        configMap:
          name: ml-waf-code
      - name: waf-models
        persistentVolumeClaim:
          claimName: waf-models-pvc

---
apiVersion: v1
kind: Service
metadata:
  name: ml-waf
spec:
  selector:
    app: ml-waf
  ports:
  - port: 8000
    targetPort: 8000
  type: ClusterIP

---
# Add this annotation to your app's Ingress to route through ML-WAF:
# nginx.ingress.kubernetes.io/auth-url: "http://ml-waf.default.svc.cluster.local:8000/analyze"
''',
}


@app.get('/integrations/{lang}')
async def get_integration(lang: str):
    """Get integration snippet for a specific language/platform."""
    lang = lang.lower()
    if lang not in INTEGRATION_SNIPPETS:
        available = list(INTEGRATION_SNIPPETS.keys())
        raise HTTPException(
            status_code=404,
            detail=f'No integration for "{lang}". Available: {available}'
        )

    # Fill in the WAF URL dynamically
    waf_url = 'http://localhost:8000'
    snippet = INTEGRATION_SNIPPETS[lang].replace('{waf_url}', waf_url)

    return {
        'language': lang,
        'snippet': snippet,
        'waf_url': waf_url,
        'available_languages': list(INTEGRATION_SNIPPETS.keys()),
    }


@app.get('/integrations')
async def list_integrations():
    """List all available integration languages."""
    return {
        'available': list(INTEGRATION_SNIPPETS.keys()),
        'descriptions': {
            'nodejs':     'Express.js middleware',
            'python':     'FastAPI/Flask ASGI middleware',
            'php':        'PHP cURL-based middleware function',
            'java':       'Spring Boot Filter component',
            'go':         'net/http middleware handler',
            'docker':     'Docker Compose sidecar deployment',
            'kubernetes': 'Kubernetes Deployment + Service + Ingress',
            'nginx':      'Nginx reverse proxy via /waf_check (auth_request)',
        }
    }


@app.get('/health')
async def health():
    """Health check endpoint for integration clients and load balancers."""
    return {
        'status': 'ready' if _app_ready else 'starting',
        'version': '2.0.0',
        'model_loaded': waf_engine.is_model_loaded(),
        'uptime': time.time(),
    }


@app.websocket('/ws')
async def websocket_endpoint(ws: WebSocket):
    """WebSocket endpoint for real-time event streaming to the dashboard."""
    await manager.connect(ws)
    try:
        # Send initial state
        await ws.send_text(json.dumps({
            'type': 'init',
            'data': {
                'stats': waf_engine.get_stats(),
                'metrics': waf_engine.get_metrics(),
                'policy': policy.get_policy(),
            }
        }, default=str))

        # Keep alive with periodic stat updates
        while True:
            await asyncio.sleep(2)
            await ws.send_text(json.dumps({
                'type': 'stats_update',
                'data': waf_engine.get_stats(),
            }, default=str))

    except WebSocketDisconnect:
        manager.disconnect(ws)
    except Exception:
        manager.disconnect(ws)


# ── Startup ────────────────────────────────────────────────────────────────────
_app_ready = False  # Set to True once model + policy are loaded

@app.on_event('startup')
async def startup():
    global _app_ready
    import asyncio
    loop = asyncio.get_event_loop()

    print('\n' + '=' * 65)
    print('  ML-WAF v2.0 — open-appsec clone — Starting up')
    print('=' * 65)

    # Load model in thread pool so the async event loop stays responsive.
    # This prevents the 1.7 MB GBT pickle from blocking health-check probes.
    try:
        await loop.run_in_executor(None, waf_engine.get_model)
    except Exception as e:
        print(f'  Model load warning: {e}')

    try:
        policy.load()
        print(f'  Policy: mode={policy.get_policy().get("mode", "prevent")}')
    except Exception as e:
        print(f'  Policy load warning: {e}')

    baseline = get_baseline()
    print(f'  Unsupervised: {baseline.sample_count} samples, active={baseline.is_active}')
    print(f'  Dashboard: http://localhost:8000')
    print(f'  API Docs:  http://localhost:8000/docs')
    print('=' * 65 + '\n')
    _app_ready = True


# ── Helpers ────────────────────────────────────────────────────────────────────
def _slim(result: dict) -> dict:
    return {
        'id':                 result['id'],
        'timestamp':          result['timestamp'],
        'method':             result['method'],
        'url':                str(result['url'])[:80],
        'ip':                 result['ip'],
        'decision':           result['decision'],
        'confidence':         result['confidence'],
        'attack_type':        result['attack_type'],
        'blocked_by':         result['blocked_by'],
        'ml_score':           result.get('ml_score', 0),
        'unsupervised_score': result.get('unsupervised_score', 0),
        'features': {
            k: result.get('features', {}).get(k, 0)
            for k in ['sql_keyword_count', 'xss_pattern_count', 'path_traversal_count',
                      'cmd_injection_count', 'nosql_operator_count', 'suspicious_ua',
                      'url_length', 'body_entropy', 'jwt_alg_none']
        },
    }
