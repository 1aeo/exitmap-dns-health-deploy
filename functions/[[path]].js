/**
 * Cloudflare Pages Function - Multi-Storage Data Proxy
 * Serves JSON/archive files from DO Spaces (primary) with R2 fallback.
 * Static assets (HTML/CSS/JS) pass through to Pages.
 * 
 * API Endpoints:
 *   /latest/{fingerprint} - Get latest result for a specific relay
 *   /api/status - Health check
 *   /api/stats - Metadata/summary statistics
 *   /api/failures - All failed relay results
 *   /api/relays - List all relays with basic info
 */

// Cache TTLs in seconds
const TTL = { latest: 60, historical: 31536000, default: 300, api: 60 };

// Security: Pattern to detect traversal attempts (encoded or raw)
const UNSAFE_PATH = /(?:^|\/)\.\.(?:\/|$)|%2e|%00|\x00/i;

// Valid proxy paths pattern - strictly validate filenames
const PROXY_PATH = /^(?:archives\/exitmap-\d{6}\.tar\.gz|(?:dns_health_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}|latest|files)\.json)$/;

// Valid fingerprint: 40 hex characters
const FINGERPRINT_RE = /^[A-Fa-f0-9]{40}$/;

const securityHeaders = () => ({
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
});

const jsonResponse = (data, status, ttl = 0) => new Response(JSON.stringify(data), {
  status,
  headers: {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': ttl > 0 ? `public, max-age=${ttl}` : 'no-cache',
    ...securityHeaders(),
  },
});

const getPath = (params) => {
  const p = Array.isArray(params.path) ? params.path.join('/') : (params.path || '');
  const cleaned = p.replace(/^\/+/, '').split('/').filter(s => s && s !== '.').join('/');
  return UNSAFE_PATH.test(cleaned) ? '' : cleaned;
};

const shouldProxy = (path) => path && PROXY_PATH.test(path);
const isImmutable = (path) => /^(?:dns_health_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.json|archives\/)/.test(path);

const getCacheTTL = (path, env) => {
  if (path === 'latest.json' || path === 'files.json') 
    return parseInt(env.CACHE_TTL_LATEST) || TTL.latest;
  return isImmutable(path) ? (parseInt(env.CACHE_TTL_HISTORICAL) || TTL.historical) : TTL.default;
};

const makeResponse = (body, path, source, ttl) => {
  const immutable = isImmutable(path);
  const cacheControl = `public, max-age=${ttl}${immutable ? ', immutable' : ''}`;
  const contentType = path.endsWith('.json') ? 'application/json; charset=utf-8' : 'application/octet-stream';
  return new Response(body, {
    headers: {
      'Content-Type': contentType,
      'Cache-Control': cacheControl,
      'CDN-Cache-Control': cacheControl,
      'X-Served-From': source,
      ...securityHeaders(),
    },
  });
};

// Fetch from storage backends
const fetchFromStorage = async (env, path) => {
  const order = (env.STORAGE_ORDER || 'do,r2').split(',').map(s => s.trim());
  for (const backend of order) {
    try {
      if (backend === 'do' && env.DO_SPACES_URL) {
        const res = await fetch(`${env.DO_SPACES_URL.replace(/\/$/, '')}/${path}`);
        if (res.ok) return { body: await res.json(), source: 'digitalocean-spaces' };
      } else if (backend === 'r2' && env.EXITMAP_BUCKET) {
        const obj = await env.EXITMAP_BUCKET.get(path);
        if (obj) return { body: await obj.json(), source: 'cloudflare-r2' };
      }
    } catch { /* continue to next backend */ }
  }
  return null;
};

// Fetch latest.json data (cached internally for API endpoints)
const getLatestData = async (env) => fetchFromStorage(env, 'latest.json');

// API endpoint handlers
const apiHandlers = {
  '/api/status': () => jsonResponse({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    service: 'exitmap-dns-health'
  }, 200, TTL.api),

  '/api/stats': async (env) => {
    const data = await getLatestData(env);
    if (!data) return jsonResponse({ error: 'Data unavailable' }, 503, 10);
    return jsonResponse({ 
      metadata: data.body.metadata || {},
      source: data.source 
    }, 200, TTL.api);
  },

  '/api/failures': async (env) => {
    const data = await getLatestData(env);
    if (!data) return jsonResponse({ error: 'Data unavailable' }, 503, 10);
    const results = data.body.results || [];
    const failures = results.filter(r => r.status !== 'success');
    return jsonResponse({ 
      count: failures.length,
      timestamp: data.body.metadata?.timestamp,
      failures,
      source: data.source 
    }, 200, TTL.api);
  },

  '/api/relays': async (env) => {
    const data = await getLatestData(env);
    if (!data) return jsonResponse({ error: 'Data unavailable' }, 503, 10);
    const results = data.body.results || [];
    const relays = results.map(r => ({
      fingerprint: r.exit_fingerprint,
      nickname: r.exit_nickname,
      status: r.status
    }));
    return jsonResponse({ 
      count: relays.length,
      timestamp: data.body.metadata?.timestamp,
      relays,
      source: data.source 
    }, 200, TTL.api);
  },
};

// Handle /latest/{fingerprint} endpoint
const handleLatestFingerprint = async (env, fingerprint) => {
  const fp = fingerprint.toUpperCase();
  if (!FINGERPRINT_RE.test(fp)) {
    return jsonResponse({ error: 'Invalid fingerprint format (expected 40 hex characters)' }, 400, 0);
  }
  const data = await getLatestData(env);
  if (!data) return jsonResponse({ error: 'Data unavailable' }, 503, 10);
  const results = data.body.results || [];
  const result = results.find(r => r.exit_fingerprint?.toUpperCase() === fp);
  if (!result) {
    return jsonResponse({ error: 'Fingerprint not found in latest results' }, 404, TTL.api);
  }
  return jsonResponse({ 
    timestamp: data.body.metadata?.timestamp,
    result,
    source: data.source 
  }, 200, TTL.api);
};

export async function onRequest({ request, env, params, next, waitUntil }) {
  const url = new URL(request.url);
  const rawPath = url.pathname;

  // Handle CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: securityHeaders() });
  }

  // Check API endpoints first
  if (apiHandlers[rawPath]) {
    return apiHandlers[rawPath](env);
  }

  // Handle /latest/{fingerprint} 
  const latestMatch = rawPath.match(/^\/latest\/([A-Fa-f0-9]{40})$/);
  if (latestMatch) {
    return handleLatestFingerprint(env, latestMatch[1]);
  }

  // Return helpful error for malformed /latest/ requests
  if (rawPath.startsWith('/latest/') && rawPath !== '/latest.json') {
    return jsonResponse({ 
      error: 'Invalid fingerprint format',
      usage: '/latest/{40-character-hex-fingerprint}',
      example: '/latest/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    }, 400, 0);
  }

  // Get clean path from params
  const path = getPath(params);
  
  // Pass through to static assets if not a proxy path
  if (!shouldProxy(path)) {
    return next();
  }

  // Try cache first for proxy paths
  const cache = caches.default;
  const cacheKey = new Request(url.origin + '/' + path);
  const cached = await cache.match(cacheKey);
  if (cached) {
    const res = new Response(cached.body, cached);
    res.headers.set('X-Cache-Status', 'HIT');
    return res;
  }

  // Fetch from backends
  const ttl = getCacheTTL(path, env);
  const order = (env.STORAGE_ORDER || 'do,r2').split(',').map(s => s.trim());
  
  for (const backend of order) {
    try {
      if (backend === 'do' && env.DO_SPACES_URL) {
        const res = await fetch(`${env.DO_SPACES_URL.replace(/\/$/, '')}/${path}`);
        if (res.ok) {
          const response = makeResponse(res.body, path, 'digitalocean-spaces', ttl);
          waitUntil(cache.put(cacheKey, response.clone()));
          response.headers.set('X-Cache-Status', 'MISS');
          return response;
        }
      } else if (backend === 'r2' && env.EXITMAP_BUCKET) {
        const obj = await env.EXITMAP_BUCKET.get(path);
        if (obj) {
          const response = makeResponse(obj.body, path, 'cloudflare-r2', ttl);
          waitUntil(cache.put(cacheKey, response.clone()));
          response.headers.set('X-Cache-Status', 'MISS');
          return response;
        }
      }
    } catch { /* continue */ }
  }

  return jsonResponse({ error: 'Not found' }, 404, TTL.api);
}
