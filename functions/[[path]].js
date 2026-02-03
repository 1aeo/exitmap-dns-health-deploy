/**
 * Cloudflare Pages Function - Multi-Storage Data Proxy
 * Serves JSON/archive files from DO Spaces (primary) with R2 fallback.
 * Static assets (HTML/CSS/JS) pass through to Pages.
 * 
 * API Endpoints:
 *   /api/status           - Health check
 *   /api/stats            - Metadata/summary from latest.json
 *   /api/failures         - Failed relay results only
 *   /api/relays           - List all relays with basic info
 *   /latest/{fingerprint} - Result for a specific relay fingerprint
 */

// === Constants ===
const TTL = { latest: 60, historical: 31536000, default: 300, api: 60 };
const LATEST_PATH = 'latest.json';
const FINGERPRINT_RE = /^[A-Fa-f0-9]{40}$/;

// Security: Pattern to detect traversal attempts (encoded or raw)
const UNSAFE_PATH = /(?:^|\/)\.\.(?:\/|$)|%2e|%00|\x00/i;

// Valid proxy paths pattern - strictly validate filenames
const PROXY_PATH = /^(?:archives\/exitmap-\d{6}\.tar\.gz|(?:dns_health_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}|latest|files)\.json)$/;

// === Helpers ===

const securityHeaders = () => ({
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
});

const getPath = (params) => {
  const p = Array.isArray(params.path) ? params.path.join('/') : (params.path || '');
  const cleaned = p.replace(/^\/+/, '').split('/').filter(s => s && s !== '.').join('/');
  return UNSAFE_PATH.test(cleaned) ? '' : cleaned;
};

const shouldProxy = (path) => path && PROXY_PATH.test(path);
const isImmutable = (path) => /^(?:dns_health_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.json|archives\/)/.test(path);
const normalizeFingerprint = (fp) => (fp || '').toUpperCase();

const getCacheTTL = (path, env) => {
  if (path === LATEST_PATH || path === 'files.json')
    return parseInt(env.CACHE_TTL_LATEST) || TTL.latest;
  return isImmutable(path) ? (parseInt(env.CACHE_TTL_HISTORICAL) || TTL.historical) : TTL.default;
};

// === Response Builders ===

const jsonResponse = (data, status, ttl = 0, cacheStatus = null) => {
  const res = new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': ttl > 0 ? `public, max-age=${ttl}` : 'no-cache',
      ...securityHeaders(),
    },
  });
  if (cacheStatus) res.headers.set('X-Cache-Status', cacheStatus);
  return res;
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

// === Cache Helpers (from 2260) ===

const cacheRequest = (origin, path) => new Request(`${origin}/${path}`);

const cacheHit = (cached) => {
  const res = new Response(cached.body, cached);
  res.headers.set('X-Cache-Status', 'HIT');
  return res;
};

const cacheAndReturn = (cache, cacheKey, res, waitUntil) => {
  waitUntil(cache.put(cacheKey, res.clone()));
  res.headers.set('X-Cache-Status', 'MISS');
  return res;
};

// === Storage Fetching (DRY from 2260) ===

const fetchFromStorage = async (env, path, ttl) => {
  const order = (env.STORAGE_ORDER || 'do,r2').split(',').map(s => s.trim());
  for (const backend of order) {
    try {
      if (backend === 'do' && env.DO_SPACES_URL) {
        const res = await fetch(`${env.DO_SPACES_URL.replace(/\/$/, '')}/${path}`);
        if (res.ok) return makeResponse(res.body, path, 'digitalocean-spaces', ttl);
      } else if (backend === 'r2' && env.EXITMAP_BUCKET) {
        const obj = await env.EXITMAP_BUCKET.get(path);
        if (obj) return makeResponse(obj.body, path, 'cloudflare-r2', ttl);
      }
    } catch { /* continue to next backend */ }
  }
  return null;
};

// Fetch latest.json and parse as JSON (for API endpoints)
const fetchLatestJson = async (env) => {
  const order = (env.STORAGE_ORDER || 'do,r2').split(',').map(s => s.trim());
  for (const backend of order) {
    try {
      if (backend === 'do' && env.DO_SPACES_URL) {
        const res = await fetch(`${env.DO_SPACES_URL.replace(/\/$/, '')}/${LATEST_PATH}`);
        if (res.ok) return { data: await res.json(), source: 'digitalocean-spaces' };
      } else if (backend === 'r2' && env.EXITMAP_BUCKET) {
        const obj = await env.EXITMAP_BUCKET.get(LATEST_PATH);
        if (obj) return { data: await obj.json(), source: 'cloudflare-r2' };
      }
    } catch { /* continue */ }
  }
  return null;
};

// Load latest.json with Cloudflare cache integration (from 2260)
const getLatestData = async (env, origin, cache, waitUntil) => {
  const cacheKey = cacheRequest(origin, LATEST_PATH);
  const cached = await cache.match(cacheKey);
  
  if (cached) {
    try {
      return { data: await cached.clone().json(), cacheStatus: 'HIT' };
    } catch { /* cache corrupted, refetch */ }
  }

  const result = await fetchLatestJson(env);
  if (!result) return null;
  
  // Store raw response in cache for future use
  const ttl = getCacheTTL(LATEST_PATH, env);
  const cacheResponse = jsonResponse(result.data, 200, ttl);
  waitUntil(cache.put(cacheKey, cacheResponse));
  
  return { data: result.data, source: result.source, cacheStatus: 'MISS' };
};

// === API Handlers (pattern from bc7f/cb18) ===

const apiHandlers = {
  '/api/status': () => jsonResponse({
    status: 'ok',
    timestamp: new Date().toISOString(),
    service: 'exitmap-dns-health'
  }, 200, TTL.api),

  '/api/stats': async (ctx) => {
    const result = await getLatestData(ctx.env, ctx.origin, ctx.cache, ctx.waitUntil);
    if (!result) return jsonResponse({ error: 'Data unavailable' }, 503, 10);
    const { metadata = {} } = result.data;
    return jsonResponse({ metadata, source: result.source }, 200, TTL.api, result.cacheStatus);
  },

  '/api/failures': async (ctx) => {
    const result = await getLatestData(ctx.env, ctx.origin, ctx.cache, ctx.waitUntil);
    if (!result) return jsonResponse({ error: 'Data unavailable' }, 503, 10);
    const { metadata = {}, results = [] } = result.data;
    const failures = results.filter(r => r.status !== 'success');
    return jsonResponse({
      count: failures.length,
      timestamp: metadata.timestamp,
      failures,
      source: result.source
    }, 200, TTL.api, result.cacheStatus);
  },

  '/api/relays': async (ctx) => {
    const result = await getLatestData(ctx.env, ctx.origin, ctx.cache, ctx.waitUntil);
    if (!result) return jsonResponse({ error: 'Data unavailable' }, 503, 10);
    const { metadata = {}, results = [] } = result.data;
    const relays = results.map(r => ({
      fingerprint: r.exit_fingerprint,
      nickname: r.exit_nickname,
      status: r.status
    }));
    return jsonResponse({
      count: relays.length,
      timestamp: metadata.timestamp,
      relays,
      source: result.source
    }, 200, TTL.api, result.cacheStatus);
  },
};

// Handle /latest/{fingerprint} endpoint (from cb18)
const handleLatestFingerprint = async (ctx, fingerprint) => {
  const fp = normalizeFingerprint(fingerprint);
  if (!FINGERPRINT_RE.test(fp)) {
    return jsonResponse({
      error: 'Invalid fingerprint format',
      usage: '/latest/{40-character-hex-fingerprint}',
      example: '/latest/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    }, 400, 0);
  }

  const result = await getLatestData(ctx.env, ctx.origin, ctx.cache, ctx.waitUntil);
  if (!result) return jsonResponse({ error: 'Data unavailable' }, 503, 10);

  const { metadata = {}, results = [] } = result.data;
  const relay = results.find(r => normalizeFingerprint(r.exit_fingerprint) === fp);
  
  if (!relay) {
    return jsonResponse({ error: 'Relay not found', fingerprint: fp }, 404, TTL.api);
  }

  return jsonResponse({
    timestamp: metadata.timestamp,
    relay,
    source: result.source
  }, 200, TTL.api, result.cacheStatus);
};

// === Main Handler ===

export async function onRequest({ request, env, params, next, waitUntil }) {
  const url = new URL(request.url);
  const rawPath = url.pathname;

  // Handle CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: securityHeaders() });
  }

  // Context object for handlers
  const cache = caches.default;
  const ctx = { env, origin: url.origin, cache, waitUntil };

  // Check API handlers (DRY pattern from bc7f)
  const apiHandler = apiHandlers[rawPath];
  if (apiHandler) {
    return typeof apiHandler === 'function' ? apiHandler(ctx) : apiHandler;
  }

  // Handle /latest/{fingerprint} (from cb18)
  const fpMatch = rawPath.match(/^\/latest\/([A-Fa-f0-9]{40})$/i);
  if (fpMatch) {
    return handleLatestFingerprint(ctx, fpMatch[1]);
  }

  // Helpful error for malformed /latest/ requests (from cb18)
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

  // Try cache first (using helpers from 2260)
  const cacheKey = cacheRequest(url.origin, path);
  const cached = await cache.match(cacheKey);
  if (cached) return cacheHit(cached);

  // Fetch from storage backends
  const ttl = getCacheTTL(path, env);
  const res = await fetchFromStorage(env, path, ttl);
  if (res) return cacheAndReturn(cache, cacheKey, res, waitUntil);

  // Security: Don't leak requested path in error messages
  return jsonResponse({ error: 'Not found' }, 404, TTL.api);
}
