/**
 * Cloudflare Pages Function - Multi-Storage Data Proxy
 * Serves JSON/archive files from DO Spaces (primary) with R2 fallback.
 * Static assets (HTML/CSS/JS) pass through to Pages.
 * 
 * Adapted from aroivalidator-deploy for exitmap DNS health validation.
 */

// Cache TTLs in seconds
const TTL = { latest: 60, historical: 31536000, default: 300 };
const LATEST_PATH = 'latest.json';
const FILES_PATH = 'files.json';
const FINGERPRINT_RE = /^[a-fA-F0-9]{40}$/;

// Security: Pattern to detect traversal attempts (encoded or raw)
const UNSAFE_PATH = /(?:^|\/)\.\.(?:\/|$)|%2e|%00|\x00/i;

// Valid proxy paths pattern - strictly validate filenames
// Matches: dns_health_YYYY-MM-DD_HH-MM-SS.json, latest.json, files.json, archives/exitmap-YYYYMM.tar.gz
const PROXY_PATH = /^(?:archives\/exitmap-\d{6}\.tar\.gz|(?:dns_health_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}|latest|files)\.json)$/;

const getPath = (params) => {
  const p = Array.isArray(params.path) ? params.path.join('/') : (params.path || '');
  // Normalize: remove leading slash and empty/dot segments in one pass
  const cleaned = p.replace(/^\/+/, '').split('/').filter(s => s && s !== '.').join('/');
  // Security: reject paths with traversal attempts
  return UNSAFE_PATH.test(cleaned) ? '' : cleaned;
};

const shouldProxy = (path) => path && PROXY_PATH.test(path);

// Immutable files: timestamped validation files and archives (but not latest.json/files.json)
const isImmutable = (path) => /^(?:dns_health_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.json|archives\/)/.test(path);

const getCacheTTL = (path, env) => {
  if (path === LATEST_PATH || path === FILES_PATH)
    return parseInt(env.CACHE_TTL_LATEST) || TTL.latest;
  return isImmutable(path) ? (parseInt(env.CACHE_TTL_HISTORICAL) || TTL.historical) : TTL.default;
};

const normalizeFingerprint = (value) => (value || '').toUpperCase();

const API_LATEST_HANDLERS = {
  'latest': (data) => data || {},
  'latest/metadata': (data) => (data && data.metadata) || {},
  'latest/results': (data) => (data && data.results) || [],
};

let latestMemory = { data: null, expiresAt: 0 };

const securityHeaders = () => ({
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
});

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

const jsonResponse = (data, status, ttl = 0) => {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': ttl > 0 ? `public, max-age=${ttl}` : 'no-cache',
      ...securityHeaders(),
    },
  });
};

const fetchDO = async (env, path, ttl) => {
  if (!env.DO_SPACES_URL) return null;
  try {
    const res = await fetch(`${env.DO_SPACES_URL.replace(/\/$/, '')}/${path}`);
    return res.ok ? makeResponse(res.body, path, 'digitalocean-spaces', ttl) : null;
  } catch { return null; }
};

const fetchR2 = async (env, path, ttl) => {
  if (!env.EXITMAP_BUCKET) return null;
  try {
    const obj = await env.EXITMAP_BUCKET.get(path);
    return obj ? makeResponse(obj.body, path, 'cloudflare-r2', ttl) : null;
  } catch { return null; }
};

const fetchFromBackends = async (env, path, ttl) => {
  const order = (env.STORAGE_ORDER || 'do,r2').split(',').map(s => s.trim()).filter(Boolean);
  for (const backend of order) {
    const res = backend === 'do' ? await fetchDO(env, path, ttl) :
                backend === 'r2' ? await fetchR2(env, path, ttl) : null;
    if (res) return res;
  }
  return null;
};

const getLatestData = async (env, origin, cache, waitUntil) => {
  const ttl = getCacheTTL(LATEST_PATH, env);
  const now = Date.now();
  if (latestMemory.data && latestMemory.expiresAt > now) {
    return { data: latestMemory.data, ttl, cacheStatus: 'MEM' };
  }

  const cacheKey = new Request(`${origin}/${LATEST_PATH}`);
  const cached = await cache.match(cacheKey);
  if (cached) {
    try {
      const data = await cached.json();
      latestMemory = { data, expiresAt: now + ttl * 1000 };
      return { data, ttl, cacheStatus: 'HIT' };
    } catch {}
  }

  const res = await fetchFromBackends(env, LATEST_PATH, ttl);
  if (!res) return null;
  waitUntil(cache.put(cacheKey, res.clone()));
  try {
    const data = await res.clone().json();
    latestMemory = { data, expiresAt: now + ttl * 1000 };
    return { data, ttl, cacheStatus: 'MISS' };
  } catch {
    return null;
  }
};

export async function onRequest({ request, env, params, next, waitUntil }) {
  const url = new URL(request.url);
  const rawPath = url.pathname;

  // Handle CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: securityHeaders() });
  }

  // Health check endpoint
  if (rawPath === '/api/status') {
    return jsonResponse({ 
      status: 'ok', 
      timestamp: new Date().toISOString(),
      service: 'exitmap-dns-health'
    }, 200, 60);
  }

  // Get clean path from params
  const path = getPath(params);
  const cache = caches.default;
  const origin = url.origin;
  const segments = path ? path.split('/') : [];

  // Latest result for a specific fingerprint
  if (segments[0] === 'latest' && segments.length === 2) {
    const fingerprint = segments[1];
    if (!FINGERPRINT_RE.test(fingerprint)) {
      return jsonResponse({ error: 'Invalid fingerprint' }, 400, 60);
    }
    const latest = await getLatestData(env, origin, cache, waitUntil);
    if (!latest || !latest.data || !Array.isArray(latest.data.results)) {
      return jsonResponse({ error: 'Latest data unavailable' }, 503, 60);
    }
    const target = normalizeFingerprint(fingerprint);
    const result = latest.data.results.find(r => normalizeFingerprint(r.exit_fingerprint) === target);
    if (!result) {
      return jsonResponse({ error: 'Fingerprint not found' }, 404, latest.ttl);
    }
    const res = jsonResponse(result, 200, latest.ttl);
    res.headers.set('X-Cache-Status', latest.cacheStatus);
    return res;
  }

  // Simple API endpoints based on latest.json
  const apiPath = path.startsWith('api/') ? path.slice(4) : '';
  const apiHandler = API_LATEST_HANDLERS[apiPath];
  if (apiHandler) {
    const latest = await getLatestData(env, origin, cache, waitUntil);
    if (!latest) {
      return jsonResponse({ error: 'Latest data unavailable' }, 503, 60);
    }
    const res = jsonResponse(apiHandler(latest.data), 200, latest.ttl);
    res.headers.set('X-Cache-Status', latest.cacheStatus);
    return res;
  }
  
  // Pass through to static assets if not a proxy path
  if (!shouldProxy(path)) {
    return next();
  }

  // Try cache first
  const cacheKey = new Request(origin + '/' + path);
  const cached = await cache.match(cacheKey);
  if (cached) {
    const res = new Response(cached.body, cached);
    res.headers.set('X-Cache-Status', 'HIT');
    return res;
  }

  // Fetch from backends in order
  const ttl = getCacheTTL(path, env);
  const res = await fetchFromBackends(env, path, ttl);
  if (res) {
    waitUntil(cache.put(cacheKey, res.clone()));
    res.headers.set('X-Cache-Status', 'MISS');
    return res;
  }

  // Security: Don't leak requested path in error messages
  return jsonResponse({ error: 'Not found' }, 404, 60);
}
