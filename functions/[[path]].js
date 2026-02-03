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
const FINGERPRINT = /^[A-Fa-f0-9]{40}$/;

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
  if (path === LATEST_PATH || path === 'files.json') 
    return parseInt(env.CACHE_TTL_LATEST) || TTL.latest;
  return isImmutable(path) ? (parseInt(env.CACHE_TTL_HISTORICAL) || TTL.historical) : TTL.default;
};

const cacheRequest = (origin, path) =>
  new Request(`${origin}${path.startsWith('/') ? '' : '/'}${path}`);

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

const fetchFromStorage = async (env, path, ttl) => {
  const order = (env.STORAGE_ORDER || 'do,r2').split(',').map(s => s.trim());
  for (const backend of order) {
    const res = backend === 'do' ? await fetchDO(env, path, ttl) : 
                backend === 'r2' ? await fetchR2(env, path, ttl) : null;
    if (res) return res;
  }
  return null;
};

const loadLatestData = async (cache, url, env, waitUntil, ttl) => {
  const latestKey = cacheRequest(url.origin, LATEST_PATH);
  const cached = await cache.match(latestKey);
  if (cached) {
    try { return await cached.clone().json(); }
    catch {}
  }
  const res = await fetchFromStorage(env, LATEST_PATH, ttl);
  if (!res) return null;
  try {
    const data = await res.clone().json();
    waitUntil(cache.put(latestKey, res.clone()));
    return data;
  } catch { return null; }
};

const handleLatestRequest = async ({ url, rawPath, env, waitUntil }) => {
  const cache = caches.default;
  const cacheKey = cacheRequest(url.origin, rawPath);
  const cached = await cache.match(cacheKey);
  if (cached) return cacheHit(cached);

  const ttl = getCacheTTL(LATEST_PATH, env);
  const latest = await loadLatestData(cache, url, env, waitUntil, ttl);
  if (!latest) return jsonResponse({ error: 'Not found' }, 404, 60);

  const parts = rawPath.slice('/latest/'.length).split('/').filter(Boolean);
  if (parts.length !== 1) return jsonResponse({ error: 'Not found' }, 404, 60);
  let key = parts[0];
  try { key = decodeURIComponent(key); } catch {}

  const metadata = latest.metadata || {};
  const results = Array.isArray(latest.results) ? latest.results : [];
  const respond = (filtered) =>
    cacheAndReturn(cache, cacheKey, jsonResponse({ metadata, results: filtered }, 200, ttl), waitUntil);

  const lower = key.toLowerCase();
  if (lower === 'metadata') return respond([]);
  if (lower === 'failures') return respond(results.filter(r => r.status !== 'success'));
  if (!FINGERPRINT.test(key)) return jsonResponse({ error: 'Invalid fingerprint' }, 400, 60);

  const target = key.toUpperCase();
  const match = results.find(r => (r.exit_fingerprint || '').toUpperCase() === target);
  if (!match) return jsonResponse({ error: 'Fingerprint not found' }, 404, 60);
  return respond([match]);
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

  if (rawPath.startsWith('/latest/')) {
    return handleLatestRequest({ url, rawPath, env, waitUntil });
  }

  // Get clean path from params
  const path = getPath(params);
  
  // Pass through to static assets if not a proxy path
  if (!shouldProxy(path)) {
    return next();
  }

  // Try cache first
  const cache = caches.default;
  const cacheKey = cacheRequest(url.origin, path);
  const cached = await cache.match(cacheKey);
  if (cached) return cacheHit(cached);

  // Fetch from backends in order
  const ttl = getCacheTTL(path, env);
  const res = await fetchFromStorage(env, path, ttl);
  if (res) return cacheAndReturn(cache, cacheKey, res, waitUntil);

  // Security: Don't leak requested path in error messages
  return jsonResponse({ error: 'Not found' }, 404, 60);
}
