/**
 * Cloudflare Pages Function - Multi-Storage Data Proxy
 * Serves JSON/archive files from DO Spaces (primary) with R2 fallback.
 * Static assets (HTML/CSS/JS) pass through to Pages.
 * 
 * Adapted from aroivalidator-deploy for exitmap DNS health validation.
 */

// Cache TTLs in seconds
const TTL = { latest: 60, historical: 31536000, default: 300, api: 60 };
const LATEST_PATH = 'latest.json';
const FILES_PATH = 'files.json';
const FINGERPRINT_RE = /^[A-Fa-f0-9]{40}$/;

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

const storageOrder = (env) =>
  (env.STORAGE_ORDER || 'do,r2').split(',').map(s => s.trim()).filter(Boolean);

const cacheRequest = (origin, path) =>
  new Request(`${origin}${path.startsWith('/') ? '' : '/'}${path}`);

const cacheHit = (cached) => {
  const res = new Response(cached.body, cached);
  res.headers.set('X-Cache-Status', 'HIT');
  return res;
};

const cacheAndReturn = (cache, cacheKey, res, waitUntil, cacheStatus = 'MISS') => {
  waitUntil(cache.put(cacheKey, res.clone()));
  if (!res.headers.get('X-Cache-Status')) {
    res.headers.set('X-Cache-Status', cacheStatus);
  }
  return res;
};

const normalizeFingerprint = (value) => (value || '').toUpperCase();

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
  const order = storageOrder(env);
  for (const backend of order) {
    const res = backend === 'do' ? await fetchDO(env, path, ttl) : 
                backend === 'r2' ? await fetchR2(env, path, ttl) : null;
    if (res) return res;
  }
  return null;
};

let latestMemory = { data: null, derived: null, source: null, expiresAt: 0 };

const buildLatestDerived = (data) => {
  const metadata = data && typeof data === 'object' ? (data.metadata || {}) : {};
  const results = Array.isArray(data && data.results) ? data.results : [];
  const failures = [];
  const relays = [];
  const byFingerprint = new Map();

  for (const result of results) {
    const fingerprint = normalizeFingerprint(result && result.exit_fingerprint);
    if (fingerprint) {
      byFingerprint.set(fingerprint, result);
    }
    if (result && result.status !== 'success') {
      failures.push(result);
    }
    relays.push({
      fingerprint: result && result.exit_fingerprint,
      nickname: result && result.exit_nickname,
      status: result && result.status,
    });
  }

  return { metadata, results, failures, relays, byFingerprint };
};

const updateLatestMemory = (data, ttl, source) => {
  latestMemory = {
    data,
    derived: buildLatestDerived(data),
    source,
    expiresAt: Date.now() + ttl * 1000,
  };
  return latestMemory;
};

const getLatestData = async (env, origin, cache, waitUntil) => {
  const ttl = getCacheTTL(LATEST_PATH, env);
  const now = Date.now();

  if (latestMemory.data && latestMemory.expiresAt > now) {
    return { 
      data: latestMemory.data,
      derived: latestMemory.derived,
      source: latestMemory.source,
      ttl,
      cacheStatus: 'MEM',
    };
  }

  const cacheKey = cacheRequest(origin, LATEST_PATH);
  const cached = await cache.match(cacheKey);
  if (cached) {
    try {
      const data = await cached.clone().json();
      const source = cached.headers.get('X-Served-From') || 'cache';
      const memory = updateLatestMemory(data, ttl, source);
      return {
        data: memory.data,
        derived: memory.derived,
        source: memory.source,
        ttl,
        cacheStatus: 'HIT',
      };
    } catch {}
  }

  const res = await fetchFromStorage(env, LATEST_PATH, ttl);
  if (!res) return null;

  const source = res.headers.get('X-Served-From') || 'storage';
  waitUntil(cache.put(cacheKey, res.clone()));
  try {
    const data = await res.json();
    const memory = updateLatestMemory(data, ttl, source);
    return {
      data: memory.data,
      derived: memory.derived,
      source: memory.source,
      ttl,
      cacheStatus: 'MISS',
    };
  } catch {
    return null;
  }
};

const API_HANDLERS = {
  status: () => jsonResponse({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    service: 'exitmap-dns-health'
  }, 200, TTL.api),
  latest: (latest) => jsonResponse(latest.data || {}, 200, latest.ttl),
  'latest/metadata': (latest) => jsonResponse(latest.derived.metadata, 200, latest.ttl),
  'latest/results': (latest) => jsonResponse(latest.derived.results, 200, latest.ttl),
  summary: (latest) => jsonResponse({ 
    metadata: latest.derived.metadata,
    source: latest.source,
  }, 200, latest.ttl),
  stats: (latest) => jsonResponse({ 
    metadata: latest.derived.metadata,
    source: latest.source,
  }, 200, latest.ttl),
  failures: (latest) => jsonResponse({
    count: latest.derived.failures.length,
    timestamp: latest.derived.metadata.timestamp,
    failures: latest.derived.failures,
    source: latest.source,
  }, 200, latest.ttl),
  relays: (latest) => jsonResponse({
    count: latest.derived.relays.length,
    timestamp: latest.derived.metadata.timestamp,
    relays: latest.derived.relays,
    source: latest.source,
  }, 200, latest.ttl),
};

const handleApiRequest = async ({ rawPath, env, origin, cache, waitUntil }) => {
  if (!rawPath.startsWith('/api/')) return null;
  const apiPath = rawPath.slice('/api/'.length);
  const handler = API_HANDLERS[apiPath];
  if (!handler) return null;
  if (apiPath === 'status') return handler();

  const latest = await getLatestData(env, origin, cache, waitUntil);
  if (!latest) return jsonResponse({ error: 'Latest data unavailable' }, 503, TTL.api);
  const res = handler(latest);
  res.headers.set('X-Cache-Status', latest.cacheStatus);
  return res;
};

const handleLatestRequest = async ({ rawPath, env, origin, cache, waitUntil }) => {
  if (!rawPath.startsWith('/latest/')) return null;

  const parts = rawPath.slice('/latest/'.length).split('/').filter(Boolean);
  if (parts.length !== 1) {
    return jsonResponse({ error: 'Not found' }, 404, TTL.api);
  }

  let key = parts[0];
  try { key = decodeURIComponent(key); } catch {}
  const lower = key.toLowerCase();
  const isSpecial = lower === 'metadata' || lower === 'failures';

  if (!isSpecial && !FINGERPRINT_RE.test(key)) {
    return jsonResponse({ error: 'Invalid fingerprint' }, 400, TTL.api);
  }

  const latest = await getLatestData(env, origin, cache, waitUntil);
  if (!latest) return jsonResponse({ error: 'Latest data unavailable' }, 503, TTL.api);

  const respond = (results) => {
    const res = jsonResponse({ metadata: latest.derived.metadata, results }, 200, latest.ttl);
    res.headers.set('X-Cache-Status', latest.cacheStatus);
    return res;
  };

  if (lower === 'metadata') return respond([]);
  if (lower === 'failures') return respond(latest.derived.failures);

  const fingerprint = normalizeFingerprint(key);
  if (!FINGERPRINT_RE.test(fingerprint)) {
    return jsonResponse({ error: 'Invalid fingerprint' }, 400, TTL.api);
  }

  const match = latest.derived.byFingerprint.get(fingerprint);
  if (!match) {
    return jsonResponse({ error: 'Fingerprint not found' }, 404, latest.ttl);
  }

  return respond([match]);
};

export async function onRequest({ request, env, params, next, waitUntil }) {
  const url = new URL(request.url);
  const rawPath = url.pathname;

  // Handle CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: securityHeaders() });
  }

  const apiResponse = await handleApiRequest({
    rawPath,
    env,
    origin: url.origin,
    cache: caches.default,
    waitUntil,
  });
  if (apiResponse) return apiResponse;

  const latestResponse = await handleLatestRequest({
    rawPath,
    env,
    origin: url.origin,
    cache: caches.default,
    waitUntil,
  });
  if (latestResponse) return latestResponse;

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
