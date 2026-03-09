/**
 * Shared constants and utilities for Cloudflare Pages Functions
 * 
 * Used by:
 *   - [[path]].js (content serving)
 *   - search.js (search functionality)
 */

// =============================================================================
// MIME TYPES
// =============================================================================

export const MIME_TYPES = Object.freeze({
  html: 'text/html; charset=utf-8',
  css: 'text/css',
  js: 'application/javascript',
  json: 'application/json',
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  svg: 'image/svg+xml',
  ico: 'image/x-icon',
  webp: 'image/webp',
  woff: 'font/woff',
  woff2: 'font/woff2',
  ttf: 'font/ttf',
  txt: 'text/plain',
  xml: 'application/xml',
  pdf: 'application/pdf',
});

export const CONTENT_TYPE_HTML = MIME_TYPES.html;

export const STATIC_EXTENSIONS = Object.freeze([
  'css', 'js', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'webp', 'woff', 'woff2', 'ttf'
]);

// =============================================================================
// SECURITY HEADERS
// =============================================================================

// Content Security Policy - restrictive by default
const CSP_POLICY = [
  "default-src 'self'",
  "style-src 'self' 'unsafe-inline'",  // Allow inline styles for generated pages
  "img-src 'self' data:",
  "script-src 'none'",                  // No scripts on generated pages
  "frame-ancestors 'none'",
  "form-action 'self'",
  "base-uri 'self'",
].join('; ');

// Security headers for HTML responses
export const SECURITY_HEADERS_HTML = Object.freeze({
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Content-Security-Policy': CSP_POLICY,
});

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Get file extension from path
 * @param {string} path - File path
 * @returns {string} Lowercase extension without dot
 */
export function getExtension(path) {
  return path.split('.').pop()?.toLowerCase() || '';
}

/**
 * Get MIME type for a file path
 * @param {string} path - File path
 * @returns {string} MIME type
 */
export function getMimeType(path) {
  // Prometheus metrics endpoint (no file extension)
  if (path === 'metrics' || path.endsWith('/metrics')) {
    return 'text/plain; version=0.0.4; charset=utf-8';
  }
  return MIME_TYPES[getExtension(path)] || 'application/octet-stream';
}

/**
 * Check if path is a static asset (long cache TTL)
 * @param {string} path - File path
 * @returns {boolean}
 */
export function isStaticAsset(path) {
  return STATIC_EXTENSIONS.includes(getExtension(path));
}

// =============================================================================
// HTML ESCAPING (XSS Prevention)
// =============================================================================

const HTML_ESCAPE_MAP = Object.freeze({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#x27;',
});

const HTML_ESCAPE_RE = /[&<>"']/g;

/**
 * Escape HTML special characters to prevent XSS
 * @param {*} s - Value to escape (converted to string)
 * @returns {string} Escaped string
 */
export function escapeHtml(s) {
  if (s == null) return '';
  return String(s).replace(HTML_ESCAPE_RE, c => HTML_ESCAPE_MAP[c]);
}

