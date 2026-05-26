/**
 * NexTalk Security Middleware
 * Drop this file into your project root and require it in your server entry point:
 *   const security = require('./security');
 *   security.apply(app);  // call before any routes
 */

'use strict';

// ─── In-memory rate limit store ───────────────────────────────────────────────
// For multi-instance deployments, swap this Map with a Redis client.
const loginAttempts = new Map(); // key: IP → { count, firstAttempt, blockedUntil }

const RATE_LIMIT = {
  windowMs: 15 * 60 * 1000,   // 15-minute window
  maxAttempts: 10,             // max failed logins per window
  blockDurationMs: 30 * 60 * 1000, // block for 30 min after limit hit
};

// Clean up stale entries every 10 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of loginAttempts.entries()) {
    if (now - data.firstAttempt > RATE_LIMIT.windowMs && !data.blockedUntil) {
      loginAttempts.delete(ip);
    } else if (data.blockedUntil && now > data.blockedUntil) {
      loginAttempts.delete(ip);
    }
  }
}, 10 * 60 * 1000);

// ─── Helpers ──────────────────────────────────────────────────────────────────
function getClientIp(req) {
  // Trust Railway's / reverse-proxy forwarded IP
  const forwarded = req.headers['x-forwarded-for'];
  return forwarded ? forwarded.split(',')[0].trim() : req.socket.remoteAddress;
}

function recordFailedLogin(ip) {
  const now = Date.now();
  const entry = loginAttempts.get(ip) || { count: 0, firstAttempt: now, blockedUntil: null };

  // Reset window if expired
  if (now - entry.firstAttempt > RATE_LIMIT.windowMs && !entry.blockedUntil) {
    entry.count = 0;
    entry.firstAttempt = now;
  }

  entry.count += 1;

  if (entry.count >= RATE_LIMIT.maxAttempts) {
    entry.blockedUntil = now + RATE_LIMIT.blockDurationMs;
  }

  loginAttempts.set(ip, entry);
  return entry;
}

function isBlocked(ip) {
  const entry = loginAttempts.get(ip);
  if (!entry || !entry.blockedUntil) return false;
  if (Date.now() > entry.blockedUntil) {
    loginAttempts.delete(ip);
    return false;
  }
  return true;
}

function clearFailedLogins(ip) {
  loginAttempts.delete(ip);
}

// ─── Middleware factories ──────────────────────────────────────────────────────

/**
 * 1. Secure HTTP headers
 *    Adds CSP, HSTS, X-Frame-Options, etc.
 */
function secureHeaders() {
  return function (req, res, next) {
    // Force HTTPS in production
    if (process.env.NODE_ENV === 'production' && req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect(301, 'https://' + req.headers.host + req.originalUrl);
    }

    // Strict-Transport-Security (1 year, include subdomains)
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');

    // Prevent clickjacking
    res.setHeader('X-Frame-Options', 'DENY');

    // Stop MIME sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');

    // XSS filter (legacy browsers)
    res.setHeader('X-XSS-Protection', '1; mode=block');

    // Referrer policy
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

    // Permissions policy — disable unused browser features
    res.setHeader(
      'Permissions-Policy',
      'camera=(), microphone=(), geolocation=(), payment=()'
    );

    // Content Security Policy
    // Adjust 'connect-src' if you use external Socket.io or API hosts
    res.setHeader(
      'Content-Security-Policy',
      [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",          // tighten if you can use nonces
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com",
        "img-src 'self' data: blob:",
        "connect-src 'self' wss: ws:",                // allow WebSocket (Socket.io)
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
      ].join('; ')
    );

    // Remove server fingerprinting
    res.removeHeader('X-Powered-By');

    next();
  };
}

/**
 * 2. Login rate-limit guard
 *    Wrap your login route handler with this.
 *
 *    Usage:
 *      app.post('/api/login', loginRateLimit(), async (req, res) => { ... });
 *
 *    On success, call req.loginSuccess() to reset the counter.
 *    On failure, call req.loginFailure() to increment it.
 */
function loginRateLimit() {
  return function (req, res, next) {
    const ip = getClientIp(req);

    if (isBlocked(ip)) {
      const entry = loginAttempts.get(ip);
      const retryAfterSec = Math.ceil((entry.blockedUntil - Date.now()) / 1000);
      res.setHeader('Retry-After', retryAfterSec);
      return res.status(429).json({
        error: 'Too many login attempts. Please try again later.',
        retryAfter: retryAfterSec,
      });
    }

    // Attach helpers so the route handler can signal outcome
    req.loginSuccess = () => clearFailedLogins(ip);
    req.loginFailure = () => recordFailedLogin(ip);

    next();
  };
}

/**
 * 3. General API rate limiter (optional, broader protection)
 *    Limits every IP to `maxRequests` per `windowMs` on any route.
 */
function generalRateLimit({ windowMs = 60_000, maxRequests = 100 } = {}) {
  const store = new Map(); // ip → { count, windowStart }

  setInterval(() => {
    const now = Date.now();
    for (const [ip, data] of store.entries()) {
      if (now - data.windowStart > windowMs) store.delete(ip);
    }
  }, windowMs);

  return function (req, res, next) {
    const ip = getClientIp(req);
    const now = Date.now();
    const entry = store.get(ip) || { count: 0, windowStart: now };

    if (now - entry.windowStart > windowMs) {
      entry.count = 0;
      entry.windowStart = now;
    }

    entry.count += 1;
    store.set(ip, entry);

    if (entry.count > maxRequests) {
      res.setHeader('Retry-After', Math.ceil(windowMs / 1000));
      return res.status(429).json({ error: 'Rate limit exceeded. Slow down.' });
    }

    next();
  };
}

// ─── apply() convenience helper ───────────────────────────────────────────────
/**
 * Call security.apply(app) once at server startup.
 * Then use security.loginRateLimit() on your /login route.
 */
function apply(app) {
  app.use(secureHeaders());
  app.use(generalRateLimit({ windowMs: 60_000, maxRequests: 200 }));
  console.log('[NexTalk Security] Secure headers + rate limiting active.');
}

module.exports = { apply, secureHeaders, loginRateLimit, generalRateLimit };