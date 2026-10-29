// API Gateway = Policy Enforcement Point (PEP), port 3000.
// Satu-satunya pintu masuk: memeriksa setiap request, meminta keputusan ke
// Policy Engine (policy.js), mencatat audit log, lalu meneruskan ke service.
import { timingSafeEqual } from 'node:crypto';
import express from 'express';
import { db, runInTransaction } from '../database/connection.js';
import { createAuditor } from '../shared/audit.js';
import { requireEnv, URLS } from '../shared/config.js';
import {
  verifyPassword,
  createAccessToken,
  createRefreshToken,
  hashRefreshToken,
  createServiceToken
} from './auth.js';
import {
  authenticate,
  authorize,
  verifyUserRequest,
  verifyServiceRequest,
  endpointLabel
} from './middleware.js';
import { matchRoute, decideUser, decideService } from './policy.js';

requireEnv(
  'JWT_SECRET', 'GATEWAY_SECRET',
  'SERVICE_CLIENT_ID', 'SERVICE_CLIENT_SECRET'
);

const PORT = 3000;
const REFRESH_TTL_MS = 24 * 60 * 60 * 1000; // 1 hari
const audit = createAuditor(db, 'gateway');

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '20kb' }));

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || !a || !b) {
    return false;
  }

  const x = Buffer.from(a);
  const y = Buffer.from(b);

  return x.length === y.length && timingSafeEqual(x, y);
}

// Pembatasan percobaan login (5 gagal / 5 menit per username).
const failedLogins = new Map();
const MAX_FAILS = 5;
const FAIL_WINDOW_MS = 5 * 60 * 1000;

function isLockedOut(username) {
  const entry = failedLogins.get(username);
  if (!entry) return false;

  if (Date.now() - entry.first > FAIL_WINDOW_MS) {
    failedLogins.delete(username);
    return false;
  }

  return entry.count >= MAX_FAILS;
}

function recordFailure(username) {
  const entry = failedLogins.get(username);

  if (!entry || Date.now() - entry.first > FAIL_WINDOW_MS) {
    failedLogins.set(username, { count: 1, first: Date.now() });
  } else {
    entry.count += 1;
  }
}

const insertRefresh = db.prepare(`
  INSERT INTO refresh_tokens (user_id, token_hash, device_id, expires_at)
  VALUES (?, ?, ?, ?)
`);

function issueRefreshToken(userId, deviceId) {
  const { token, tokenHash } = createRefreshToken();
  const expiresAt = new Date(Date.now() + REFRESH_TTL_MS).toISOString();

  insertRefresh.run(userId, tokenHash, deviceId, expiresAt);
  return token;
}

const deviceOk = db.prepare(`
  SELECT id FROM devices WHERE user_id = ? AND device_id = ? AND active = 1
`);

// ============================ ENDPOINT /auth ============================

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'zero-trust-gateway',
    timestamp: new Date().toISOString()
  });
});

app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body ?? {};
  const deviceId = req.get('X-Device-ID')?.trim();
  const ep = endpointLabel(req);

  if (
    typeof username !== 'string' || typeof password !== 'string' || !deviceId
  ) {
    audit(typeof username === 'string' ? username : null, ep,
      deviceId ?? null, 'deny', 'Missing credentials or device ID');

    return res.status(400).json({
      error: 'Username, password, dan X-Device-ID wajib diisi.'
    });
  }

  if (isLockedOut(username)) {
    audit(username, ep, deviceId, 'deny', 'Too many failed logins');

    return res.status(429).json({
      error: 'Terlalu banyak percobaan gagal. Coba lagi beberapa menit lagi.'
    });
  }

  const user = db.prepare(`
    SELECT id, username, password_hash, role, nim
    FROM users WHERE username = ?
  `).get(username);

  const passwordValid = await verifyPassword(password, user?.password_hash);

  if (!user || !passwordValid) {
    recordFailure(username);
    audit(username, ep, deviceId, 'deny', 'Invalid credentials');

    return res.status(401).json({ error: 'Username atau password salah.' });
  }

  if (!deviceOk.get(user.id, deviceId)) {
    audit(username, ep, deviceId, 'deny', 'Unregistered or inactive device');

    return res.status(403).json({
      error: 'Perangkat belum terdaftar atau tidak aktif.'
    });
  }

  failedLogins.delete(username);

  const accessToken = createAccessToken(user);
  const refreshToken = issueRefreshToken(user.id, deviceId);

  audit(username, ep, deviceId, 'allow', 'Login successful');

  res.json({
    message: 'Login berhasil.',
    accessToken,
    refreshToken,
    tokenType: 'Bearer',
    expiresIn: 600,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      nim: user.nim
    }
  });
});

app.post('/auth/refresh', (req, res) => {
  const { refreshToken } = req.body ?? {};
  const deviceId = req.get('X-Device-ID')?.trim();
  const ep = endpointLabel(req);

  if (typeof refreshToken !== 'string' || !refreshToken || !deviceId) {
    audit(null, ep, deviceId ?? null, 'deny',
      'Missing refresh token or device ID');

    return res.status(400).json({
      error: 'Refresh token dan X-Device-ID wajib diisi.'
    });
  }

  const stored = db.prepare(`
    SELECT rt.id, rt.user_id, rt.device_id, rt.expires_at, rt.revoked,
           u.username, u.role
    FROM refresh_tokens rt
    JOIN users u ON u.id = rt.user_id
    WHERE rt.token_hash = ?
  `).get(hashRefreshToken(refreshToken));

  if (!stored || stored.revoked) {
    // Refresh token yang sudah dipakai/dicabut lalu muncul lagi = indikasi
    // pencurian. Semua refresh token milik user tersebut dicabut.
    if (stored?.revoked) {
      db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?')
        .run(stored.user_id);
    }

    audit(stored?.username ?? null, ep, deviceId, 'deny',
      stored ? 'Refresh token reuse or revoked' : 'Unknown refresh token');

    return res.status(401).json({
      error: 'Refresh token tidak valid atau sudah dicabut.'
    });
  }

  if (Date.parse(stored.expires_at) <= Date.now()) {
    db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE id = ?')
      .run(stored.id);
    audit(stored.username, ep, deviceId, 'deny', 'Refresh token expired');

    return res.status(401).json({
      error: 'Refresh token sudah kedaluwarsa.'
    });
  }

  if (stored.device_id !== deviceId || !deviceOk.get(stored.user_id, deviceId)) {
    audit(stored.username, ep, deviceId, 'deny',
      'Refresh token used from a different or inactive device');

    return res.status(403).json({
      error: 'Perangkat tidak sesuai dengan sesi atau tidak aktif.'
    });
  }

  const next = createRefreshToken();

  try {
    // Rotasi: token lama dicabut, token baru diterbitkan (atomik).
    runInTransaction(() => {
      const result = db.prepare(`
        UPDATE refresh_tokens SET revoked = 1
        WHERE id = ? AND revoked = 0
      `).run(stored.id);

      if (result.changes !== 1) throw new Error('already used');

      insertRefresh.run(
        stored.user_id,
        next.tokenHash,
        deviceId,
        new Date(Date.now() + REFRESH_TTL_MS).toISOString()
      );
    });
  } catch {
    audit(stored.username, ep, deviceId, 'deny', 'Refresh token race/reuse');

    return res.status(401).json({
      error: 'Refresh token sudah digunakan atau tidak valid.'
    });
  }

  audit(stored.username, ep, deviceId, 'allow', 'Tokens refreshed (rotated)');

  res.json({
    accessToken: createAccessToken({ id: stored.user_id, role: stored.role }),
    refreshToken: next.token,
    tokenType: 'Bearer',
    expiresIn: 600
  });
});

app.post('/auth/logout', (req, res) => {
  const { refreshToken } = req.body ?? {};
  const deviceId = req.get('X-Device-ID')?.trim() ?? null;
  const ep = endpointLabel(req);

  if (typeof refreshToken !== 'string' || !refreshToken) {
    audit(null, ep, deviceId, 'deny', 'Missing refresh token');

    return res.status(400).json({ error: 'Refresh token wajib diisi.' });
  }

  const hash = hashRefreshToken(refreshToken);

  const owner = db.prepare(`
    SELECT u.username FROM refresh_tokens rt
    JOIN users u ON u.id = rt.user_id WHERE rt.token_hash = ?
  `).get(hash);

  const result = db.prepare(`
    UPDATE refresh_tokens SET revoked = 1
    WHERE token_hash = ? AND revoked = 0
  `).run(hash);

  audit(
    owner?.username ?? null, ep, deviceId,
    result.changes ? 'allow' : 'deny',
    result.changes
      ? 'Refresh token revoked'
      : 'Refresh token not found or already revoked'
  );

  if (!result.changes) {
    return res.status(401).json({
      error: 'Refresh token tidak valid atau sudah dicabut.'
    });
  }

  res.json({ message: 'Logout berhasil. Refresh token telah dicabut.' });
});

app.get('/auth/me', authenticate, (req, res) => {
  res.json({
    message: 'Identitas berhasil diverifikasi.',
    user: req.auth,
    deviceId: req.deviceId
  });
});

app.get('/auth/admin-check', authenticate, authorize('admin'),
  (req, res) => {
    res.json({ message: 'Akses admin diizinkan.', user: req.auth });
  }
);

// Token service: client ID + secret (bukan token user).
app.post('/auth/service', (req, res) => {
  const { clientId, clientSecret } = req.body ?? {};
  const ep = endpointLabel(req);

  const valid =
    safeEqual(clientId, process.env.SERVICE_CLIENT_ID) &&
    safeEqual(clientSecret, process.env.SERVICE_CLIENT_SECRET);

  if (!valid) {
    audit(typeof clientId === 'string' ? `client:${clientId}` : null, ep,
      null, 'deny', 'Invalid service client credentials');

    return res.status(403).json({
      error: 'Client ID atau secret tidak valid.'
    });
  }

  audit('service:nilai', ep, null, 'allow', 'Service token issued');

  res.json({
    accessToken: createServiceToken('nilai'),
    tokenType: 'Bearer',
    role: 'service',
    expiresIn: 300
  });
});

// ================== PEP: semua request ke resource ==================

async function forward(req, res, route, deviceId) {
  const headers = {
    'X-Gateway-Secret': process.env.GATEWAY_SECRET
  };

  // Header identitas dari client TIDAK diteruskan. Service memverifikasi
  // sendiri token yang dibawa di Authorization.
  if (req.get('Authorization')) {
    headers.Authorization = req.get('Authorization');
  }

  if (deviceId) headers['X-Device-ID'] = deviceId;

  const options = { method: req.method, headers };

  if (!['GET', 'HEAD'].includes(req.method)) {
    headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(req.body ?? {});
  }

  options.signal = AbortSignal.timeout(10_000);

  try {
    const upstream = await fetch(`${URLS[route.target]}${req.path}`, options);
    const text = await upstream.text();

    res.status(upstream.status);
    res.type(upstream.headers.get('content-type') || 'application/json');
    res.send(text);
  } catch (error) {
    console.error(`Service ${route.target} error:`, error.message);

    res.status(502).json({
      error: `Service ${route.target} tidak dapat dihubungi.`
    });
  }
}

app.use(async (req, res) => {
  const ep = endpointLabel(req);
  const route = matchRoute(req.method, req.path);

  if (!route) {
    audit(null, ep, req.get('X-Device-ID'), 'deny',
      'Unknown endpoint or method (default deny)');

    return res.status(404).json({ error: 'Endpoint tidak ditemukan.' });
  }

  // ----- Jalur service-to-service (hanya token service) -----
  if (route.service) {
    const result = verifyServiceRequest(req);

    if (!result.ok) {
      audit(result.subject, ep, null, 'deny', result.reason);
      return res.status(result.status).json({ error: result.error });
    }

    const decision = decideService(route, result.claims);
    audit(result.subject, ep, null,
      decision.allow ? 'allow' : 'deny', decision.reason);

    if (!decision.allow) {
      return res.status(decision.status).json({ error: decision.message });
    }

    return forward(req, res, route, null);
  }

  // ----- Jalur user: token + device + kebijakan -----
  const result = verifyUserRequest(req);

  if (!result.ok) {
    audit(result.subject, ep, req.get('X-Device-ID'), 'deny', result.reason);
    return res.status(result.status).json({ error: result.error });
  }

  const decision = decideUser(route, result.actor);

  audit(result.actor.username, ep, result.deviceId,
    decision.allow ? 'allow' : 'deny', decision.reason);

  if (!decision.allow) {
    return res.status(decision.status).json({ error: decision.message });
  }

  return forward(req, res, route, result.deviceId);
});

app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Body JSON tidak valid.' });
  }

  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Body terlalu besar.' });
  }

  console.error('Gateway error:', err.message);
  res.status(500).json({ error: 'Terjadi kesalahan internal.' });
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`API Gateway berjalan di http://127.0.0.1:${PORT}`);
});
