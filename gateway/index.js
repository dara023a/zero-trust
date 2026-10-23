import 'dotenv/config';
import express from 'express';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { authenticate, authorize } from './middleware.js';
import { createServiceToken, verifyServiceToken } from './auth.js';
import { timingSafeEqual } from 'node:crypto';
import {
  verifyPassword,
  createAccessToken,
  verifyAccessToken,
  createRefreshToken
} from './auth.js';

const app = express();
const PORT = 3000;
const db = new DatabaseSync('database/zero-trust.db');

db.exec('PRAGMA foreign_keys = ON;');
app.use(express.json({ limit: '20kb' }));

function gatewaySecretMatches(provided) {
  const expected = process.env.GATEWAY_SECRET;

  if (!provided || !expected) return false;

  const a = Buffer.from(provided);
  const b = Buffer.from(expected);

  return a.length === b.length && timingSafeEqual(a, b);
}

function hashToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

function audit(subject, endpoint, deviceId, decision, reason) {
  db.prepare(`
    INSERT INTO audit_logs
      (subject, endpoint, device_id, decision, reason)
    VALUES (?, ?, ?, ?, ?)
  `).run(subject, endpoint, deviceId, decision, reason);
}

function issueRefreshToken(userId) {
  const { token, tokenHash } = createRefreshToken();
  const expiresAt = new Date(
    Date.now() + 24 * 60 * 60 * 1000
  ).toISOString();

  db.prepare(`
    INSERT INTO refresh_tokens
      (user_id, token_hash, expires_at)
    VALUES (?, ?, ?)
  `).run(userId, tokenHash, expiresAt);

  return token;
}

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'zero-trust-gateway',
    timestamp: new Date().toISOString()
  });
});

app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body ?? {};
  const deviceId = req.get('X-Device-ID');

  if (
    typeof username !== 'string' ||
    typeof password !== 'string' ||
    typeof deviceId !== 'string' ||
    !deviceId.trim()
  ) {
    audit(
      username ?? null,
      '/auth/login',
      deviceId ?? null,
      'deny',
      'Missing credentials or device ID'
    );

    return res.status(400).json({
      error: 'Username, password, dan X-Device-ID wajib diisi.'
    });
  }

  try {
    const user = db.prepare(`
      SELECT id, username, password_hash, role
      FROM users
      WHERE username = ?
    `).get(username);

    const passwordValid = user
      ? await verifyPassword(password, user.password_hash)
      : false;

    if (!user || !passwordValid) {
      audit(
        username,
        '/auth/login',
        deviceId,
        'deny',
        'Invalid credentials'
      );

      return res.status(401).json({
        error: 'Username atau password salah.'
      });
    }

    const device = db.prepare(`
      SELECT id FROM devices
      WHERE user_id = ? AND device_id = ? AND active = 1
    `).get(user.id, deviceId);

    if (!device) {
      audit(
        username,
        '/auth/login',
        deviceId,
        'deny',
        'Unregistered or inactive device'
      );

      return res.status(403).json({
        error: 'Perangkat belum terdaftar atau tidak aktif.'
      });
    }

    const accessToken = createAccessToken(user);
    const refreshToken = issueRefreshToken(user.id);

    audit(
      username,
      '/auth/login',
      deviceId,
      'allow',
      'Login successful'
    );

    return res.json({
      message: 'Login berhasil.',
      accessToken,
      refreshToken,
      tokenType: 'Bearer',
      expiresIn: 600,
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error.message);
    return res.status(500).json({
      error: 'Terjadi kesalahan internal.'
    });
  }
});

app.post('/auth/refresh', (req, res) => {
  const { refreshToken } = req.body ?? {};
  const deviceId = req.get('X-Device-ID');

  if (
    typeof refreshToken !== 'string' ||
    typeof deviceId !== 'string' ||
    !deviceId.trim()
  ) {
    return res.status(400).json({
      error: 'Refresh token dan X-Device-ID wajib diisi.'
    });
  }

  try {
    const tokenHash = hashToken(refreshToken);

    const stored = db.prepare(`
      SELECT rt.id, rt.user_id, rt.expires_at, u.username, u.role
      FROM refresh_tokens rt
      JOIN users u ON u.id = rt.user_id
      WHERE rt.token_hash = ? AND rt.revoked = 0
    `).get(tokenHash);

    if (!stored || Date.parse(stored.expires_at) <= Date.now()) {
      if (stored) {
        db.prepare(`
          UPDATE refresh_tokens SET revoked = 1 WHERE id = ?
        `).run(stored.id);
      }

      audit(
        stored?.username ?? null,
        '/auth/refresh',
        deviceId,
        'deny',
        'Invalid or expired refresh token'
      );

      return res.status(401).json({
        error: 'Refresh token tidak valid atau sudah kedaluwarsa.'
      });
    }

    const device = db.prepare(`
      SELECT id FROM devices
      WHERE user_id = ? AND device_id = ? AND active = 1
    `).get(stored.user_id, deviceId);

    if (!device) {
      audit(
        stored.username,
        '/auth/refresh',
        deviceId,
        'deny',
        'Unregistered or inactive device'
      );

      return res.status(403).json({
        error: 'Perangkat tidak terdaftar atau tidak aktif.'
      });
    }

    const newRefresh = createRefreshToken();
    const expiresAt = new Date(
      Date.now() + 24 * 60 * 60 * 1000
    ).toISOString();

    const rotate = db.transaction(() => {
      const result = db.prepare(`
        UPDATE refresh_tokens
        SET revoked = 1
        WHERE id = ? AND revoked = 0
      `).run(stored.id);

      if (result.changes !== 1) {
        throw new Error('Refresh token already used');
      }

      db.prepare(`
        INSERT INTO refresh_tokens
          (user_id, token_hash, expires_at)
        VALUES (?, ?, ?)
      `).run(
        stored.user_id,
        newRefresh.tokenHash,
        expiresAt
      );
    });

    try {
      rotate();
    } catch {
      return res.status(401).json({
        error: 'Refresh token sudah digunakan atau tidak valid.'
      });
    }

    const accessToken = createAccessToken({
      id: stored.user_id,
      role: stored.role
    });

    audit(
      stored.username,
      '/auth/refresh',
      deviceId,
      'allow',
      'Tokens refreshed'
    );

    return res.json({
      accessToken,
      refreshToken: newRefresh.token,
      tokenType: 'Bearer',
      expiresIn: 600
    });
  } catch (error) {
    console.error('Refresh error:', error.message);
    return res.status(500).json({
      error: 'Terjadi kesalahan internal.'
    });
  }
});

app.post('/auth/logout', (req, res) => {
  const { refreshToken } = req.body ?? {};
  const deviceId = req.get('X-Device-ID');

  if (typeof refreshToken !== 'string' || !refreshToken) {
    return res.status(400).json({
      error: 'Refresh token wajib diisi.'
    });
  }

  try {
    const result = db.prepare(`
      UPDATE refresh_tokens
      SET revoked = 1
      WHERE token_hash = ? AND revoked = 0
    `).run(hashToken(refreshToken));

    audit(
      null,
      '/auth/logout',
      deviceId ?? null,
      result.changes ? 'allow' : 'deny',
      result.changes
        ? 'Refresh token revoked'
        : 'Refresh token not found or already revoked'
    );

    return res.json({
      message: 'Logout diproses. Refresh token tidak dapat digunakan kembali.'
    });
  } catch (error) {
    console.error('Logout error:', error.message);
    return res.status(500).json({
      error: 'Terjadi kesalahan internal.'
    });
  }
});

app.get('/auth/me', authenticate, (req, res) => {
  res.json({
    message: 'Identitas berhasil diverifikasi.',
    user: req.auth,
    deviceId: req.deviceId
  });
});

app.get(
  '/auth/admin-check',
  authenticate,
  authorize('admin'),
  (req, res) => {
    res.json({
      message: 'Akses admin diizinkan.',
      user: req.auth
    });
  }
);

app.use('/nilai', authenticate, async (req, res) => {
  try {
    const targetUrl =
      `http://127.0.0.1:3001${req.originalUrl}`;

    const headers = {
      'X-Gateway-Secret': process.env.GATEWAY_SECRET,
      'X-User-Id': req.auth.sub,
      'X-User-Role': req.auth.role,
      'X-Username': req.auth.username
    };

    if (req.is('application/json')) {
      headers['Content-Type'] = 'application/json';
    }

    const options = {
      method: req.method,
      headers
    };

    if (!['GET', 'HEAD'].includes(req.method)) {
      options.body = JSON.stringify(req.body ?? {});
    }

    const upstream = await fetch(targetUrl, options);
    const responseText = await upstream.text();

    res.status(upstream.status);

    if (upstream.headers.get('content-type')) {
      res.set(
        'Content-Type',
        upstream.headers.get('content-type')
      );
    }

    res.send(responseText);
  } catch (error) {
    console.error('Service Nilai error:', error.message);

    res.status(502).json({
      error: 'Service Nilai tidak dapat dihubungi.'
    });
  }
});


app.post('/auth/service', (req, res) => {
  if (!gatewaySecretMatches(req.get('X-Gateway-Secret'))) {
    return res.status(403).json({
      error: 'Pemanggil service tidak terverifikasi.'
    });
  }

  const serviceName = req.get('X-Service-Name');

  if (serviceName !== 'nilai') {
    return res.status(403).json({
      error: 'Service tidak diizinkan meminta token.'
    });
  }

  return res.json({
    accessToken: createServiceToken('nilai'),
    tokenType: 'Bearer',
    expiresIn: 300
  });
});

app.post('/internal/transkrip/sinkron', async (req, res) => {
  if (!gatewaySecretMatches(req.get('X-Gateway-Secret'))) {
    return res.status(403).json({
      error: 'Pemanggil service tidak terverifikasi.'
    });
  }

  const authorization = req.get('Authorization') ?? '';
  const token = authorization.startsWith('Bearer ')
    ? authorization.slice(7).trim()
    : '';

  try {
    if (!token) throw new Error('Token wajib diisi.');
    verifyServiceToken(token);
  } catch {
    return res.status(403).json({
      error: 'Service token tidak valid.'
    });
  }

  try {
    const upstream = await fetch(
      'http://127.0.0.1:3002/sinkron',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Gateway-Secret': process.env.GATEWAY_SECRET,
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify(req.body ?? {})
      }
    );

    const responseText = await upstream.text();

    res.status(upstream.status);
    res.type(
      upstream.headers.get('content-type') || 'application/json'
    );
    res.send(responseText);
  } catch (error) {
    console.error('Transcript sync error:', error.message);

    res.status(502).json({
      error: 'Service Transkrip tidak dapat dihubungi.'
    });
  }
});

app.use('/transkrip', authenticate, async (req, res) => {
  try {
    const servicePath =
      req.originalUrl.replace(/^\/transkrip/, '') || '/';

    const upstream = await fetch(
      `http://127.0.0.1:3002${servicePath}`,
      {
        method: req.method,
        headers: {
          'X-Gateway-Secret': process.env.GATEWAY_SECRET,
          'X-User-Id': req.auth.sub,
          'X-User-Role': req.auth.role,
          'X-Username': req.auth.username
        }
      }
    );

    const responseText = await upstream.text();

    res.status(upstream.status);
    res.type(
      upstream.headers.get('content-type') || 'application/json'
    );
    res.send(responseText);
  } catch (error) {
    console.error('Transcript service error:', error.message);

    res.status(502).json({
      error: 'Service Transkrip tidak dapat dihubungi.'
    });
  }
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`API Gateway berjalan di http://127.0.0.1:${PORT}`);
});
