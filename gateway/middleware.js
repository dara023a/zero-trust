import { DatabaseSync } from 'node:sqlite';
import { verifyAccessToken } from './auth.js';

const db = new DatabaseSync('database/zero-trust.db');

function audit(subject, endpoint, deviceId, decision, reason) {
  db.prepare(`
    INSERT INTO audit_logs
      (subject, endpoint, device_id, decision, reason)
    VALUES (?, ?, ?, ?, ?)
  `).run(subject, endpoint, deviceId, decision, reason);
}

export function authenticate(req, res, next) {
  const endpoint = req.originalUrl;
  const deviceId = req.get('X-Device-ID');
  const authorization = req.get('Authorization');

  if (!authorization?.startsWith('Bearer ')) {
    audit(
      null, endpoint, deviceId ?? null,
      'deny', 'Missing bearer token'
    );

    return res.status(401).json({
      error: 'Access token wajib disertakan.'
    });
  }

  if (!deviceId?.trim()) {
    audit(
      null, endpoint, null,
      'deny', 'Missing device ID'
    );

    return res.status(403).json({
      error: 'X-Device-ID wajib disertakan.'
    });
  }

  const token = authorization.slice(7).trim();

  if (!token) {
    return res.status(401).json({
      error: 'Access token tidak valid.'
    });
  }

  let claims;

  try {
    claims = verifyAccessToken(token);
  } catch {
    audit(
      null, endpoint, deviceId,
      'deny', 'Invalid or expired access token'
    );

    return res.status(401).json({
      error: 'Access token tidak valid atau kedaluwarsa.'
    });
  }

  try {
    const user = db.prepare(`
      SELECT id, username, role
      FROM users
      WHERE id = ?
    `).get(Number(claims.sub));

    if (!user) {
      audit(
        claims.sub, endpoint, deviceId,
        'deny', 'User no longer exists'
      );

      return res.status(401).json({
        error: 'Pengguna tidak ditemukan.'
      });
    }

    const device = db.prepare(`
      SELECT id FROM devices
      WHERE user_id = ?
        AND device_id = ?
        AND active = 1
    `).get(user.id, deviceId);

    if (!device) {
      audit(
        user.username, endpoint, deviceId,
        'deny', 'Unregistered or inactive device'
      );

      return res.status(403).json({
        error: 'Perangkat tidak terdaftar atau tidak aktif.'
      });
    }

    req.auth = {
      sub: String(user.id),
      username: user.username,
      role: user.role
    };

    req.deviceId = deviceId;

    audit(
      user.username, endpoint, deviceId,
      'allow', 'Token and device verified'
    );

    next();
  } catch (error) {
    console.error('Authentication error:', error.message);

    return res.status(500).json({
      error: 'Terjadi kesalahan internal.'
    });
  }
}

export function authorize(...allowedRoles) {
  return (req, res, next) => {
    if (!req.auth) {
      return res.status(401).json({
        error: 'Autentikasi diperlukan.'
      });
    }

    if (!allowedRoles.includes(req.auth.role)) {
      return res.status(403).json({
        error: 'Role tidak memiliki izin untuk mengakses resource ini.'
      });
    }

    next();
  };
}
