import { db } from '../database/connection.js';
import { createAuditor } from '../shared/audit.js';
import {
  verifyAccessToken,
  verifyServiceToken,
  bearerToken
} from './auth.js';

const audit = createAuditor(db, 'gateway');

export const endpointLabel = (req) => `${req.method} ${req.path}`;

const findUser = db.prepare(
  'SELECT id, username, role, nim FROM users WHERE id = ?'
);

const findDevice = db.prepare(`
  SELECT id FROM devices
  WHERE user_id = ? AND device_id = ? AND active = 1
`);

const fail = (status, error, reason, subject = null) =>
  ({ ok: false, status, error, reason, subject });

// Memverifikasi request dari USER: token JWT, device terdaftar, dan data
// user di database (role diambil dari database, bukan dipercaya dari token).
export function verifyUserRequest(req) {
  const deviceId = req.get('X-Device-ID')?.trim() || null;
  const token = bearerToken(req);

  if (!token) {
    return fail(401, 'Access token wajib disertakan.', 'Missing bearer token');
  }

  if (!deviceId) {
    return fail(403, 'X-Device-ID wajib disertakan.', 'Missing device ID');
  }

  let claims;

  try {
    claims = verifyAccessToken(token);
  } catch {
    return fail(
      401,
      'Access token tidak valid atau kedaluwarsa.',
      'Invalid or expired access token'
    );
  }

  const user = findUser.get(Number(claims.sub));

  if (!user) {
    return fail(401, 'Pengguna tidak ditemukan.', 'User no longer exists',
      claims.sub);
  }

  if (user.role !== claims.role) {
    return fail(
      401,
      'Token tidak sesuai dengan role terbaru. Silakan login ulang.',
      'Token role does not match database role',
      user.username
    );
  }

  if (!findDevice.get(user.id, deviceId)) {
    return fail(
      403,
      'Perangkat tidak terdaftar atau tidak aktif.',
      'Unregistered or inactive device',
      user.username
    );
  }

  return { ok: true, actor: user, deviceId };
}

// Memverifikasi request antar-SERVICE: hanya token service yang sah.
export function verifyServiceRequest(req) {
  const token = bearerToken(req);

  if (!token) {
    return fail(403, 'Service token wajib disertakan.',
      'Missing service token');
  }

  try {
    const claims = verifyServiceToken(token);
    return { ok: true, claims, subject: `service:${claims.service}` };
  } catch {
    return fail(
      403,
      'Service token tidak valid. Token user tidak diterima di sini.',
      'Invalid service token (user tokens are rejected)'
    );
  }
}

// Middleware untuk endpoint /auth/me dan /auth/admin-check.
export function authenticate(req, res, next) {
  const result = verifyUserRequest(req);

  if (!result.ok) {
    audit(result.subject, endpointLabel(req), req.get('X-Device-ID'),
      'deny', result.reason);
    return res.status(result.status).json({ error: result.error });
  }

  req.auth = {
    sub: String(result.actor.id),
    username: result.actor.username,
    role: result.actor.role
  };
  req.deviceId = result.deviceId;
  next();
}

export function authorize(...allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.auth.role)) {
      audit(req.auth.username, endpointLabel(req), req.deviceId, 'deny',
        `Role ${req.auth.role} not allowed`);

      return res.status(403).json({
        error: 'Role tidak memiliki izin untuk mengakses resource ini.'
      });
    }

    audit(req.auth.username, endpointLabel(req), req.deviceId, 'allow',
      'Role permitted');
    next();
  };
}
