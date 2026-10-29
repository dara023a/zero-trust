// Pengaman yang dipakai ulang oleh Service Nilai dan Service Transkrip.
// Prinsip: service TIDAK mempercayai gateway begitu saja. Selain gateway
// secret, service memverifikasi sendiri tanda tangan + masa berlaku token,
// lalu membaca ulang user dan device dari database.
import { timingSafeEqual } from 'node:crypto';
import { verifyAccessToken, bearerToken } from '../gateway/auth.js';

function secretMatches(provided, expected) {
  if (!provided || !expected) return false;

  const a = Buffer.from(provided);
  const b = Buffer.from(expected);

  return a.length === b.length && timingSafeEqual(a, b);
}

export function createGuards(db, audit) {
  const findUser = db.prepare(
    'SELECT id, username, role, nim FROM users WHERE id = ?'
  );

  const findDevice = db.prepare(`
    SELECT id FROM devices
    WHERE user_id = ? AND device_id = ? AND active = 1
  `);

  const label = (req) => `${req.method} ${req.path}`;

  // 1) Tolak request langsung yang tidak membawa gateway secret yang valid.
  function gatewayOnly(req, res, next) {
    if (!secretMatches(req.get('X-Gateway-Secret'),
      process.env.GATEWAY_SECRET)) {
      audit(null, label(req), req.get('X-Device-ID'), 'deny',
        'Missing or invalid gateway secret (direct access blocked)');

      return res.status(403).json({
        error: 'Permintaan bukan berasal dari Gateway tepercaya.'
      });
    }

    next();
  }

  // 2) Verifikasi ulang access token user + user + device dari database.
  function userAuth(req, res, next) {
    const deviceId = req.get('X-Device-ID')?.trim() || null;
    const token = bearerToken(req);

    const reject = (status, error, reason, subject = null) => {
      audit(subject, label(req), deviceId, 'deny', reason);
      return res.status(status).json({ error });
    };

    if (!token) {
      return reject(401, 'Access token wajib disertakan.',
        'Service: missing bearer token');
    }

    let claims;

    try {
      claims = verifyAccessToken(token);
    } catch {
      return reject(401, 'Access token tidak valid atau kedaluwarsa.',
        'Service: invalid or expired access token');
    }

    const user = findUser.get(Number(claims.sub));

    if (!user) {
      return reject(401, 'Pengguna tidak ditemukan.',
        'Service: user no longer exists', claims.sub);
    }

    if (user.role !== claims.role) {
      return reject(401, 'Token tidak sesuai dengan role terbaru.',
        'Service: token role does not match database role', user.username);
    }

    if (!deviceId || !findDevice.get(user.id, deviceId)) {
      return reject(403, 'Perangkat tidak terdaftar atau tidak aktif.',
        'Service: unregistered or inactive device', user.username);
    }

    req.actor = user;
    req.deviceId = deviceId;
    next();
  }

  return { gatewayOnly, userAuth };
}
