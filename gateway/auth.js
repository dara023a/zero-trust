import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { createHash, randomBytes } from 'node:crypto';
import { requireEnv } from '../shared/config.js';

requireEnv('JWT_SECRET');

const ISSUER = 'zero-trust-gateway';
const USER_AUDIENCE = 'zero-trust-api';
const SERVICE_AUDIENCE = 'zero-trust-transkrip';

// Hash palsu supaya waktu respons login sama baik username ada maupun tidak.
const DUMMY_HASH =
  '$2b$12$/bBtlNmQJtt4J5Dxzml28.niJqEhO1zaYQUowEyc/jJ3IHVRdbGH.';

export async function hashPassword(password) {
  return bcrypt.hash(password, 12);
}

export async function verifyPassword(password, hash) {
  if (!hash) {
    await bcrypt.compare(password, DUMMY_HASH);
    return false;
  }

  return bcrypt.compare(password, hash);
}

// ---------- Access token user (10 menit, berisi sub + role) ----------
export function createAccessToken(user) {
  return jwt.sign(
    { role: user.role },
    process.env.JWT_SECRET,
    {
      subject: String(user.id),
      expiresIn: process.env.ACCESS_TOKEN_TTL || '10m',
      issuer: ISSUER,
      audience: USER_AUDIENCE,
      algorithm: 'HS256'
    }
  );
}

export function verifyAccessToken(token) {
  return jwt.verify(token, process.env.JWT_SECRET, {
    issuer: ISSUER,
    audience: USER_AUDIENCE,
    algorithms: ['HS256']
  });
}

// ---------- Refresh token (acak, disimpan sebagai hash SHA-256) ----------
export function hashRefreshToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

export function createRefreshToken() {
  const token = randomBytes(32).toString('hex');
  return { token, tokenHash: hashRefreshToken(token) };
}

// ---------- Token service (5 menit, role: service) ----------
export function createServiceToken(serviceName) {
  if (serviceName !== 'nilai') {
    throw new Error('Nama service tidak diizinkan.');
  }

  return jwt.sign(
    {
      tokenType: 'service',
      service: serviceName,
      role: 'service'
    },
    process.env.JWT_SECRET,
    {
      subject: serviceName,
      expiresIn: '5m',
      issuer: ISSUER,
      audience: SERVICE_AUDIENCE,
      algorithm: 'HS256'
    }
  );
}

export function verifyServiceToken(token) {
  const claims = jwt.verify(token, process.env.JWT_SECRET, {
    issuer: ISSUER,
    audience: SERVICE_AUDIENCE,
    algorithms: ['HS256']
  });

  if (
    claims.tokenType !== 'service' ||
    claims.role !== 'service' ||
    claims.service !== 'nilai' ||
    claims.sub !== 'nilai'
  ) {
    throw new Error('Service token tidak diizinkan.');
  }

  return claims;
}

export function bearerToken(req) {
  const header = req.get('Authorization') ?? '';
  return header.startsWith('Bearer ') ? header.slice(7).trim() : '';
}
