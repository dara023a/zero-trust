import 'dotenv/config';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { createHash, randomBytes } from 'node:crypto';

if (!process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET belum diatur di .env');
}

export async function hashPassword(password) {
  return bcrypt.hash(password, 12);
}

export async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

export function createAccessToken(user) {
  return jwt.sign(
    {
      role: user.role
    },
    process.env.JWT_SECRET,
    {
      subject: String(user.id),
      expiresIn: process.env.ACCESS_TOKEN_TTL || '10m',
      issuer: 'zero-trust-gateway',
      audience: 'zero-trust-api'
    }
  );
}

export function verifyAccessToken(token) {
  return jwt.verify(token, process.env.JWT_SECRET, {
    issuer: 'zero-trust-gateway',
    audience: 'zero-trust-api'
  });
}

export function createRefreshToken() {
  const token = randomBytes(32).toString('hex');

  return {
    token,
    tokenHash: createHash('sha256').update(token).digest('hex')
  };
}

export function createServiceToken(serviceName) {
  if (serviceName !== 'nilai') {
    throw new Error('Nama service tidak diizinkan.');
  }

  return jwt.sign(
    {
      tokenType: 'service',
      service: serviceName
    },
    process.env.JWT_SECRET,
    {
      subject: serviceName,
      expiresIn: '5m',
      issuer: 'zero-trust-gateway',
      audience: 'zero-trust-transkrip'
    }
  );
}

export function verifyServiceToken(token) {
  const claims = jwt.verify(token, process.env.JWT_SECRET, {
    issuer: 'zero-trust-gateway',
    audience: 'zero-trust-transkrip'
  });

  if (
    claims.tokenType !== 'service' ||
    claims.service !== 'nilai' ||
    claims.sub !== 'nilai'
  ) {
    throw new Error('Service token tidak diizinkan.');
  }

  return claims;
}
