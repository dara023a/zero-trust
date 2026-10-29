// Membuat/melengkapi file .env tanpa menimpa nilai yang sudah ada dan
// tanpa menampilkan secret.   npm run setup
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, appendFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { PROJECT_ROOT } from '../shared/config.js';

const envPath = path.join(PROJECT_ROOT, '.env');
const secret = () => randomBytes(32).toString('hex');

const DEFAULTS = {
  JWT_SECRET: secret,
  GATEWAY_SECRET: secret,
  SERVICE_CLIENT_ID: () => 'service-nilai',
  SERVICE_CLIENT_SECRET: secret,
  ACCESS_HOUR_START: () => '7',
  ACCESS_HOUR_END: () => '21',
  ACCESS_TZ: () => 'Asia/Jakarta'
};

if (!existsSync(envPath)) writeFileSync(envPath, '', { mode: 0o600 });

const current = readFileSync(envPath, 'utf8');
const present = new Set(
  current.split('\n')
    .map((line) => line.match(/^\s*([A-Z0-9_]+)\s*=/)?.[1])
    .filter(Boolean)
);

const added = [];
let block = current && !current.endsWith('\n') ? '\n' : '';

for (const [key, make] of Object.entries(DEFAULTS)) {
  if (!present.has(key)) {
    block += `${key}=${make()}\n`;
    added.push(key);
  }
}

if (added.length) appendFileSync(envPath, block);

console.log(
  added.length
    ? `.env dilengkapi. Variabel ditambahkan: ${added.join(', ')}`
    : '.env sudah lengkap. Tidak ada yang diubah.'
);
