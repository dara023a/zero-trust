// Konfigurasi bersama untuk gateway, service nilai, dan service transkrip.
// Memuat .env dari root project (tidak bergantung pada folder tempat perintah dijalankan).
import { config } from 'dotenv';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

export const PROJECT_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..'
);

config({ path: path.join(PROJECT_ROOT, '.env'), quiet: true });

export function requireEnv(...names) {
  const missing = names.filter((name) => !process.env[name]);

  if (missing.length > 0) {
    throw new Error(
      `Variabel .env belum diatur: ${missing.join(', ')}. ` +
      'Jalankan: npm run setup'
    );
  }
}

export const URLS = {
  gateway: process.env.GATEWAY_URL || 'http://127.0.0.1:3000',
  nilai: process.env.NILAI_URL || 'http://127.0.0.1:3001',
  transkrip: process.env.TRANSKRIP_URL || 'http://127.0.0.1:3002'
};

// ---------- Jam akses (4.3) ----------
// Dapat diatur lewat .env: ACCESS_HOUR_START, ACCESS_HOUR_END, ACCESS_TZ.
// Jendela waktu: START <= jam < END. Default 07.00 sampai sebelum 21.00 WIB.
export function getAccessWindow() {
  const start = Number(process.env.ACCESS_HOUR_START ?? 7);
  const end = Number(process.env.ACCESS_HOUR_END ?? 21);

  if (
    !Number.isFinite(start) || !Number.isFinite(end) ||
    start < 0 || start > 24 || end < 0 || end > 24
  ) {
    throw new Error('ACCESS_HOUR_START/ACCESS_HOUR_END harus angka 0-24.');
  }

  return {
    start,
    end,
    timeZone: process.env.ACCESS_TZ || 'Asia/Jakarta'
  };
}

function hourInZone(date, timeZone) {
  try {
    const parts = new Intl.DateTimeFormat('en-GB', {
      hour: '2-digit',
      minute: '2-digit',
      hourCycle: 'h23',
      timeZone
    }).formatToParts(date);

    const hour = Number(parts.find((p) => p.type === 'hour').value);
    const minute = Number(parts.find((p) => p.type === 'minute').value);

    return hour + minute / 60;
  } catch {
    // Zona waktu tidak dikenali: pakai jam lokal perangkat.
    return date.getHours() + date.getMinutes() / 60;
  }
}

export function withinAccessHours(date = new Date()) {
  const { start, end, timeZone } = getAccessWindow();
  const hour = hourInZone(date, timeZone);

  return start <= end
    ? hour >= start && hour < end
    : hour >= start || hour < end; // jendela melewati tengah malam
}

export function accessWindowLabel() {
  const { start, end, timeZone } = getAccessWindow();
  const pad = (n) => String(n).padStart(2, '0');
  return `${pad(start)}.00-${pad(end)}.00 (${timeZone})`;
}
