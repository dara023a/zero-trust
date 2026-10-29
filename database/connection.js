// Koneksi SQLite bersama (modul bawaan Node.js: node:sqlite).
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import '../shared/config.js';

const here = path.dirname(fileURLToPath(import.meta.url));

export const DB_PATH =
  process.env.DB_PATH || path.join(here, 'zero-trust.db');

export const db = new DatabaseSync(DB_PATH);

// WAL + busy_timeout: tiga proses (gateway, nilai, transkrip) menulis ke
// database yang sama, jadi perlu menunggu kunci alih-alih langsung gagal.
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA busy_timeout = 5000;
  PRAGMA foreign_keys = ON;
`);

// node:sqlite tidak punya db.transaction(), jadi dibuat manual.
export function runInTransaction(fn) {
  db.exec('BEGIN IMMEDIATE');

  try {
    const result = fn();
    db.exec('COMMIT');
    return result;
  } catch (error) {
    try { db.exec('ROLLBACK'); } catch { /* sudah di-rollback */ }
    throw error;
  }
}
