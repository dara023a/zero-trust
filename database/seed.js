import 'dotenv/config';
import { DatabaseSync } from 'node:sqlite';
import { hashPassword } from '../gateway/auth.js';

const db = new DatabaseSync('database/zero-trust.db');

const accounts = [
  {
    username: 'student01',
    password: 'DevMahasiswa123!',
    role: 'mahasiswa',
    deviceId: 'HP-STUDENT-01'
  },
  {
    username: 'dosen01',
    password: 'DevDosen123!',
    role: 'dosen',
    deviceId: 'HP-DOSEN-01'
  },
  {
    username: 'admin01',
    password: 'DevAdmin123!',
    role: 'admin',
    deviceId: 'HP-ADMIN-01'
  }
];

try {
  const insertUser = db.prepare(`
    INSERT OR IGNORE INTO users (username, password_hash, role)
    VALUES (?, ?, ?)
  `);

  const getUser = db.prepare(
    'SELECT id FROM users WHERE username = ?'
  );

  const insertDevice = db.prepare(`
    INSERT OR IGNORE INTO devices (user_id, device_id)
    VALUES (?, ?)
  `);

  for (const account of accounts) {
    const passwordHash = await hashPassword(account.password);

    insertUser.run(
      account.username,
      passwordHash,
      account.role
    );

    const user = getUser.get(account.username);
    insertDevice.run(user.id, account.deviceId);
  }

  console.log('Akun pengujian berhasil disiapkan.');
  console.log('Username dan device ID:');

  for (const account of accounts) {
    console.log(
      `${account.username} | ${account.deviceId}`
    );
  }
} finally {
  db.close();
}
