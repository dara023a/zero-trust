// Seed akun + device: 1 admin, 2 dosen, 3 mahasiswa (masing-masing 1 device).
// Aman dijalankan berulang (INSERT OR IGNORE).   npm run seed
import { db } from './connection.js';
import { hashPassword } from '../gateway/auth.js';

export const ACCOUNTS = [
  { username: 'admin01',   password: 'DevAdmin123!',      role: 'admin',
    deviceId: 'HP-ADMIN-01' },
  { username: 'dosen01',   password: 'DevDosen123!',      role: 'dosen',
    deviceId: 'HP-DOSEN-01' },
  { username: 'dosen02',   password: 'DevDosen223!',      role: 'dosen',
    deviceId: 'HP-DOSEN-02' },
  { username: 'student01', password: 'DevMahasiswa123!',  role: 'mahasiswa',
    nim: '2210001', deviceId: 'HP-STUDENT-01' },
  { username: 'student02', password: 'DevMahasiswa223!',  role: 'mahasiswa',
    nim: '2210002', deviceId: 'HP-STUDENT-02' },
  { username: 'student03', password: 'DevMahasiswa323!',  role: 'mahasiswa',
    nim: '2210003', deviceId: 'HP-STUDENT-03' }
];

const insertUser = db.prepare(`
  INSERT OR IGNORE INTO users (username, password_hash, role, nim)
  VALUES (?, ?, ?, ?)
`);
const setNim = db.prepare(
  'UPDATE users SET nim = ? WHERE username = ? AND nim IS NULL'
);
const getUser = db.prepare('SELECT id FROM users WHERE username = ?');
const insertDevice = db.prepare(`
  INSERT OR IGNORE INTO devices (user_id, device_id) VALUES (?, ?)
`);

try {
  for (const account of ACCOUNTS) {
    const exists = getUser.get(account.username);

    // Hash bcrypt hanya dihitung bila akun belum ada (hemat waktu di HP).
    if (!exists) {
      insertUser.run(
        account.username,
        await hashPassword(account.password),
        account.role,
        account.nim ?? null
      );
    }

    if (account.nim) setNim.run(account.nim, account.username);

    insertDevice.run(getUser.get(account.username).id, account.deviceId);
  }

  console.log('Akun dan device demo siap:');
  for (const a of ACCOUNTS) {
    console.log(
      `${a.username.padEnd(10)} ${a.role.padEnd(10)} ` +
      `${(a.nim ?? '-').padEnd(8)} ${a.deviceId}`
    );
  }
} finally {
  db.close();
}
