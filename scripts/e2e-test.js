// Pengujian positif & negatif otomatis. Jalankan SETELAH ketiga layanan hidup:
//   npm run test:e2e
import jwt from 'jsonwebtoken';
import { URLS, withinAccessHours, accessWindowLabel } from '../shared/config.js';
import { db } from '../database/connection.js';

const GW = URLS.gateway;
const inHours = withinAccessHours();
let pass = 0;
let fail = 0;

async function call(method, url, { token, device, body, headers = {} } = {}) {
  const h = { ...headers };
  if (token) h.Authorization = `Bearer ${token}`;
  if (device) h['X-Device-ID'] = device;
  if (body !== undefined) h['Content-Type'] = 'application/json';

  const res = await fetch(url, {
    method,
    headers: h,
    body: body !== undefined ? JSON.stringify(body) : undefined
  });

  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}

function check(name, actual, expected) {
  const ok = Array.isArray(expected)
    ? expected.includes(actual) : actual === expected;

  if (ok) pass += 1; else fail += 1;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}  (status ${actual}, harapan ${expected})`);
}

const USERS = {
  admin01: ['DevAdmin123!', 'HP-ADMIN-01'],
  dosen01: ['DevDosen123!', 'HP-DOSEN-01'],
  dosen02: ['DevDosen223!', 'HP-DOSEN-02'],
  student01: ['DevMahasiswa123!', 'HP-STUDENT-01'],
  student02: ['DevMahasiswa223!', 'HP-STUDENT-02'],
  student03: ['DevMahasiswa323!', 'HP-STUDENT-03']
};

const sessions = {};

async function login(name) {
  const [password, device] = USERS[name];
  const r = await call('POST', `${GW}/auth/login`, {
    device, body: { username: name, password }
  });
  return { ...r, device };
}

console.log(`Jam akses saat ini: ${accessWindowLabel()} -> ${inHours ? 'DIBUKA' : 'DITUTUP'}\n`);

// ---------- Autentikasi & device ----------
console.log('== Autentikasi dan device ==');
check('GET /health', (await call('GET', `${GW}/health`)).status, 200);

for (const name of Object.keys(USERS)) {
  const r = await login(name);
  check(`login ${name}`, r.status, 200);
  sessions[name] = { token: r.json.accessToken, refresh: r.json.refreshToken, device: r.device };
}

check('login password salah',
  (await call('POST', `${GW}/auth/login`, {
    device: 'HP-STUDENT-01', body: { username: 'student01', password: 'salah' }
  })).status, 401);

check('login device tidak terdaftar',
  (await call('POST', `${GW}/auth/login`, {
    device: 'HP-ASING', body: { username: 'student01', password: USERS.student01[0] }
  })).status, 403);

check('login tanpa X-Device-ID',
  (await call('POST', `${GW}/auth/login`, {
    body: { username: 'student01', password: USERS.student01[0] }
  })).status, 400);

const s1 = sessions.student01;
check('/auth/me tanpa token', (await call('GET', `${GW}/auth/me`, { device: s1.device })).status, 401);
check('/auth/me token sampah', (await call('GET', `${GW}/auth/me`, { token: 'abc.def.ghi', device: s1.device })).status, 401);
check('/auth/me device milik user lain', (await call('GET', `${GW}/auth/me`, { token: s1.token, device: 'HP-DOSEN-01' })).status, 403);
check('/auth/me tanpa device', (await call('GET', `${GW}/auth/me`, { token: s1.token })).status, 403);
check('/auth/me valid', (await call('GET', `${GW}/auth/me`, { token: s1.token, device: s1.device })).status, 200);

const expired = jwt.sign({ role: 'mahasiswa' }, process.env.JWT_SECRET, {
  subject: '1', expiresIn: -60, issuer: 'zero-trust-gateway', audience: 'zero-trust-api'
});
check('access token kedaluwarsa', (await call('GET', `${GW}/nilai`, { token: expired, device: s1.device })).status, 401);

const forged = jwt.sign({ role: 'admin' }, 'secret-palsu', {
  subject: '1', expiresIn: '10m', issuer: 'zero-trust-gateway', audience: 'zero-trust-api'
});
check('token ditandatangani secret palsu', (await call('GET', `${GW}/nilai`, { token: forged, device: s1.device })).status, 401);

const roleForged = jwt.sign({ role: 'admin' }, process.env.JWT_SECRET, {
  subject: String(db.prepare("SELECT id FROM users WHERE username='student01'").get().id),
  expiresIn: '10m', issuer: 'zero-trust-gateway', audience: 'zero-trust-api'
});
check('role di token tidak cocok dengan database', (await call('GET', `${GW}/auth/me`, { token: roleForged, device: s1.device })).status, 401);

check('/auth/admin-check oleh mahasiswa', (await call('GET', `${GW}/auth/admin-check`, { token: s1.token, device: s1.device })).status, 403);
check('/auth/admin-check oleh admin', (await call('GET', `${GW}/auth/admin-check`, { token: sessions.admin01.token, device: sessions.admin01.device })).status, 200);

// ---------- Refresh & logout ----------
console.log('\n== Refresh token dan logout ==');
const extra = await login('student03');
const r1 = await call('POST', `${GW}/auth/refresh`, { device: 'HP-STUDENT-03', body: { refreshToken: extra.json.refreshToken } });
check('refresh valid (rotasi)', r1.status, 200);
check('refresh token lama dipakai ulang', (await call('POST', `${GW}/auth/refresh`, { device: 'HP-STUDENT-03', body: { refreshToken: extra.json.refreshToken } })).status, 401);
check('refresh token baru ikut dicabut setelah reuse terdeteksi', (await call('POST', `${GW}/auth/refresh`, { device: 'HP-STUDENT-03', body: { refreshToken: r1.json.refreshToken } })).status, 401);

const lo = await login('student03');
check('refresh dari device lain', (await call('POST', `${GW}/auth/refresh`, { device: 'HP-STUDENT-01', body: { refreshToken: lo.json.refreshToken } })).status, 403);
check('logout', (await call('POST', `${GW}/auth/logout`, { device: 'HP-STUDENT-03', body: { refreshToken: lo.json.refreshToken } })).status, 200);
check('refresh setelah logout', (await call('POST', `${GW}/auth/refresh`, { device: 'HP-STUDENT-03', body: { refreshToken: lo.json.refreshToken } })).status, 401);
const re3 = await login("student03");
sessions.student03 = { token: re3.json.accessToken, device: "HP-STUDENT-03" };

// ---------- GET /nilai ----------
console.log('\n== GET /nilai ==');
const g = (n) => call('GET', `${GW}/nilai`, { token: sessions[n].token, device: sessions[n].device });
const gs1 = await g('student01');
check('mahasiswa melihat nilai', gs1.status, 200);
check('nilai mahasiswa hanya milik sendiri (2 baris)', gs1.json.grades?.length, 2);
const gd1 = await g('dosen01');
check('dosen01 melihat nilai', gd1.status, 200);
check('dosen01 hanya kelas IF101', gd1.json.grades?.every((x) => x.code === 'IF101') ? 'ok' : 'bocor', 'ok');
const gd2 = await g('dosen02');
check('dosen02 hanya kelas IF102', gd2.json.grades?.every((x) => x.code === 'IF102') ? 'ok' : 'bocor', 'ok');
check('admin tidak boleh GET /nilai', (await g('admin01')).status, 403);
check('GET /nilai tanpa token', (await call('GET', `${GW}/nilai`, { device: 'HP-STUDENT-01' })).status, 401);

// ---------- PUT /nilai/:id ----------
console.log('\n== PUT /nilai/:id ==');
const put = (n, id, score) => call('PUT', `${GW}/nilai/${id}`, {
  token: sessions[n].token, device: sessions[n].device, body: { score }
});
const ownIF101 = gd1.json.grades.find((x) => x.student === 'student03');
const ownIF102 = gd2.json.grades.find((x) => x.student === 'student03');

check('mahasiswa tidak boleh ubah nilai', (await put('student01', ownIF101.gradeId, 100)).status, 403);
check('dosen01 ubah nilai kelas dosen02', (await put('dosen01', ownIF102.gradeId, 100)).status, 403);
check('dosen02 ubah nilai kelas dosen01', (await put('dosen02', ownIF101.gradeId, 100)).status, 403);
check('ubah nilai id tidak ada', (await put('dosen01', 99999, 80)).status, 403);
check(`dosen01 ubah nilai kelas sendiri (${inHours ? 'dalam' : 'luar'} jam akses)`,
  (await put('dosen01', ownIF101.gradeId, 66)).status, inHours ? 200 : 403);
if (inHours) {
  check('nilai di luar rentang 0-100', (await put('dosen01', ownIF101.gradeId, 150)).status, 400);
  check('nilai bukan angka', (await put('dosen01', ownIF101.gradeId, 'A')).status, 400);
}

// ---------- Finalisasi + sinkron ----------
console.log('\n== POST /kelas/:id/finalisasi ==');
const IF101 = db.prepare("SELECT id FROM courses WHERE code='IF101'").get().id;
const IF102 = db.prepare("SELECT id FROM courses WHERE code='IF102'").get().id;
const fin = (n, id) => call('POST', `${GW}/kelas/${id}/finalisasi`, {
  token: sessions[n].token, device: sessions[n].device, body: {}
});

check('mahasiswa tidak boleh finalisasi', (await fin('student01', IF102)).status, 403);
check('dosen01 finalisasi kelas dosen02', (await fin('dosen01', IF102)).status, 403);
const f = await fin('dosen02', IF102);
check(`dosen02 finalisasi IF102 (${inHours ? 'dalam' : 'luar'} jam akses)`, f.status, inHours ? 200 : 403);

if (inHours) {
  check('sinkron transkrip ikut berjalan', f.json.transcriptSync?.syncedCount, 3);
  check('ubah nilai yang sudah final', (await put('dosen02', ownIF102.gradeId, 50)).status, 409);
  check('finalisasi ulang idempotent', (await fin('dosen02', IF102)).status, 200);
}

// ---------- Transkrip ----------
console.log('\n== GET /transkrip/:nim ==');
const tr = (n, nim) => call('GET', `${GW}/transkrip/${nim}`, {
  token: sessions[n].token, device: sessions[n].device
});

const own = await tr('student01', '2210001');
check('mahasiswa lihat transkrip sendiri', own.status, 200);
if (inHours) check('transkrip berisi hasil sinkron (IF102)', own.json.courses?.some((c) => c.code === 'IF102') ? 'ada' : 'kosong', 'ada');
check('mahasiswa lihat transkrip NIM lain', (await tr('student01', '2210002')).status, 403);
check('dosen lihat transkrip', (await tr('dosen01', '2210001')).status, 403);
check('admin lihat transkrip NIM mana pun', (await tr('admin01', '2210002')).status, 200);
check('admin NIM tidak ada', (await tr('admin01', '9999999')).status, 404);
check('admin lihat semua transkrip', (await call('GET', `${GW}/transkrip`, { token: sessions.admin01.token, device: 'HP-ADMIN-01' })).status, 200);
check('dosen GET /transkrip', (await call('GET', `${GW}/transkrip`, { token: sessions.dosen01.token, device: 'HP-DOSEN-01' })).status, 403);

// ---------- Service token & akses langsung ----------
console.log('\n== Token service, gateway secret, akses langsung ==');
check('/auth/service client salah', (await call('POST', `${GW}/auth/service`, { body: { clientId: 'x', clientSecret: 'y' } })).status, 403);
const st = await call('POST', `${GW}/auth/service`, {
  body: { clientId: process.env.SERVICE_CLIENT_ID, clientSecret: process.env.SERVICE_CLIENT_SECRET }
});
check('/auth/service client benar', st.status, 200);
const svc = st.json.accessToken;

check('sinkron dengan token service', (await call('POST', `${GW}/transkrip/sinkron`, { token: svc, body: { courseId: IF101 } })).status, 200);
check('sinkron dengan token user (mahasiswa)', (await call('POST', `${GW}/transkrip/sinkron`, { token: sessions.student01.token, device: 'HP-STUDENT-01', body: { courseId: IF101 } })).status, 403);
check('sinkron dengan token dosen', (await call('POST', `${GW}/transkrip/sinkron`, { token: sessions.dosen01.token, device: 'HP-DOSEN-01', body: { courseId: IF101 } })).status, 403);
check('sinkron tanpa token', (await call('POST', `${GW}/transkrip/sinkron`, { body: { courseId: IF101 } })).status, 403);
check('token service dipakai di GET /nilai', (await call('GET', `${GW}/nilai`, { token: svc, device: 'HP-DOSEN-01' })).status, 401);

const secret = { 'X-Gateway-Secret': process.env.GATEWAY_SECRET };
check('akses langsung Nilai tanpa gateway secret', (await call('GET', `${URLS.nilai}/nilai`)).status, 403);
check('akses langsung Transkrip tanpa gateway secret', (await call('GET', `${URLS.transkrip}/transkrip`)).status, 403);
check('gateway secret salah', (await call('GET', `${URLS.nilai}/nilai`, { headers: { 'X-Gateway-Secret': 'salah' } })).status, 403);
check('gateway secret benar tapi tanpa token (Nilai)', (await call('GET', `${URLS.nilai}/nilai`, { headers: secret })).status, 401);
check('gateway secret benar tapi tanpa token (Transkrip)', (await call('GET', `${URLS.transkrip}/transkrip`, { headers: secret })).status, 401);
check('langsung ke sinkron dengan secret + token user', (await call('POST', `${URLS.transkrip}/transkrip/sinkron`, {
  token: sessions.student01.token, headers: secret, body: { courseId: IF101 }
})).status, 403);
check('langsung ke Nilai: secret + token mahasiswa, header X-User-Role dipalsukan',
  (await call('PUT', `${URLS.nilai}/nilai/${ownIF101.gradeId}`, {
    token: sessions.student01.token, device: 'HP-STUDENT-01',
    headers: { ...secret, 'X-User-Role': 'dosen', 'X-User-Id': '2' }, body: { score: 100 }
  })).status, 403);

check('endpoint tidak dikenal (default deny)', (await call('GET', `${GW}/admin/rahasia`, { token: sessions.admin01.token, device: 'HP-ADMIN-01' })).status, 404);

// ---------- Audit log ----------
console.log('\n== Audit log ==');
const rows = db.prepare('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 400').all();
const complete = rows.every((r) => r.occurred_at && r.endpoint && r.decision && r.reason);
check('semua baris audit punya waktu, endpoint, keputusan, alasan', complete ? 'ok' : 'tidak', 'ok');
check('audit mencatat allow', rows.some((r) => r.decision === 'allow') ? 'ada' : 'tidak', 'ada');
check('audit mencatat deny', rows.some((r) => r.decision === 'deny') ? 'ada' : 'tidak', 'ada');
check('audit mencatat device', rows.some((r) => r.device_id === 'HP-STUDENT-01') ? 'ada' : 'tidak', 'ada');
check('audit mencatat subjek service', rows.some((r) => r.subject === 'service:nilai') ? 'ada' : 'tidak', 'ada');

console.log(`\nHasil: ${pass} lulus, ${fail} gagal.`);
db.close();
process.exit(fail ? 1 : 0);
