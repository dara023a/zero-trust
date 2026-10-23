import 'dotenv/config';
import express from 'express';
import { timingSafeEqual } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { verifyServiceToken } from '../gateway/auth.js';

const app = express();
const PORT = 3002;
const db = new DatabaseSync('database/zero-trust.db');

app.use(express.json({ limit: '20kb' }));

function secretMatches(provided, expected) {
  if (!provided || !expected) return false;

  const a = Buffer.from(provided);
  const b = Buffer.from(expected);

  return a.length === b.length && timingSafeEqual(a, b);
}

function gatewayOnly(req, res, next) {
  if (!secretMatches(
    req.get('X-Gateway-Secret'),
    process.env.GATEWAY_SECRET
  )) {
    return res.status(403).json({
      error: 'Gateway tidak terverifikasi.'
    });
  }

  next();
}

function getActor(req) {
  const id = Number(req.get('X-User-Id'));
  const role = req.get('X-User-Role');
  const username = req.get('X-Username');

  if (
    !Number.isSafeInteger(id) ||
    id < 1 ||
    !['mahasiswa', 'dosen', 'admin'].includes(role) ||
    !username
  ) {
    return null;
  }

  return { id, role, username };
}

function audit(subject, endpoint, decision, reason) {
  db.prepare(`
    INSERT INTO audit_logs (subject, endpoint, decision, reason)
    VALUES (?, ?, ?, ?)
  `).run(subject ?? null, endpoint, decision, reason);
}

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'transkrip' });
});

app.use(gatewayOnly);

// GET / : mahasiswa hanya melihat transkrip miliknya;
// admin dapat melihat seluruh transkrip.
app.get('/', (req, res) => {
  const actor = getActor(req);

  if (!actor) {
    return res.status(401).json({
      error: 'Identitas pengguna tidak valid.'
    });
  }

  if (actor.role === 'dosen') {
    audit(actor.username, req.originalUrl, 'deny',
      'Lecturer cannot access transcript endpoint');

    return res.status(403).json({
      error: 'Role dosen tidak memiliki akses ke endpoint transkrip ini.'
    });
  }

  let rows;

  if (actor.role === 'mahasiswa') {
    rows = db.prepare(`
      SELECT c.code, c.name AS course, g.score, g.finalized
      FROM grades g
      JOIN courses c ON c.id = g.course_id
      WHERE g.student_id = ?
      ORDER BY c.code
    `).all(actor.id);
  } else {
    rows = db.prepare(`
      SELECT u.username AS student, c.code, c.name AS course,
             g.score, g.finalized
      FROM grades g
      JOIN courses c ON c.id = g.course_id
      JOIN users u ON u.id = g.student_id
      ORDER BY u.username, c.code
    `).all();
  }

  audit(actor.username, req.originalUrl, 'allow', 'Transcript read');
  res.json({ transcripts: rows });
});

// Hanya service nilai yang boleh memanggil endpoint sinkronisasi.
// Token pengguna biasa tidak akan diterima.
app.post('/sinkron', (req, res) => {
  const authorization = req.get('Authorization') ?? '';
  const token = authorization.startsWith('Bearer ')
    ? authorization.slice(7).trim()
    : '';

  let claims;

  try {
    if (!token) throw new Error('Service token wajib diisi.');
    claims = verifyServiceToken(token);
  } catch {
    audit(null, req.originalUrl, 'deny',
      'Invalid or missing service token');

    return res.status(403).json({
      error: 'Endpoint sinkronisasi hanya untuk service nilai.'
    });
  }

  const { courseCode } = req.body ?? {};

  if (
    typeof courseCode !== 'string' ||
    !courseCode.trim()
  ) {
    return res.status(400).json({
      error: 'courseCode wajib diisi.'
    });
  }

  const course = db.prepare(`
    SELECT id FROM courses WHERE code = ?
  `).get(courseCode);

  if (!course) {
    audit(claims.service, req.originalUrl, 'deny',
      'Course not found');

    return res.status(404).json({
      error: 'Mata kuliah tidak ditemukan.'
    });
  }

  // Data nilai dan transkrip berada di database bersama.
  // Endpoint ini memvalidasi pemanggil dan memastikan mata kuliah ada.
  const count = db.prepare(`
    SELECT COUNT(*) AS total
    FROM grades
    WHERE course_id = ? AND finalized = 1
  `).get(course.id).total;

  audit(claims.service, req.originalUrl, 'allow',
    `Transcript sync checked; finalized=${count}`);

  res.json({
    message: 'Sinkronisasi transkrip berhasil diproses.',
    courseCode,
    finalizedCount: count
  });
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Service Transkrip berjalan di http://127.0.0.1:${PORT}`);
});
