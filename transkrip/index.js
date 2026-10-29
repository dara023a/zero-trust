// Service Transkrip (resource), port 3002. Hanya menerima request dari gateway.
import express from 'express';
import { db, runInTransaction } from '../database/connection.js';
import { createAuditor } from '../shared/audit.js';
import { createGuards } from '../shared/service-guards.js';
import { requireEnv } from '../shared/config.js';
import { verifyServiceToken, bearerToken } from '../gateway/auth.js';

requireEnv('JWT_SECRET', 'GATEWAY_SECRET');

const PORT = 3002;
const audit = createAuditor(db, 'transkrip');
const { gatewayOnly, userAuth } = createGuards(db, audit);

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '20kb' }));

const label = (req) => `${req.method} ${req.path}`;

function gradeLetter(score) {
  if (score >= 85) return 'A';
  if (score >= 75) return 'B';
  if (score >= 65) return 'C';
  if (score >= 50) return 'D';
  return 'E';
}

const transcriptRows = `
  SELECT u.nim, u.username AS student, c.code, c.name AS course,
         t.score, t.grade_letter AS gradeLetter, t.synced_at AS syncedAt
  FROM transcripts t
  JOIN users u ON u.id = t.student_id
  JOIN courses c ON c.id = t.course_id
`;

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'transkrip' });
});

app.use(gatewayOnly);

// POST /transkrip/sinkron : khusus token service. Token user ditolak.
// Mengambil nilai yang SUDAH FINAL dari database dan menyimpannya ke tabel
// transcripts (upsert, idempotent). Skor tidak dipercaya dari body request.
app.post('/transkrip/sinkron', (req, res) => {
  let claims;

  try {
    const token = bearerToken(req);
    if (!token) throw new Error('missing');
    claims = verifyServiceToken(token);
  } catch {
    audit(null, label(req), null, 'deny',
      'Service: invalid or missing service token (user tokens rejected)');

    return res.status(403).json({
      error: 'Endpoint sinkronisasi hanya untuk service nilai.'
    });
  }

  const courseId = Number(req.body?.courseId);

  if (!Number.isSafeInteger(courseId) || courseId < 1) {
    return res.status(400).json({ error: 'courseId wajib berupa angka.' });
  }

  const course = db.prepare('SELECT id, code FROM courses WHERE id = ?')
    .get(courseId);

  if (!course) {
    audit(`service:${claims.service}`, label(req), null, 'deny',
      'Course not found');

    return res.status(404).json({ error: 'Mata kuliah tidak ditemukan.' });
  }

  const finalGrades = db.prepare(`
    SELECT student_id, score FROM grades
    WHERE course_id = ? AND finalized = 1 AND score IS NOT NULL
  `).all(courseId);

  const upsert = db.prepare(`
    INSERT INTO transcripts
      (student_id, course_id, score, grade_letter, synced_at)
    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT (student_id, course_id) DO UPDATE SET
      score = excluded.score,
      grade_letter = excluded.grade_letter,
      synced_at = CURRENT_TIMESTAMP
  `);

  runInTransaction(() => {
    for (const grade of finalGrades) {
      upsert.run(grade.student_id, courseId, grade.score,
        gradeLetter(grade.score));
    }
  });

  audit(`service:${claims.service}`, label(req), null, 'allow',
    `Transcript synced for ${course.code}; rows=${finalGrades.length}`);

  res.json({
    message: 'Sinkronisasi transkrip berhasil.',
    course: course.code,
    syncedCount: finalGrades.length
  });
});

// Semua endpoint di bawah ini untuk USER: token diverifikasi ulang di sini.
app.use(userAuth);

// GET /transkrip : mahasiswa = miliknya, admin = semua.
app.get('/transkrip', (req, res) => {
  const { role, id, username } = req.actor;

  if (role === 'mahasiswa') {
    const rows = db.prepare(
      `${transcriptRows} WHERE t.student_id = ? ORDER BY c.code`
    ).all(id);

    audit(username, label(req), req.deviceId, 'allow', 'Own transcript read');
    return res.json({ transcripts: rows });
  }

  if (role === 'admin') {
    const rows = db.prepare(
      `${transcriptRows} ORDER BY u.nim, c.code`
    ).all();

    audit(username, label(req), req.deviceId, 'allow',
      'All transcripts read');
    return res.json({ transcripts: rows });
  }

  audit(username, label(req), req.deviceId, 'deny',
    'Service: role cannot read transcripts');

  res.status(403).json({
    error: 'Role Anda tidak diizinkan mengakses transkrip.'
  });
});

// GET /transkrip/:nim : mahasiswa hanya NIM sendiri, admin semua NIM.
app.get('/transkrip/:nim', (req, res) => {
  const { role, nim: ownNim, username } = req.actor;
  const nim = req.params.nim;

  const allowed =
    role === 'admin' || (role === 'mahasiswa' && ownNim && ownNim === nim);

  if (!allowed) {
    audit(username, label(req), req.deviceId, 'deny',
      role === 'mahasiswa'
        ? 'Service: student requested another NIM'
        : 'Service: role cannot read transcripts');

    return res.status(403).json({
      error: 'Anda tidak berhak melihat transkrip ini.'
    });
  }

  const student = db.prepare(`
    SELECT id, username, nim FROM users
    WHERE nim = ? AND role = 'mahasiswa'
  `).get(nim);

  if (!student) {
    audit(username, label(req), req.deviceId, 'allow', 'NIM not found');
    return res.status(404).json({ error: 'NIM tidak ditemukan.' });
  }

  const courses = db.prepare(
    `${transcriptRows} WHERE t.student_id = ? ORDER BY c.code`
  ).all(student.id);

  const average = courses.length
    ? courses.reduce((sum, row) => sum + row.score, 0) / courses.length
    : null;

  audit(username, label(req), req.deviceId, 'allow',
    `Transcript read for NIM ${nim}`);

  res.json({
    student: { nim: student.nim, username: student.username },
    courses,
    totalCourses: courses.length,
    averageScore: average === null ? null : Number(average.toFixed(2))
  });
});

app.use((req, res) => {
  audit(req.actor?.username, label(req), req.deviceId, 'deny',
    'Service: unknown endpoint');
  res.status(404).json({ error: 'Endpoint tidak ditemukan.' });
});

app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Body JSON tidak valid.' });
  }

  console.error('Transkrip error:', err.message);
  res.status(500).json({ error: 'Terjadi kesalahan internal.' });
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Service Transkrip berjalan di http://127.0.0.1:${PORT}`);
});
