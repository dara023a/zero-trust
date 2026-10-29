// Service Nilai (resource), port 3001. Hanya menerima request dari gateway.
import express from 'express';
import { db, runInTransaction } from '../database/connection.js';
import { createAuditor } from '../shared/audit.js';
import { createGuards } from '../shared/service-guards.js';
import {
  requireEnv, URLS, withinAccessHours, accessWindowLabel
} from '../shared/config.js';

requireEnv(
  'JWT_SECRET', 'GATEWAY_SECRET',
  'SERVICE_CLIENT_ID', 'SERVICE_CLIENT_SECRET'
);

const PORT = 3001;
const audit = createAuditor(db, 'nilai');
const { gatewayOnly, userAuth } = createGuards(db, audit);

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '20kb' }));

const label = (req) => `${req.method} ${req.path}`;

function deny(req, res, status, message, reason) {
  audit(req.actor?.username, label(req), req.deviceId, 'deny', reason);
  return res.status(status).json({ error: message });
}

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'nilai' });
});

app.use(gatewayOnly, userAuth);

// GET /nilai
// Mahasiswa: hanya nilai miliknya. Dosen: hanya kelas yang diampu.
app.get('/nilai', (req, res) => {
  const { id, role } = req.actor;
  let rows;

  if (role === 'mahasiswa') {
    rows = db.prepare(`
      SELECT g.id AS gradeId, c.code, c.name AS course, g.score, g.finalized
      FROM grades g
      JOIN courses c ON c.id = g.course_id
      WHERE g.student_id = ?
      ORDER BY c.code
    `).all(id);
  } else if (role === 'dosen') {
    rows = db.prepare(`
      SELECT g.id AS gradeId, c.id AS courseId, c.code, c.name AS course,
             u.username AS student, u.nim, g.score, g.finalized
      FROM grades g
      JOIN courses c ON c.id = g.course_id
      JOIN users u ON u.id = g.student_id
      JOIN teaching_assignments ta ON ta.course_id = c.id
      WHERE ta.lecturer_id = ?
      ORDER BY c.code, u.username
    `).all(id);
  } else {
    return deny(req, res, 403, 'Role Anda tidak diizinkan mengakses nilai.',
      'Service: role not allowed to read grades');
  }

  audit(req.actor.username, label(req), req.deviceId, 'allow',
    `Grades read (${rows.length} rows)`);

  res.json({ grades: rows });
});

// PUT /nilai/:id  (id = id baris nilai)
app.put('/nilai/:id', (req, res) => {
  const { id: lecturerId, role } = req.actor;
  const gradeId = Number(req.params.id);
  const { score } = req.body ?? {};

  if (role !== 'dosen') {
    return deny(req, res, 403, 'Hanya dosen yang dapat mengubah nilai.',
      'Service: role cannot update grades');
  }

  if (!Number.isSafeInteger(gradeId) || gradeId < 1) {
    return res.status(400).json({ error: 'ID nilai tidak valid.' });
  }

  // Kepemilikan kelas dibaca dari database, bukan dari token/header.
  const grade = db.prepare(`
    SELECT g.id, g.finalized
    FROM grades g
    JOIN teaching_assignments ta ON ta.course_id = g.course_id
    WHERE g.id = ? AND ta.lecturer_id = ?
  `).get(gradeId, lecturerId);

  if (!grade) {
    return deny(req, res, 403,
      'Nilai tidak ditemukan atau bukan kelas yang Anda ampu.',
      'Service: grade missing or lecturer not assigned');
  }

  if (grade.finalized) {
    return deny(req, res, 409,
      'Nilai sudah difinalisasi dan tidak dapat diubah.',
      'Service: grade already finalized');
  }

  if (!withinAccessHours()) {
    return deny(req, res, 403,
      `Perubahan nilai hanya diizinkan pada jam ${accessWindowLabel()}.`,
      'Service: outside access hours');
  }

  if (
    typeof score !== 'number' || !Number.isFinite(score) ||
    score < 0 || score > 100
  ) {
    return res.status(400).json({
      error: 'Nilai harus berupa angka antara 0 dan 100.'
    });
  }

  // "AND finalized = 0" mencegah balapan dengan proses finalisasi.
  const result = db.prepare(`
    UPDATE grades SET score = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ? AND finalized = 0
  `).run(score, grade.id);

  if (result.changes !== 1) {
    return deny(req, res, 409,
      'Nilai sudah difinalisasi dan tidak dapat diubah.',
      'Service: grade finalized during update');
  }

  audit(req.actor.username, label(req), req.deviceId, 'allow',
    `Grade ${grade.id} updated`);

  res.json({ message: 'Nilai berhasil diperbarui.', gradeId: grade.id, score });
});

// Meminta token service ke gateway, lalu memanggil sinkron transkrip
// melalui gateway (bukan langsung ke Service Transkrip).
async function syncTranscript(courseId) {
  const tokenResponse = await fetch(`${URLS.gateway}/auth/service`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      clientId: process.env.SERVICE_CLIENT_ID,
      clientSecret: process.env.SERVICE_CLIENT_SECRET
    }),
    signal: AbortSignal.timeout(10_000)
  });

  if (!tokenResponse.ok) {
    throw new Error('Gagal memperoleh service token.');
  }

  const { accessToken } = await tokenResponse.json();

  const syncResponse = await fetch(`${URLS.gateway}/transkrip/sinkron`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({ courseId }),
    signal: AbortSignal.timeout(10_000)
  });

  const body = await syncResponse.json().catch(() => ({}));

  if (!syncResponse.ok) {
    throw new Error(body.error || 'Sinkronisasi transkrip gagal.');
  }

  return body;
}

// POST /kelas/:id/finalisasi  (id = id mata kuliah/kelas)
// Idempotent: jika sinkron sempat gagal, memanggil endpoint ini lagi akan
// mengulang sinkronisasi untuk nilai yang sudah final.
app.post('/kelas/:id/finalisasi', async (req, res) => {
  const { id: lecturerId, role } = req.actor;
  const courseId = Number(req.params.id);

  if (role !== 'dosen') {
    return deny(req, res, 403, 'Hanya dosen yang dapat memfinalisasi nilai.',
      'Service: role cannot finalize grades');
  }

  if (!Number.isSafeInteger(courseId) || courseId < 1) {
    return res.status(400).json({ error: 'ID kelas tidak valid.' });
  }

  const assigned = db.prepare(`
    SELECT c.id, c.code FROM courses c
    JOIN teaching_assignments ta ON ta.course_id = c.id
    WHERE c.id = ? AND ta.lecturer_id = ?
  `).get(courseId, lecturerId);

  if (!assigned) {
    return deny(req, res, 403,
      'Kelas tidak ditemukan atau bukan kelas yang Anda ampu.',
      'Service: course missing or lecturer not assigned');
  }

  if (!withinAccessHours()) {
    return deny(req, res, 403,
      `Finalisasi hanya diizinkan pada jam ${accessWindowLabel()}.`,
      'Service: outside access hours');
  }

  const { finalized, pending } = runInTransaction(() => {
    const result = db.prepare(`
      UPDATE grades
      SET finalized = 1, updated_at = CURRENT_TIMESTAMP
      WHERE course_id = ? AND finalized = 0 AND score IS NOT NULL
    `).run(courseId);

    const left = db.prepare(`
      SELECT COUNT(*) AS n FROM grades
      WHERE course_id = ? AND finalized = 0
    `).get(courseId).n;

    return { finalized: result.changes, pending: left };
  });

  try {
    const sync = await syncTranscript(courseId);

    audit(req.actor.username, label(req), req.deviceId, 'allow',
      `Finalized ${finalized} grades for ${assigned.code}; transcript synced`);

    return res.json({
      message: 'Finalisasi nilai berhasil dan transkrip telah disinkronkan.',
      course: assigned.code,
      newlyFinalized: finalized,
      notFinalizedNoScore: pending,
      transcriptSync: sync
    });
  } catch (error) {
    console.error('Transcript sync error:', error.message);

    audit(req.actor.username, label(req), req.deviceId, 'deny',
      `Finalized ${finalized} grades but transcript sync failed`);

    return res.status(502).json({
      error:
        'Nilai sudah difinalisasi, tetapi sinkronisasi transkrip gagal. ' +
        'Panggil endpoint finalisasi yang sama lagi untuk mengulang sinkron.',
      newlyFinalized: finalized
    });
  }
});

app.use((req, res) => {
  deny(req, res, 404, 'Endpoint tidak ditemukan.', 'Service: unknown endpoint');
});

app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Body JSON tidak valid.' });
  }

  console.error('Nilai error:', err.message);
  res.status(500).json({ error: 'Terjadi kesalahan internal.' });
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Service Nilai berjalan di http://127.0.0.1:${PORT}`);
});
