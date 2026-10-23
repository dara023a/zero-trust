import 'dotenv/config';
import express from 'express';
import { timingSafeEqual } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

const app = express();
const PORT = 3001;
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
      error: 'Permintaan bukan berasal dari Gateway tepercaya.'
    });
  }

  const userId = Number(req.get('X-User-Id'));
  const role = req.get('X-User-Role');
  const username = req.get('X-Username');

  if (
    !Number.isSafeInteger(userId) ||
    userId < 1 ||
    !['mahasiswa', 'dosen', 'admin'].includes(role) ||
    !username
  ) {
    return res.status(401).json({
      error: 'Identitas pengguna dari Gateway tidak valid.'
    });
  }

  req.actor = { id: userId, role, username };
  next();
}

function withinOperatingHours() {
  const hour = new Date().getHours();
  return hour >= 7 && hour < 21;
}

function audit(actor, endpoint, decision, reason) {
  db.prepare(`
    INSERT INTO audit_logs
      (subject, endpoint, decision, reason)
    VALUES (?, ?, ?, ?)
  `).run(
    actor?.username ?? null,
    endpoint,
    decision,
    reason
  );
}

function deny(res, actor, endpoint, status, message, reason) {
  audit(actor, endpoint, 'deny', reason);
  return res.status(status).json({ error: message });
}

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'nilai' });
});

app.use(gatewayOnly);

// Mahasiswa hanya melihat nilainya sendiri.
// Dosen hanya melihat nilai pada mata kuliah yang diampu.
// Admin dapat membaca seluruh nilai melalui endpoint ini.
app.get('/', (req, res) => {
  const { id, role } = req.actor;

  let rows;

  if (role === 'mahasiswa') {
    rows = db.prepare(`
      SELECT c.code, c.name AS course, g.score, g.finalized
      FROM grades g
      JOIN courses c ON c.id = g.course_id
      WHERE g.student_id = ?
      ORDER BY c.code
    `).all(id);
  } else if (role === 'dosen') {
    rows = db.prepare(`
      SELECT u.username AS student, c.code, c.name AS course,
             g.score, g.finalized
      FROM grades g
      JOIN courses c ON c.id = g.course_id
      JOIN users u ON u.id = g.student_id
      JOIN teaching_assignments ta ON ta.course_id = c.id
      WHERE ta.lecturer_id = ?
      ORDER BY c.code, u.username
    `).all(id);
  } else {
    rows = db.prepare(`
      SELECT u.username AS student, c.code, c.name AS course,
             g.score, g.finalized
      FROM grades g
      JOIN courses c ON c.id = g.course_id
      JOIN users u ON u.id = g.student_id
      ORDER BY c.code, u.username
    `).all();
  }

  audit(req.actor, req.originalUrl, 'allow', 'Grade list read');
  res.json({ grades: rows });
});

// Dosen hanya dapat mengubah nilai di kelas yang diampunya.
app.put('/:courseCode/students/:studentId', (req, res) => {
  const { id, role } = req.actor;
  const { courseCode, studentId: rawStudentId } = req.params;
  const studentId = Number(rawStudentId);
  const { score } = req.body ?? {};

  if (role !== 'dosen') {
    return deny(
      res, req.actor, req.originalUrl, 403,
      'Hanya dosen yang dapat mengubah nilai.',
      'Role cannot update grades'
    );
  }

  if (!Number.isSafeInteger(studentId) || studentId < 1) {
    return res.status(400).json({ error: 'ID mahasiswa tidak valid.' });
  }

  if (
    typeof score !== 'number' ||
    !Number.isFinite(score) ||
    score < 0 ||
    score > 100
  ) {
    return res.status(400).json({
      error: 'Nilai harus berupa angka antara 0 dan 100.'
    });
  }

  if (!withinOperatingHours()) {
    return deny(
      res, req.actor, req.originalUrl, 403,
      'Perubahan nilai hanya diizinkan pukul 07.00–20.59.',
      'Outside grade modification hours'
    );
  }

  const grade = db.prepare(`
    SELECT g.id, g.finalized
    FROM grades g
    JOIN courses c ON c.id = g.course_id
    JOIN teaching_assignments ta ON ta.course_id = c.id
    WHERE c.code = ?
      AND g.student_id = ?
      AND ta.lecturer_id = ?
  `).get(courseCode, studentId, id);

  if (!grade) {
    return deny(
      res, req.actor, req.originalUrl, 403,
      'Nilai tidak ditemukan atau dosen tidak mengampu mata kuliah ini.',
      'Grade missing or lecturer not assigned'
    );
  }

  if (grade.finalized) {
    return deny(
      res, req.actor, req.originalUrl, 403,
      'Nilai sudah difinalisasi dan tidak dapat diubah.',
      'Grade already finalized'
    );
  }

  db.prepare(`
    UPDATE grades
    SET score = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(score, grade.id);

  audit(req.actor, req.originalUrl, 'allow', 'Grade updated');
  res.json({ message: 'Nilai berhasil diperbarui.' });
});

// Finalisasi hanya dapat dilakukan dosen pengampu.
app.post('/:courseCode/finalize', async (req, res) => {
  const { id, role } = req.actor;
  const { courseCode } = req.params;

  if (role !== 'dosen') {
    return deny(
      res, req.actor, req.originalUrl, 403,
      'Hanya dosen yang dapat memfinalisasi nilai.',
      'Role cannot finalize grades'
    );
  }

  if (!withinOperatingHours()) {
    return deny(
      res, req.actor, req.originalUrl, 403,
      'Finalisasi hanya diizinkan pukul 07.00–20.59.',
      'Outside finalization hours'
    );
  }

  const assignment = db.prepare(`
    SELECT c.id
    FROM courses c
    JOIN teaching_assignments ta ON ta.course_id = c.id
    WHERE c.code = ? AND ta.lecturer_id = ?
  `).get(courseCode, id);

  if (!assignment) {
    return deny(
      res, req.actor, req.originalUrl, 403,
      'Dosen tidak mengampu mata kuliah ini.',
      'Lecturer not assigned to course'
    );
  }

  const result = db.prepare(`
    UPDATE grades
    SET finalized = 1, updated_at = CURRENT_TIMESTAMP
    WHERE course_id = ? AND finalized = 0
  `).run(assignment.id);

  try {
    const tokenResponse = await fetch(
      'http://127.0.0.1:3000/auth/service',
      {
        method: 'POST',
        headers: {
          'X-Gateway-Secret': process.env.GATEWAY_SECRET,
          'X-Service-Name': 'nilai'
        }
      }
    );

    if (!tokenResponse.ok) {
      throw new Error('Gagal memperoleh service token.');
    }

    const { accessToken: serviceToken } =
      await tokenResponse.json();

    const syncResponse = await fetch(
      'http://127.0.0.1:3000/internal/transkrip/sinkron',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Gateway-Secret': process.env.GATEWAY_SECRET,
          Authorization: `Bearer ${serviceToken}`
        },
        body: JSON.stringify({ courseCode })
      }
    );

    const syncResult = await syncResponse.json();

    if (!syncResponse.ok) {
      throw new Error(
        syncResult.error || 'Sinkronisasi transkrip gagal.'
      );
    }

    audit(
      req.actor,
      req.originalUrl,
      'allow',
      `Grades finalized; rows=${result.changes}`
    );

    return res.json({
      message: 'Finalisasi nilai berhasil.',
      finalizedCount: result.changes,
      transcriptSync: syncResult
    });
  } catch (error) {
    console.error('Transcript sync error:', error.message);

    audit(
      req.actor,
      req.originalUrl,
      'deny',
      'Grades finalized but transcript sync failed'
    );

    return res.status(502).json({
      error: 'Nilai sudah difinalisasi, tetapi sinkronisasi transkrip gagal.',
      finalizedCount: result.changes
    });
  }
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Service Nilai berjalan di http://127.0.0.1:${PORT}`);
});
