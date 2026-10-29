// Seed kelas, penugasan dosen, dan nilai awal.   npm run seed
// Reset data demo (nilai kembali awal, transkrip dikosongkan):
//   node database/seed-academic.js --reset
import { db } from './connection.js';

const COURSES = [
  { code: 'IF101', name: 'Dasar Informatika',  lecturer: 'dosen01' },
  { code: 'IF102', name: 'Struktur Data',      lecturer: 'dosen02' }
];

const GRADES = [
  ['student01', 'IF101', 85], ['student02', 'IF101', 90],
  ['student03', 'IF101', 65],
  ['student01', 'IF102', 78], ['student02', 'IF102', 70],
  ['student03', 'IF102', 88]
];

const userId = (username) =>
  db.prepare('SELECT id FROM users WHERE username = ?').get(username)?.id;

const courseId = (code) =>
  db.prepare('SELECT id FROM courses WHERE code = ?').get(code)?.id;

try {
  if (!userId('dosen01') || !userId('dosen02') || !userId('student01')) {
    throw new Error('Jalankan node database/seed.js terlebih dahulu.');
  }

  for (const c of COURSES) {
    db.prepare('INSERT OR IGNORE INTO courses (code, name) VALUES (?, ?)')
      .run(c.code, c.name);

    db.prepare(`
      INSERT OR IGNORE INTO teaching_assignments (lecturer_id, course_id)
      VALUES (?, ?)
    `).run(userId(c.lecturer), courseId(c.code));
  }

  const reset = process.argv.includes('--reset');

  for (const [student, code, score] of GRADES) {
    db.prepare(`
      INSERT OR IGNORE INTO grades (student_id, course_id, score)
      VALUES (?, ?, ?)
    `).run(userId(student), courseId(code), score);

    if (reset) {
      db.prepare(`
        UPDATE grades SET score = ?, finalized = 0,
          updated_at = CURRENT_TIMESTAMP
        WHERE student_id = ? AND course_id = ?
      `).run(score, userId(student), courseId(code));
    }
  }

  if (reset) {
    db.exec('DELETE FROM transcripts');
    console.log('Data demo di-reset: nilai awal, belum final, transkrip kosong.');
  }

  console.log('Kelas dan nilai demo siap:');
  for (const c of COURSES) {
    console.log(`${c.code} - ${c.name} (dosen pengampu: ${c.lecturer})`);
  }
} finally {
  db.close();
}
