import { DatabaseSync } from 'node:sqlite';

const db = new DatabaseSync('database/zero-trust.db');

try {
  const student = db.prepare(
    "SELECT id FROM users WHERE username = 'student01'"
  ).get();

  const lecturer = db.prepare(
    "SELECT id FROM users WHERE username = 'dosen01'"
  ).get();

  if (!student || !lecturer) {
    throw new Error(
      'Jalankan node database/seed.js terlebih dahulu.'
    );
  }

  const insertCourse = db.prepare(`
    INSERT OR IGNORE INTO courses (code, name)
    VALUES (?, ?)
  `);

  insertCourse.run('IF101', 'Dasar Informatika');

  const course = db.prepare(
    "SELECT id FROM courses WHERE code = 'IF101'"
  ).get();

  db.prepare(`
    INSERT OR IGNORE INTO teaching_assignments
      (lecturer_id, course_id)
    VALUES (?, ?)
  `).run(lecturer.id, course.id);

  db.prepare(`
    INSERT OR IGNORE INTO grades
      (student_id, course_id, score)
    VALUES (?, ?, ?)
  `).run(student.id, course.id, 85);

  console.log('Data mata kuliah dan nilai contoh siap.');
  console.log('Mata kuliah: IF101 - Dasar Informatika');
} finally {
  db.close();
}
