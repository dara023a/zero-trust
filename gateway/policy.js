// Policy Engine (PE): memutuskan allow/deny beserta alasan, berdasarkan
// Tabel 3 pada tugas. Keputusan yang bergantung pada kepemilikan data
// dibaca dari DATABASE, bukan dari isi token.
import { db } from '../database/connection.js';
import { withinAccessHours, accessWindowLabel } from '../shared/config.js';

// Daftar endpoint yang dikenal. Selain ini => ditolak (default deny).
const ROUTES = [
  { method: 'GET', re: /^\/nilai\/?$/,
    id: 'nilai.list', target: 'nilai' },
  { method: 'PUT', re: /^\/nilai\/(\d+)\/?$/,
    id: 'nilai.update', target: 'nilai', params: ['gradeId'] },
  { method: 'POST', re: /^\/kelas\/(\d+)\/finalisasi\/?$/,
    id: 'kelas.finalisasi', target: 'nilai', params: ['courseId'] },
  { method: 'GET', re: /^\/transkrip\/?$/,
    id: 'transkrip.list', target: 'transkrip' },
  { method: 'POST', re: /^\/transkrip\/sinkron\/?$/,
    id: 'transkrip.sinkron', target: 'transkrip', service: true },
  { method: 'GET', re: /^\/transkrip\/([A-Za-z0-9_-]{3,32})\/?$/,
    id: 'transkrip.get', target: 'transkrip', params: ['nim'] }
];

export function matchRoute(method, pathname) {
  for (const route of ROUTES) {
    if (route.method !== method) continue;

    const match = route.re.exec(pathname);
    if (!match) continue;

    const params = {};
    (route.params ?? []).forEach((name, i) => {
      params[name] = match[i + 1];
    });

    return { ...route, params };
  }

  return null;
}

const gradeOwnership = db.prepare(`
  SELECT g.id, g.finalized,
         EXISTS (
           SELECT 1 FROM teaching_assignments ta
           WHERE ta.course_id = g.course_id AND ta.lecturer_id = ?
         ) AS teaches
  FROM grades g
  WHERE g.id = ?
`);

const courseOwnership = db.prepare(`
  SELECT c.id
  FROM courses c
  JOIN teaching_assignments ta ON ta.course_id = c.id
  WHERE c.id = ? AND ta.lecturer_id = ?
`);

const allow = (reason) => ({ allow: true, status: 200, reason });
const deny = (status, reason, message) =>
  ({ allow: false, status, reason, message });

const roleDenied = (actor) =>
  deny(403, `Role ${actor.role} not allowed`,
    'Role Anda tidak diizinkan mengakses endpoint ini.');

const outsideHours = () =>
  deny(403, `Outside access hours (${accessWindowLabel()})`,
    `Perubahan/finalisasi nilai hanya diizinkan pada jam ${accessWindowLabel()}.`);

// Keputusan untuk request dari USER.
export function decideUser(route, actor) {
  switch (route.id) {
    case 'nilai.list':
      // Mahasiswa: nilai miliknya. Dosen: kelas yang diampu.
      return ['mahasiswa', 'dosen'].includes(actor.role)
        ? allow('Role permitted to read grades')
        : roleDenied(actor);

    case 'nilai.update': {
      if (actor.role !== 'dosen') return roleDenied(actor);

      const grade = gradeOwnership.get(actor.id, Number(route.params.gradeId));

      if (!grade || !grade.teaches) {
        return deny(403, 'Grade missing or lecturer does not teach the class',
          'Nilai tidak ditemukan atau bukan kelas yang Anda ampu.');
      }

      if (grade.finalized) {
        return deny(409, 'Grade already finalized',
          'Nilai sudah difinalisasi dan tidak dapat diubah.');
      }

      if (!withinAccessHours()) return outsideHours();

      return allow('Lecturer teaches class, grade not final, within hours');
    }

    case 'kelas.finalisasi': {
      if (actor.role !== 'dosen') return roleDenied(actor);

      if (!courseOwnership.get(Number(route.params.courseId), actor.id)) {
        return deny(403, 'Course missing or lecturer does not teach the class',
          'Kelas tidak ditemukan atau bukan kelas yang Anda ampu.');
      }

      if (!withinAccessHours()) return outsideHours();

      return allow('Lecturer teaches class and within hours');
    }

    case 'transkrip.list':
      return ['mahasiswa', 'admin'].includes(actor.role)
        ? allow('Role permitted to read transcripts')
        : roleDenied(actor);

    case 'transkrip.get':
      if (actor.role === 'admin') return allow('Admin may read any transcript');

      if (actor.role === 'mahasiswa') {
        return actor.nim && actor.nim === route.params.nim
          ? allow('Student reads own transcript')
          : deny(403, 'Student requested another NIM',
              'Mahasiswa hanya boleh melihat transkrip miliknya sendiri.');
      }

      return roleDenied(actor);

    default:
      // Termasuk transkrip.sinkron: user biasa tidak pernah boleh.
      return deny(403, 'Endpoint is restricted to service tokens',
        'Endpoint ini khusus service.');
  }
}

// Keputusan untuk request dari SERVICE (token service sudah diverifikasi).
export function decideService(route, claims) {
  if (route.service && claims.service === 'nilai') {
    return allow('Valid service token from nilai');
  }

  return deny(403, 'Service token not allowed for this endpoint',
    'Service tidak diizinkan mengakses endpoint ini.');
}
