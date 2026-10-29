// Penulis audit log. Dipakai gateway (sumber utama) dan kedua service.
// Sengaja tidak menelan error: jika audit gagal ditulis, request ikut gagal
// (fail closed) supaya tidak ada akses tanpa jejak.
export function createAuditor(db, source) {
  const insert = db.prepare(`
    INSERT INTO audit_logs
      (subject, endpoint, device_id, decision, reason, source)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  const clip = (value, max) =>
    value == null ? null : String(value).slice(0, max);

  return function audit(subject, endpoint, deviceId, decision, reason) {
    insert.run(
      clip(subject, 100),
      clip(endpoint, 300) ?? '-',
      clip(deviceId, 100),
      decision,
      clip(reason, 300) ?? '-',
      source
    );
  };
}
