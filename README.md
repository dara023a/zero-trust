# Sistem Nilai dan Transkrip — Zero Trust Security

Tugas Praktikum Individu, Keamanan Informasi (KP70065004), Informatika UNSIL.
Prinsip: *never trust, always verify*, *least privilege*, *assume breach* (NIST SP 800-207).

## Arsitektur

```
Client (curl/Postman)
        │  Authorization: Bearer <JWT>  +  X-Device-ID
        ▼
┌─────────────────────────────┐  PE/PA: gateway/policy.js + gateway/auth.js
│ API Gateway :3000  (PEP)    │  Audit log: tabel audit_logs
└───────┬─────────────┬───────┘
 X-Gateway-Secret + Authorization diteruskan
        ▼             ▼
 Service Nilai    Service Transkrip
     :3001            :3002
        └──── SQLite bersama (database/zero-trust.db) ────┘
```

| Komponen | Peran NIST | File |
|---|---|---|
| API Gateway | PEP | `gateway/index.js` |
| Policy Engine / Administrator | PE / PA | `gateway/policy.js`, `gateway/auth.js`, `gateway/middleware.js` |
| Service Nilai | Resource | `nilai/index.js` |
| Service Transkrip | Resource | `transkrip/index.js` |
| Database + Audit Log | Resource / Data source | `database/`, `shared/audit.js` |

## Instalasi (Termux / Linux)

Butuh Node.js dengan modul `node:sqlite` (Node 22.5+; di Node 22 akan muncul peringatan *ExperimentalWarning*, itu normal).

```bash
npm install
npm run setup      # membuat/melengkapi .env dengan secret acak (tidak menimpa yang ada)
npm run init-db    # membuat tabel + migrasi database lama (aman diulang)
npm run seed       # akun, device, kelas, dan nilai awal (aman diulang)
```

Isi `.env` (lihat `.env.example`): `JWT_SECRET`, `GATEWAY_SECRET`, `SERVICE_CLIENT_ID`, `SERVICE_CLIENT_SECRET`, `ACCESS_HOUR_START`, `ACCESS_HOUR_END`, `ACCESS_TZ`.

## Menjalankan

Satu perintah (ketiga layanan, log di `logs/`):

```bash
npm run start:all
```

Atau tiga sesi Termux terpisah: `npm run transkrip`, `npm run nilai`, `npm run gateway`.

## Akun demo dan device ID

| Username | Role | NIM | Device ID | Password |
|---|---|---|---|---|
| admin01 | admin | – | HP-ADMIN-01 | DevAdmin123! |
| dosen01 | dosen (IF101) | – | HP-DOSEN-01 | DevDosen123! |
| dosen02 | dosen (IF102) | – | HP-DOSEN-02 | DevDosen223! |
| student01 | mahasiswa | 2210001 | HP-STUDENT-01 | DevMahasiswa123! |
| student02 | mahasiswa | 2210002 | HP-STUDENT-02 | DevMahasiswa223! |
| student03 | mahasiswa | 2210003 | HP-STUDENT-03 | DevMahasiswa323! |

Kelas: **IF101** Dasar Informatika (dosen01), **IF102** Struktur Data (dosen02). Password hanya untuk demo lokal.

## Endpoint (semua lewat gateway :3000)

| Endpoint | Siapa | Kondisi |
|---|---|---|
| `POST /auth/login` | semua user | kredensial valid + device terdaftar |
| `POST /auth/refresh`, `/auth/logout` | semua user | refresh token valid & belum dicabut |
| `POST /auth/service` | Service Nilai | `clientId` + `clientSecret` valid → token 5 menit, role `service` |
| `GET /nilai` | mahasiswa, dosen | mahasiswa: miliknya; dosen: kelas yang diampu |
| `PUT /nilai/:id` | dosen | kelas diampu, belum final, dalam jam akses (`:id` = `gradeId`) |
| `POST /kelas/:id/finalisasi` | dosen | kelas diampu, dalam jam akses (`:id` = id kelas); lalu memicu sinkron |
| `GET /transkrip/:nim` | mahasiswa, admin | mahasiswa: NIM sendiri; admin: semua |
| `GET /transkrip` | mahasiswa, admin | ringkasan (milik sendiri / semua) |
| `POST /transkrip/sinkron` | Service Nilai | hanya token service; token user ditolak |
| `GET /auth/me`, `/auth/admin-check` | user / admin | pengecekan identitas |

## Pemetaan kebutuhan ke kode (untuk video demo)

| Kebutuhan | Lokasi |
|---|---|
| JWT 10 menit, `sub` + `role` | `gateway/auth.js` → `createAccessToken` |
| Refresh token 1 hari, hash di DB, rotasi, dicabut saat logout | `gateway/index.js` → `/auth/refresh`, `/auth/logout` |
| Token service 5 menit, `role: service`, client ID + secret | `gateway/auth.js` → `createServiceToken`; `gateway/index.js` → `/auth/service` |
| Gateway secret; service tidak bisa diakses langsung | `shared/service-guards.js` → `gatewayOnly` |
| Verifikasi ulang token di service | `shared/service-guards.js` → `userAuth`; `transkrip/index.js` → `/transkrip/sinkron` |
| Policy Engine (allow/deny + alasan, baca DB) | `gateway/policy.js` |
| Device terdaftar (`X-Device-ID`) | `gateway/middleware.js` → `verifyUserRequest` |
| Jam akses dapat dikonfigurasi | `shared/config.js` → `withinAccessHours` |
| Kepemilikan kelas/NIM dari database | `gateway/policy.js`, `nilai/index.js`, `transkrip/index.js` |
| Sinkron nilai final → tabel `transcripts` | `transkrip/index.js` → `/transkrip/sinkron` |
| Audit log | `shared/audit.js`; tabel `audit_logs` |

## Konfigurasi jam akses

Default 07.00 sampai sebelum 21.00 WIB. Untuk demo, ubah di `.env` lalu restart layanan:

```
ACCESS_HOUR_START=0
ACCESS_HOUR_END=24      # selalu buka
# ACCESS_HOUR_START=7 dan ACCESS_HOUR_END=7  => selalu tutup (demo penolakan)
```

## Contoh pengujian dengan curl

```bash
# Login (simpan token ke variabel; jangan ditampilkan/dibagikan)
TOKEN=$(curl -s -X POST http://127.0.0.1:3000/auth/login \
  -H 'Content-Type: application/json' -H 'X-Device-ID: HP-DOSEN-02' \
  -d '{"username":"dosen02","password":"DevDosen223!"}' | node -pe 'JSON.parse(require("fs").readFileSync(0)).accessToken')

# Lihat nilai kelas yang diampu (ambil gradeId)
curl -s http://127.0.0.1:3000/nilai -H "Authorization: Bearer $TOKEN" -H 'X-Device-ID: HP-DOSEN-02'

# Ubah nilai, lalu finalisasi kelas IF102 (id kelas = 2)
curl -s -X PUT http://127.0.0.1:3000/nilai/4 -H "Authorization: Bearer $TOKEN" \
  -H 'X-Device-ID: HP-DOSEN-02' -H 'Content-Type: application/json' -d '{"score":80}'
curl -s -X POST http://127.0.0.1:3000/kelas/2/finalisasi \
  -H "Authorization: Bearer $TOKEN" -H 'X-Device-ID: HP-DOSEN-02'

# Akses langsung ke service tanpa gateway secret => 403
curl -i http://127.0.0.1:3001/nilai
curl -i http://127.0.0.1:3002/transkrip

# Lihat audit log
sqlite3 database/zero-trust.db "select occurred_at,subject,endpoint,device_id,decision,reason,source from audit_logs order by id desc limit 15"
```

## Pengujian otomatis

Saat layanan sudah berjalan:

```bash
npm run test:e2e     # ±70 skenario positif dan negatif
npm run reset-demo   # mengembalikan nilai awal, finalisasi dibuka lagi, transkrip dikosongkan
```

Skenario: login (password salah, device asing), token kedaluwarsa/dipalsukan/role tidak cocok, refresh (rotasi, reuse, device lain), logout, kepemilikan kelas dosen, mahasiswa melihat NIM orang lain, admin, finalisasi + sinkron, ubah nilai final, token user di endpoint sinkron, akses langsung tanpa gateway secret, header identitas dipalsukan, jam akses, dan kelengkapan audit log.

## Catatan keamanan

- Gateway tidak meneruskan header identitas dari client; service membaca ulang user dan device dari database dari token yang diverifikasi sendiri.
- Role di token harus sama dengan role di database (token usang ditolak).
- Refresh token dipakai ulang → semua refresh token user dicabut (indikasi pencurian). Refresh token terikat ke device.
- Login dibatasi 5 kegagalan per 5 menit per username.
- Audit gagal ditulis → request gagal (fail closed).
- Finalisasi bersifat idempotent: jika sinkron transkrip gagal (502), panggil finalisasi lagi untuk mengulang sinkron.
- Jangan commit `.env` dan `*.db` (sudah ada di `.gitignore`).
