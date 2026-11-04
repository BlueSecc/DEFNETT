# Approval Authority Report (VM)

Authority berjalan sebagai UID `defnett-approval`, bind `127.0.0.1:8093` HTTPS, database `/var/lib/defnett-approval/approvals.sqlite3` (direktori 0700).

| Test ID | Test | Expected | Actual | Status | Evidence |
|---|---|---|---|---|---|
| AA-01 | Startup dan HTTPS | active, TLS | active; HTTP polos gagal | PASS | `vm-checks-root-collector.txt`, ISO-13 |
| AA-02 | Collector UID baca database Authority | ditolak | ditolak | PASS | UID-08 |
| AA-03 | Collector UID tulis direktori Authority | ditolak | ditolak | PASS | UID-09 |
| AA-04 | Executor UID baca database Authority | ditolak | ditolak | PASS | UID-10 |
| AA-05 | Collector UID baca akun operator / env token | ditolak | ditolak | PASS | UID-11..13 |
| AA-06 | API internal tanpa token / token salah | 401 | 401 / 401 | PASS | ISO-11, ISO-12 |
| AA-07 | Login akun tidak dikenal | 401 | 401 | PASS | TOK-05 |
| AA-08 | Viewer login dan baca dashboard | 200 | 200 / 200 | PASS | VW-01, VW-02 |
| AA-09 | Viewer menekan Serang | ditolak | 401 | PASS | VW-03 |
| AA-10 | Viewer menyetujui | ditolak | 401 | PASS | VW-04 |
| AA-11 | Serang dengan sesi tapi tanpa CSRF | 403 | 403 | PASS | `e2e-approval-vm.json` |
| AA-12 | Operator menyetujui, Executor mengklaim sekali | 6/6 | 6/6 klaim, 6/6 complete | PASS | journal executor, `e2e-approval-vm.json` |
| AA-13 | Baris APPROVED palsu ditulis Collector ke tabel lama di database bukti | Executor mengabaikan | tidak ada log Executor untuk baris itu dalam 8 detik | PASS | LEG-01, LEG-02 |
| AA-14 | Status eksekusi baris palsu tetap NONE | NONE | tidak tercatat karena bug variabel di skrip | NOT_VERIFIED | LEG-03; skrip sudah diperbaiki |
| AA-15 | Authority mati: login | 503 fail-closed | 503 | PASS | FS-01 |
| AA-16 | Authority mati: Serang | ditolak | 401 | PASS | FS-02 |
| AA-17 | Authority mati: Executor tidak mengeksekusi | tidak ada eksekusi | hanya galat poll (`URLError`) | PASS | FS-03 |
| AA-18 | Approval kedaluwarsa di runtime | ditolak | tidak dijalankan (TTL 900 detik) | NOT_RUN | unit test PASS |
| AA-19 | Replay approval di runtime | 409 | tidak dijalankan | NOT_RUN | unit test PASS |
| AA-20 | Target approval diubah | ditolak | tidak dijalankan di VM | NOT_RUN | test proses Authority PASS |
| AA-21 | AI tidak punya akses Authority | — | AI Patroli tidak diimplementasikan | NOT_IMPLEMENTED | — |

## Temuan

- Tabel `operator_approvals` lama masih ada di database bukti bersama, dan Collector bisa menulisnya. Executor tidak membacanya (kode hanya memakai API Authority, dan AA-13 membuktikannya di runtime). Sebaiknya tabel lama dihapus dari skema `db.py` agar tidak membingungkan audit.
- Antara deteksi dan persetujuan, server yang diserang tetap melayani (backend `UP` di 6/6 insiden sampai operator menyetujui). Ini konsekuensi desain human-in-the-loop, bukan kegagalan.
