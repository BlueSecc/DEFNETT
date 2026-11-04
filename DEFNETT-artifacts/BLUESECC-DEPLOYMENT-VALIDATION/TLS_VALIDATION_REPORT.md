# TLS Validation Report (VM)

Diuji dari Mac (192.168.56.1) dengan `lab/vm/vm-checks-host.py` dan dari dalam Collector.

| Test ID | Test | Expected | Actual | Status | Evidence |
|---|---|---|---|---|---|
| TLS-01 | Dashboard HTTPS dengan CA lab | HTTP 200 | HTTP 200 | PASS | `test-results/vm-checks-host.json` |
| TLS-02 | CA tidak dikenal (trust store sistem) | ditolak | `unable to get local issuer certificate` | PASS | sama |
| TLS-03 | Hostname salah | ditolak | `Hostname mismatch` untuk `salah.defnett.lab` | PASS | sama |
| TLS-04 | Sertifikat kedaluwarsa (CA dan sertifikat uji khusus, `tls_support.client_context`) | ditolak | `certificate has expired` | PASS | dijalankan ulang setelah CA uji diperbaiki (lihat catatan) |
| TLS-05 | HTTP polos ke port 8443 | bukan 200 | koneksi diputus server | PASS | sama |
| TLS-06 | Port lama 8090 | tertutup | refused | PASS | sama |
| TLS-07 | Authority lewat HTTP polos | bukan 200 | gagal (000) | PASS | ISO-13 |
| TLS-08 | Cookie sesi | Secure, HttpOnly, SameSite=Strict | ketiganya ada | PASS | `e2e-approval-vm.json` checks |
| TLS-09 | SAN sertifikat Collector | IP yang dipakai | `DNS:collector`, `IP:192.168.56.20` | PASS | `openssl x509 -ext subjectAltName` |
| TLS-10 | Agent → Collector HTTPS dengan CA | 202 | heartbeat/snapshot 202 dari .11 dan .12 | PASS | journal collector |
| TLS-11 | Executor → Remediator HTTPS | berhasil | playbook pulih 6/6 | PASS | `RECOVERY_E2E_REPORT.md` |
| TLS-12 | Browser dashboard tanpa peringatan sertifikat | trusted | Panel browser aplikasi (Chromium) memuat `https://192.168.56.20:8443/` tanpa peringatan setelah CA dipercaya khusus SSL di keychain login; `isSecureContext=true` | PASS | uji 4 Nov 2026; kepercayaan CA dicabut lagi oleh user setelahnya |
| TLS-14 | Login, Serang, Setujui, Tolak, dan logout lewat browser (Safari) | berhasil | Login 200; Serang 202 (20:06:24); Setujui 200, pulih 20:06:59; Tolak 200 tanpa eksekusi (19:49:24); logout 200 dan sesi berakhir (20:07:20) | PASS setelah 6 perbaikan | journal collector, executor, authority, remediator |
| TLS-13 | mTLS | — | tidak diimplementasikan | NOT_IMPLEMENTED | runbook |

Catatan TLS-04: percobaan pertama FAIL karena CA uji buatan skrip tidak punya ekstensi `keyUsage`, sehingga Python menolak dengan alasan lain. Itu kesalahan skrip uji. Setelah CA uji diberi `basicConstraints` dan `keyUsage`, penolakannya karena kedaluwarsa. Sertifikat deployment tidak disentuh.

Token, bukan sertifikat klien, yang membuktikan identitas layanan. Sertifikat lab berlaku 90 hari (CA 365 hari); tidak ada CRL/OCSP.

## Bug yang ditemukan saat uji browser (semua diperbaiki dan dites ulang)

| Bug | Dampak | Perbaikan |
|---|---|---|
| Refresh tiap 2,5 dtk memanggil ulang modal login dan memindahkan kursor ke kolom user | Kata sandi tidak bisa diketik | Modal hanya fokus saat pertama dibuka (`dashboard.js`) |
| `.op-modal { display: grid }` mengalahkan atribut `hidden` | Popup login tidak pernah hilang walau login sukses | `.op-modal[hidden] { display: none; }` (`dashboard.css`) |
| Sebelum login tampil "Collector tidak dapat dijangkau" | Menyesatkan | Status "Belum masuk" (`dashboard.js`) |
| `GET /v1/operator/whoami` dijawab 404 (hanya ada di `do_POST`) | Setelah reload CSRF hilang, klik pertama 403, logout gagal | Rute GET whoami (`collector.py`), test baru |
| Logout dengan body kosong (`Content-Length: 0`) dijawab 400 oleh proxy | Sesi tidak pernah berakhir di server | Body hanya dibaca bila panjang > 0 (`collector.py`), test proses Authority |
| Tolak tidak menutup insiden (`DETECTED` selamanya) | Tombol Serang host itu terkunci permanen | Tolak menutup insiden sebagai `REJECTED` (`collector.py`, `patrol.js`), test baru |

## Temuan desain yang belum diperbaiki

Setelah operator menolak pemulihan, kunci tetap berubah dan remediator menolak simulasi berikutnya (`409 key_not_pristine`). Tidak ada tombol untuk meminta pemulihan lagi. Pemulihan manual: `sudo sh lab/vm/restore-kunci.sh` di server terkait (master dicek manifes, file berubah disalin ke karantina). Perubahan balik ini dikenali sebagai pemulihan sah (INFORMATIONAL, tanpa approval).
