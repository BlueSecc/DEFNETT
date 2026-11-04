# VM Deployment Report

## Cutover

Keempat VM sebelumnya menjalankan versi tahap 0 (respons otomatis, dashboard HTTP :8090). Cutover ke versi persetujuan operator + TLS dijalankan 3 November 2026 dengan `lab/vm/cutover-stage.sh` (dari Mac) dan `lab/vm/cutover-vm.sh` (root, per VM), mengikuti `SECURITY_CUTOVER_RUNBOOK.md`:

1. CA dan sertifikat lab dibuat di Mac (`provision-lab-tls.sh`); kunci CA tidak pernah keluar dari Mac.
2. Tiga token layanan acak terpisah (Executor, Collector→Authority, Executor→Authority).
3. Backup `/etc/defnett`, `/opt/defnett`, unit, dan database bukti ke `/root/defnett-backup-<waktu>` di tiap VM sebelum perubahan.
4. Env digabung per kunci (kunci lama yang tidak ada di template dipertahankan; `ENABLE_LAB_AUTOREPAIR` dihapus).
5. Trust anchor server: kunci bersih dibuat ulang dari template seed repo (bukan dari `/data`), manifes sha256 di `/etc/defnett/master-manifest.json`.
6. Akun layanan dan izin berkas lewat `provision-service-users.sh`; urutan start Authority → Executor → Collector.

Database approval lama: VM sebelumnya tahap 0 dan tidak memakai approval, jadi tidak ada approval tertunda untuk ditinjau. Tidak ada migrasi otomatis.

Rollback: salin balik isi `/root/defnett-backup-<waktu>`, `systemctl daemon-reload`, restart layanan lama. Database tidak dihapus.

## Status layanan

| Test ID | Test | Expected | Actual | Status | Evidence |
|---|---|---|---|---|---|
| VM-01 | Empat VM teridentifikasi | 4 | 4, peran sesuai konfigurasi | PASS | `ENVIRONMENT_INVENTORY.md` |
| VM-02 | Unit Collector berjalan dengan UID terpisah | 3 UID berbeda | defnett-approval, defnett-executor, defnett-collector; active, enabled | PASS | `test-results/vm-checks-root-collector.txt` |
| VM-03 | `systemd-analyze verify` unit Collector | 0 | 0 | PASS | sama |
| VM-04 | Agent, remediator, app di server A/B | active | active, user `defnett` | PASS | `vm-checks-root-server-*.txt` |
| VM-05 | HAProxy | active | active | PASS | `vm-checks-root-gateway.txt` |
| VM-06 | Agent reconnect setelah Collector restart | heartbeat 202 lagi | 202 dari .11 dan .12 setelah restart | PASS | journal collector |
| VM-07 | Persistensi bukti lintas restart | rantai tetap utuh | 3.132 event, status `ok` | PASS | `test-results/e2e-approval-vm.json` |

## Masalah yang ditemukan dan diperbaiki saat cutover

Lihat tabel di `SOURCE_TRANSFER_AUDIT.md`. Yang muncul di runtime VM: crash collector saat start, crash `provision_master.py`, URL agent tanpa `/v1`, dashboard crash setelah beberapa insiden (16 KB), `restored-hashes` 404, dan aturan firewall lama `192.168.56.1 → :8091` di kedua server (dihapus).

## Catatan operasional

- Sesi operator disimpan di memori Authority. Restart Authority mengeluarkan semua operator. Ini terlihat nyata saat uji pertama terputus oleh restart Authority untuk mengatur ulang kata sandi.
- Login dikunci sementara setelah 5 kegagalan, dihitung per alamat sumber. Authority melihat semua login lewat Collector sebagai `127.0.0.1`, jadi kunci ini berlaku bersama untuk semua operator.
- Akun `uji-viewer` dibuat untuk uji izin dengan kata sandi acak yang tidak pernah ditampilkan. Belum ada CLI untuk menghapus akun; hapus manual dari `operator_auth.json` bila tidak diperlukan.
