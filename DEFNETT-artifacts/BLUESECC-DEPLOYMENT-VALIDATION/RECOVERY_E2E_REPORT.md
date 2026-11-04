# Containment dan Recovery E2E Report (VM)

Dijalankan 3 November 2026 18:38–18:42 UTC dengan `lab/vm/e2e-approval.py` dari Mac. Kata sandi operator diketik user di prompt dan tidak disimpan.

Alur per insiden: operator menekan Serang (simulasi lab, disetujui dengan klik yang sama) → file kunci berubah → agent mendeteksi → Collector membuat persetujuan `RESTORE_KEYS` (PENDING) → operator menyetujui → Executor mengklaim sekali → memastikan server lain sehat → HAProxy menonaktifkan target → remediator mengarantina dan memulihkan dari master yang dicek manifes → health check → rejoin.

## Hasil

| Test ID | Insiden | Jalur | Hasil | Deteksi (s) | Isolasi setelah setuju, diamati klien (s) | Pulih tanpa jeda (s) | Setuju → UP (s) |
|---|---|---|---|---|---|---|---|
| E2E-1 | server-a | SSH | PASS | 0,95 | 0,29 | 2,04 | 17,47 |
| E2E-2 | server-b | Web | PASS | 0,39 | 0,29 | 1,55 | 16,72 |
| E2E-3 | server-a | Web | PASS | 1,50 | 0,34 | 0,53 | 16,14 |
| E2E-4 | server-b | SSH | PASS | 1,16 | 0,05 | 0,54 | 15,74 |
| E2E-5 | server-a | SSH | PASS | 2,76 | 0,05 | 1,53 | 16,92 |
| E2E-6 | server-b | Web | PASS | 0,46 | 0,29 | 1,04 | 16,48 |

Ringkasan (n = 6): deteksi 0,39–2,76 s (median 1,06); persetujuan muncul 6,0–8,3 s setelah Serang; isolasi teramati klien 0,05–0,34 s setelah setuju (metrik internal 0,01 s, tercatat di 4 dari 6); pulih tanpa jeda demo 0,53–2,04 s (median 1,29); setuju → UP 15,7–17,5 s, termasuk jeda demo 15 detik.

## Kelangsungan layanan

| Ukuran | Nilai |
|---|---|
| Permintaan blog selama uji | 506, sekitar 3 per detik selama sekitar 4 menit |
| HTTP 200 | 506 (0 gagal) |
| Dijawab Server A / B | 255 / 251 |
| Server survivor | server lainnya di tiap insiden |

Sampel 506 permintaan pada lab kecil. Ini bukan klaim zero downtime untuk produksi.

## Bukti dan integritas

- Verifikasi rantai bukti setelah uji: `ok`, 3.132 event (52 terverifikasi penuh, 3.080 hanya tautan karena event lama tahap 0).
- Manifes cocok dengan master di kedua server (SRV-04).

## Uji sebelumnya yang gagal (dicatat apa adanya)

| Percobaan | Hasil | Penyebab |
|---|---|---|
| Uji 1 (18:00) | 3 PASS, 3 FAIL | Authority di-restart untuk mengatur ulang kata sandi di tengah uji; sesi hilang |
| Uji 2 (18:02) | 3 PASS, lalu crash | Bug 16 KB di `authority_client.py` (sudah diperbaiki) |
| Uji 3 (18:38) | 6/6 PASS | setelah perbaikan |

## Belum diuji di runtime

- Pemulihan gagal karena master tidak cocok manifes (`master_untrusted`) sehingga server tetap terisolasi: unit test PASS, VM NOT_RUN.
- Survivor tidak sehat sehingga playbook berhenti: unit test PASS, VM NOT_RUN.
- Operator menolak persetujuan (Tolak): NOT_RUN di VM.
