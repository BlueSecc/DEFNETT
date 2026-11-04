# Performance Report (VM lab)

Hardware: Mac M1 8 GB; empat VM masing-masing 1 vCPU, 1,5 GB RAM. Diukur dari Mac lewat host-only. Ini angka lab kecil, bukan benchmark produksi.

## Latensi (n = 50 per jalur)

| Jalur | Median | p95 | Maks | Gagal |
|---|---|---|---|---|
| Dashboard HTTPS `GET /` (TLS handshake baru tiap request) | 4,1 ms | 4,7 ms | 13,7 ms | 0 |
| API dashboard tanpa sesi (cek sesi ke Authority, 401) | 6,1 ms | 6,9 ms | 8,4 ms | 0 |
| Blog WordPress lewat HAProxy | 9,5 ms | 22,7 ms | 1.080 ms | 0 |

## Respons insiden (n = 6, lihat `RECOVERY_E2E_REPORT.md`)

| Ukuran | Rentang | Median |
|---|---|---|
| Deteksi perubahan file (interval poll agent 3 s) | 0,39–2,76 s | 1,06 s |
| Serang → persetujuan muncul | 6,0–8,3 s | 6,4 s |
| Isolasi setelah setuju (teramati klien) | 0,05–0,34 s | 0,29 s |
| Pulih tanpa jeda demo | 0,53–2,04 s | 1,29 s |

## Sumber daya saat idle setelah uji

| VM | Load 1 menit | RAM terpakai | Disk / |
|---|---|---|---|
| gateway | 0,00 | 358 / 1.430 MB | 62% |
| server-a | 0,01 | 632 / 1.430 MB | 69% |
| server-b | 0,16 | 628 / 1.430 MB | 69% |
| collector | 0,18 | 460 / 1.430 MB | 68% |

RSS proses Collector: collector 71 MB, executor 38 MB, authority 32 MB. Journal di Collector 89 MB.

## Belum diukur

Latensi ingestion event, latensi tulis bukti, latensi trajectory, waktu startup layanan, dan latensi Modbus (OT tidak berjalan). Stress test tidak dijalankan.
