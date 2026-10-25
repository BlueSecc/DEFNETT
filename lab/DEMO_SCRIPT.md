# Naskah Demo — Cyber Intrusion Patrol (DEFNETT)

Durasi target: **4–5 menit**. Semua yang disebut di bawah sudah terverifikasi ada di lab:
dashboard **Patrol** dengan peta Canvas 2D, panel **Skenario lab (digerakkan backend)**,
badge asal kejadian (`SIM`/`FIM`/`VISUAL`/`LIVE`), chip status backend, dan uji
skenario sisi backend via Scenario Driver. Jangan menampilkan panel atau tabel yang
tidak ada. Angka metrik yang dipakai mengikuti `lab/METRICS_REPORT.md` (Eksperimen:
100% request 200; n=289 sampel; deteksi rata-rata ≈1,1 s; containment ≈3,1 s;
recovery ≈11,8 s).

> Prinsip: **bukti dulu, animasi kemudian.** Visual dan demo sintetis selalu diberi
> label VISUAL di layar; event keamanan yang menentukan keputusan adalah event FIM
> nyata dari agent.

## Pratinjau persiapan (5–10 menit sebelum demo)

```sh
# A. Lab siap dan sehat
docker compose -f lab/compose.yaml -f lab/compose.canary.yaml -f lab/compose.demo-fast.yaml up -d --build
docker compose -f lab/compose.yaml -f lab/compose.canary.yaml -f lab/compose.demo-fast.yaml ps
curl -s http://127.0.0.1:8090/healthz                             # -> {"collector": true}
curl -s http://127.0.0.1:8090/v1/dashboard | python3 -m json.tool # backends server-a/b: "UP", heartbeat agents: online

# B. Layanan tampil kepada juri
curl -s http://127.0.0.1:8080/       # "DEFNETT lab response from server-a|server-b"
```

Buka browser: `http://127.0.0.1:8090/` (tab **Patrol**). Sediakan terminal kedua untuk
perintah bukti. Pastikan panel Skenario tidak sedang berjalan (status "Tidak berjalan").

## 0:00–0:30 — Kondisi awal: dua backend sehat

- **Jalankan/klik:** terminal → `curl -s http://127.0.0.1:8090/v1/dashboard`.
- **Juri melihat:** `backends.server-a = "UP"`, `backends.server-b = "UP"`, dua agent online. Chip backend di dashboard juga hijau UP.
- **Bukti teknis:** dua request ke `127.0.0.1:8080` menunjukkan rotasi round-robin ke server-a dan b.

```sh
curl -s http://127.0.0.1:8080/; curl -s http://127.0.0.1:8080/
```

- **Narasi:** "Ini lab DEFNETT: dua backend aplikasi redundan di balik HAProxy, dua agent pemantau integritas, satu collector. Keduanya sehat dan melayani trafik."
- **Gagal/mulihkan:** jika `backends` kosong/turun, panggil `curl -X POST http://127.0.0.1:8090/v1/lab/recover/server-a` (idem server-b) dan cek ulang; jika HAProxy 503, tunggu health check 2 s dan pastikan container `ps` sehat.

## 0:30–1:15 — Penyusup virtual mendekati aset (visual kanvas)

- **Jalankan/klik:** tab Patrol → klik **Kanvas demo (VISUAL)** (tombol toggle).
- **Juri melihat:** dua aktor sintetis bergerak dari sisi jaringan menuju file di Server A/B; label badge pada kartu aktor menyebut **VISUAL**. Legend juga menuliskan "Dekorasi kanvas (VISUAL)".
- **Bukti teknis:** jelaskan bahwa aktor ini murni browser: event demo tapi **tidak** ditulis ke database dan **tidak** memicu containment — hanya event nyata dari aplikasi/agent yang bisa.
- **Narasi:** "Penyusup didefinisikan melakukan penjelajahan ke file seperti .env ketika ia mencoba akses. Visual yang berjalan didukung sintetis; setiap aksi menyebut label VISUAL. Jangkar keputusan tetap di telemetri."
- **Gagal/mulihkan:** jika canvas kosong, aktifkan event demo lagi, pastikan `patrol.js` dimuat (DevTools 200) dan SSE terhubung, badge "Terhubung" di header.

## 1:15–2:30 — Kegiatan canary menghasilkan event nyata yang bisa dinilai

- **Jalankan/klik:** dari tab Patrol, gunakan panel **Skenario lab**, pilih
  **Containment diizinkan (positif)**, Target **Server A**, lalu **Mulai skenario**.
- **Juri melihat:**
  1. Baris `SIM · <8 digit run_id>` muncul di daftar event (kejadian probing `.env` dalam rekognisi); status backend Server A berubah UP → MAINT/DRAIN di chip yang relevan setelah decisi;
  2. Panel run berjalan menampilkan ladder: `PRECHECK → RECONNAISSANCE → CANARY_EVENT → EVIDENCE_VALIDATION → POLICY_EVALUATION → POLICY_APPROVED → TARGET_DRAINED …` berjalan otomatis sampai `COMPLETE`.
- **Bukti teknis (terminal kedua):**

```sh
RUN_ID=<id dari tab URL atau dari GET /api/demo/scenarios>
curl -s http://127.0.0.1:8090/api/demo/scenarios/$RUN_ID | python3 -m json.tool | head -60
curl -s http://127.0.0.1:8090/v1/events | python3 -c "
import json,sys
for e in json.load(sys.stdin)['events'][-6:]:
    print(e['host_id'], e['event_type'], e['path'], e['severity'], e['origin'])"
```

- **Narasi:** "Agen FIM mendeteksi file canary pada Server A dan mengirim ke collector; collector mengaitkan bukti (hash sebelum/sesudah, SHA-256, evidence ID) dan menjalankan Policy Gate."
- **Gagal/mulihkan:** jika tulisan skenario stuck >60 s, periksa `GET /api/demo/scenarios` (state PAUSED?) → klik `Lanjutkan`; jika state FAILED, baca ringkasan penolakan di panel, jelaskan itu perilaku keamanan, dan mulai run baru.

## 2:30–3:15 — Containment & pemulihan (skenario positif berlanjut dari tahap sebelumnya)

- **Juri melihat:** dari 2:30, backend Server A **di-drain dari rotasi** HAProxy (chip backend Server A menjadi DRAIN/MAINT), sementara Server B tetap melayani request. Canary dikarantina (`quarantine_path` di ladder detail), health check jalan, Server A kembali UP, dan run mencapai `COMPLETE`. Ladder mencetak tahap `HEALTH_VERIFICATION → RECOVERY → COMPLETE`.
- **Bukti teknis (terminal kedua):**

```sh
# Layanan tetap melayani selama drain (output dua backend):
curl -s http://127.0.0.1:8080/; curl -s http://127.0.0.1:8080/
# periksa run selesai: state COMPLETE, metrics.latencies:
curl -s http://127.0.0.1:8090/api/demo/scenarios/$RUN_ID | python3 -c "
import json,sys
d=json.load(sys.stdin)
print('state:', d['state'])
print(json.dumps((d.get('metrics') or {}).get('latencies', {})))"
```

- **Narasi:** "Selama drain, sampel HTTP 0,5 detik dalam eksperimen `(lab/METRICS_REPORT.md)`: 114/114 request sukses HTTP 200, mayoritas lewat Server B. Server A kembali dilayani berencana hanya setelah health check lolos dan karantina selesai."
- **Gagal/mulihkan:** jika `curl :8080` 502 — tunggu 2 saat atau cek backend UP; jika karantina gagal, `metrics-run<N>.json` menunjukkan tahap gagal; run ladder FAILED dan Server A tetap di-drain — jelaskan fail-safe: run menyebut status menjadi `HOLD-FOR-OPERATOR`, tidak memutasi server; pemulihan via `POST /v1/lab/recover/server-a`.

## 3:15–4:15 — Skenario negatif: kebijakan menolak containment (fail-closed)

- **Jalankan/klik:** di panel Skenario, pilih **Penolakan: survivor tidak sehat** → Target Server A → **Mulai skenario**.
- **Juri melihat:** ladder berpindah ke `POLICY_REJECTED → REJECTION_RECORDED → SERVICE_PRESERVED → COMPLETE`; panel menampilkan alasan penolakan: `SURVIVOR_NOT_HEALTHY`, `EVIDENCE_VALID ✔`, `TARGET_ALLOWED ✔`, dll.; badge backend Server-B ditandai tidak sehat saat jendela ujian (runner mem-disable survivor via socket admin HAProxy internal), dan tidak ada backend yang di-drain.
- **Bukti teknis (terminal kedua):**

```sh
curl -s http://127.0.0.1:8090/api/demo/scenarios | python3 -c "
import json,sys
runs = json.load(sys.stdin)['runs']
r = runs[0]
print('state:', r['state'])
print('alasan:', r['rejection_reason'])"
curl -s http://127.0.0.1:8080/ && echo " <- layanan tetap 200 (tidak ada backend di-drain)"
```

- **Narasi:** "Ini kanal fail-closed: ketika survivor tidak sehat atau bukti tidak cukup, kebijakan menolak containment otomatis, merekam seluruh alasan, dan dan tidak menyentuh backend mana pun. Keputusan selalu punya alasan."
- **Ulangi dengan bukti tidak valid:** pilih `Penolakan: bukti tidak memenuhi syarat` → alasan `EVIDENCE_INSUFFICIENT` terlihat di panel run; backend tetap 200.
- **Gagal/mulihkan:** jika skenario tidak memulai (HTTP 409), beri tahu juri bahwa sebelumnya masih ada run aktif — guard idempotensi `double-start denied`, tunggu run sebelumnya `COMPLETE`, lalu mulai lagi. Skenario auto-restore server-b jadi tidak perlu intervensi manual.

## 4:15–4:45 — Penutup: metrik aktual & hasil uji

- **Jalankan/klik:** terminal → `python3 lab/summarize_metrics.py` (atau tampil `lab/METRICS_REPORT.md`).
- **Juri melihat:** ringkasan fase.

```
baseline 37/37 (100%) | containment 114/114 (100%) | recovery 138/138 (100%)
detection median 813 ms | containment ≈3.1 s | recovery ≈11.8 s
```

- **Bukti teknis:** `lab/test-results/test-scenarios.csv` dan `lab/test-results/metrics-summary.csv` jujur; "semua hasil yang dihasilkan sistem, tidak ada input manual".
- **Narasi:** "Dua backend, dua agent, satu gate kebijakan: containment hanya berjalan bila bukti/kesehatan pass. Semua keputusan dibebankan alasan dan dapat direproduksi dengan skenario dari repo. Data lab ini masih awal; penilaian baseline A-D dan marhtorch tetap pekerjaan kami selanjutnya."
- **Gagal/mulihkan** (efek umum):
  - Collector down → `docker compose … up -d collector`, tunggu /healthz OK, refresh halaman.
  - Lab terpadatkan (rate limit) → tunggu cooldown 15 s; POLICY_RATE_MAX_ACTIONS=12 pada overlay canary.
  - Kalau semua gagal: `docker compose down -v` + `up -d --build` lagi menghabiskan sekitar 2 menit (arah reset yang terdokumentasi di README).

## Ceklis sebelum demo

- [ ] `curl -s http://127.0.0.1:8090/healthz` OK.
- [ ] Chip backend Server A/B UP di dashboard.
- [ ] Tab Patrol memuat (Kanvas + panel Skenario).
- [ ] Tidak ada run aktif saat halaman dibuka; jika ada dan bukan sengaja, `Batalkan` atau tunggu terminal.
- [ ] Terminal kedua siap dengan perintah bukti (yang di atas).
- [ ] Halaman `lab/METRICS_REPORT.md` dan `lab/test-results/` terbuka di jendela ketiga (opsional).
