# Laporan Metrik Ketersediaan dan Containment — Lab DEFNETT

Tanggal eksperimen: **24 Oktober 2026** (UTC). Eksperimen dilakukan pada lab Docker lokal
yang berjalan dengan overlay `compose.yaml + compose.canary.yaml + compose.demo-fast.yaml`
(delay pemulihan demo = 12 detik; ambang Policy Gate lab: `POLICY_RATE_MAX_ACTIONS=12`,
`POLICY_COOLDOWN_SECONDS=15`).

## 1. Sumber data dan pembagian

| Kumpulan | Asal | Sifat |
|---|---|---|
| Data sebelumnya | `test-results/test-scenarios.csv` + `test-results/<scenario>.json` dari `sh lab/test-scenarios.sh` | Hasil pengujian live Scenario Driver (verdict PASS, alasan penolakan, metrik latensi per run dari collector) |
| Data baru | `test-results/metrics-raw.csv`, `metrics-raw-run<N>.csv`, `metrics-run<N>.json`, `metrics-summary.csv`, `metrics-api-<N>.json` | **Eksperimen baru** `python3 lab/measure_metrics.py` pada 24 Okt 2026: pengukuran HTTP nyata via HAProxy ts. 12:19–12:22 UTC |

**Cara ukur**: sampler terpisah dari runner mengirim request `GET /` ke HAProxy
(`127.0.0.1:8080`) tiap **0,5 detik** dan mencatat timestamp + kode HTTP nyata +
marker backend (menuruni isi respons, bukan status kesehatan container). Request gagal
(timeout/koneksi) tercatat `http_code=000`. Keberhasilan **tidak** disimpulkan dari
health check container.

Kondisi eksperimen: 3 pengulangan (run 1–3) skenario `containment_allowed`
(target = server-a, survivor = server-b), masing-masing 3 fase:
baseline (12 request interval 0,5 s) → containment (sampler selama run aktif) →
recovery (sampel 20 detik pasca-run). Lab telah melewati `down -v` dan `up --build`
pada sesi yang sama; hasilnya model lab bersih.

## 2. Angka utama (eksperimen baru, n=3 run)

| Fase | Request total | HTTP 200 | Gagal | Success % |
|---|---|---|---|---|
| Baseline | 37 | 37 | 0 | 100% |
| Containment (drain aktif) | 114 | 114 | 0 | 100% |
| Recovery (pasca-rejoin) | 138 | 138 | 0 | 100% |
| **Total** | **289** | **289** | **0** | **100%** |

Distribusi backend saat containment (berdasarkan marker isi respons, bukan status health):
`server-b` 91/114 (79,8%) — backend survivor melayani mayoritas trafik selama target
di-drain; `server-a` 23/114 (20,2%) dari request yang jatuh sebelum drain efektif dan
pada fase verifikasi pra-rejoin. Pada pemulihan, distribusi kembali seimbang
(≈50/50, round-robin normal).

Latensi per tahap dari metrik Scenario Driver (ms, n=3):
detection 813 / 2131 / 485 (median 813); containment 3083 / 3073 / 3078 (≈3,1 s);
recovery 11816 / 11737 / 11783 (≈11,8 s); total run 17893 / 19334 / 17409 (≈17,4–19,3 s).

Jendela timing eksperimen (UTC): baseline mulai 12:19:13; containment 12:19:20–12:21:14;
recovery 12:19:38–12:21:37 (fase antar-run tumpang tindih sesuai sampling tanpa jeda).

## 3. Interpretasi jujur

- **100% berhasil pada 289 request ini adalah pengukuran lab, bukan jaminan.** Volume dan skenario terbatas; tidak menguji kegagalan singkat HAProxy, restart container, buffer penuh, latensi jaringan, atau beban tinggi.
- Angka zero-failure selama drain konsisten dengan tujuan desain (survivor tetap melayani), dan sejalan dengan hasil pengujian live sebelumnya pada `test-scenarios.csv` (probe 6/6 sukses saat drain pada run containment_allowed versi test suite).
- **Share server-a 20,2% fase containment adalah artefak agregasi fase, bukan kebocoran rotasi.** Analisis timestamp per run (12, 15, 11 + 6, 9, 7 baris) menunjukkan seluruh request ke server-a terjadi **sebelum step `TARGET_DRAINED`** (masa precheck/Policy) atau **setelah `HEALTH_VERIFICATION`** (rejoin kembali melayani). Pada jendela drain terkonfirmasi masing-masing run, ke server-a: **0 request**.
- Bukti eksperimen terverifikasi (§4): 88/88 request baru murni diarahkan ke survivor, 0 ke target — containment efektif bagi koneksi baru.
- Seluruh data dihasilkan dari sistem yang sama yang dilaporkan; tidak ada angka yang dihasilkan manual.

## 4. Eksperimen tambahan: burst pada jendela DRAIN terverifikasi (24 Okt 2026, 12:53–12:55 UTC)

Eksperimen kedua `python3 lab/measure_burst.py` menjalankan 3 run tersendiri dan **hanya**
mengirim request ketika collector sudah mencatat step `TARGET_DRAINED` (drain
terkonfirmasi via runtime API HAProxy) dan berhenti pada `HEALTH_VERIFICATION`
(rejoin). Setiap request memakai **koneksi HTTP baru** (urllib + header
`Connection: close`), tidak memakai pool keep-alive, sehingga tidak ada kemungkinan
koneksi persisten pra-drain masih dipakai.

3 run, setiap jendela drain ≈9–10 detik, sampler interval ≈0,35 s:

| Run | drain_ts → rejoin_ts (UTC) | Dalam jendela | OK 200 | Ke target (server-a) | Ke survivor (server-b) | no_response |
|---|---|---|---|---|---|---|
| 1 | 12:53:47 → 12:53:56 | 30 | 30 | 0 | 30 | 0 |
| 2 | 12:54:26 → 12:54:36 | 29 | 29 | 0 | 29 | 0 |
| 3 | 12:55:06 → 12:55:15 | 29 | 29 | 0 | 29 | 0 |
| **Total** | | **88** | **88** | **0** | **88** | **0** |

Artefak terpisah: `test-results/burst-raw.csv`, `burst-run<N>.json` (ladder + timestamp step), `burst-summary.csv`. Identitas target/survivor tidak diasumsikan — setiap row mencatat kolom `target,survivor` dari payload run (3 run semuanya server-a/server-b dan survivor health `UP` diverifikasi sebelum burst). Data eksperimen sebelumnya (§2) tidak diubah atau dihapus.

**Catatan historis 88/88:** `test-results/burst-run<N>.json` tertangkap saat instrumen masih snapshot status tahap rejoin, sehingga field `state` menyimpan `RECOVERY`, bukan `COMPLETE` — ketiga JSON itu dipertahankan apa adanya sebagai data historis dan **tidak** digunakan sebagai bukti final burst; bukti final adalah baris `verified_drain` di `burst-raw.csv` (88 baris, semua 200 ke survivor, 0 ke target) plus tabel ringkas di atas. Instrumen sudah diperbaiki agar JSON run berikutnya tertangkap saat state terminal (`COMPLETE`); contoh run terverifikasi: `test-results/json-state-verify/burst-run1.json`.

**Rumusan untuk laporan (metodologi dibedakan dari eksperimen fase di §2):**

> Pada tiga run pengujian laboratorium, sebanyak 88 dari 88 request koneksi baru yang dikirim selama jendela drain terverifikasi mendapat HTTP 200 melalui backend survivor, dan tidak ada request yang diarahkan ke backend target.

Angka ini adalah observasi pada skenario, volume, dan lab yang terbatas — bukan jaminan ketersediaan universal. Eksperimen ini juga saling melengkapi, tidak digabung, dengan eksperimen fase (289 request di §2) yang memakai sampler interval konstan di seluruh proses inklusif pre/post drain.

## 5. Cara mengulang eksperimen

```sh
# lab harus berjalan (panduan penuh di lab/README.md);
# skrip menulis berkas baru ke test-results/ tanpa menghapus data lama
RUNS=3 python3 lab/measure_metrics.py   # eksperimen fase baseline/containment/recovery
python3 lab/summarize_metrics.py        # ringkasan dari CSV mentah
RUNS=3 python3 lab/measure_burst.py     # burst hanya pada jendela DRAIN terverifikasi
```

Skema CSV mentah: `phase,run_id,ts,http_code,backend_marker`.
`http_code=000` berarti request gagal total; marker `no_response` idem.
