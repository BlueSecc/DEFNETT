# DEFNETT v3 — Blueprint Teknis

**Status:** Revisi rancangan per 24 Oktober 2026; memisahkan baseline lab, target implementasi, dan demo terpadu\
**Nama:** DEFNETT\
**Tujuan:** Menautkan event dan bukti keamanan ke keputusan respons yang dibatasi kebijakan, menjaga layanan survivor, serta menyajikan alur itu melalui demo visual Cyber Intrusion Patrol.

> **Batas klaim:** blueprint ini mencakup baseline lab yang telah ada dan target teknis yang belum selesai. Pada kode yang diperiksa, Patrol 2D dan demo sintetis browser sudah ada, tetapi animasi sintetis belum menulis event ke database; jalur canary terpisah dapat memicu respons terbatas. Classifier terkalibrasi, trajectory engine multi-step yang matang, Cloud/Local LLM, dan Policy Gate umum belum terintegrasi. Penurunan false positive, keselamatan respons, dan waktu respons belum terbukti. Semua ambang dan target tetap merupakan parameter eksperimen sampai diuji.

## 1. Keputusan desain v3

| Bagian | Keputusan |
| ------------------------ | -------------------------------------------------------------------------------------------------------------- |
| Lingkungan | Dua server Linux, HAProxy, dan satu control plane terpisah |
| Monitoring | Baseline: custom agent FIM pada `/data` dan event aplikasi. Target lanjutan: adapter Wazuh/Suricata setelah pemetaan skema dan integrasi dibangun |
| Peran dataset | AIT-ADS untuk evaluasi offline korelasi dan classifier; lab sendiri untuk uji integrasi, keselamatan, dan respons |
| Unit keputusan | Trajectory (rangkaian event dalam jendela waktu), bukan alert tunggal |
| Konteks | Trajectory Engine menyusun alert menurut waktu, host, bukti, dan hubungan kejadian, dengan batas ukuran konteks |
| AI | Target: Cloud LLM utama dan Local LLM fallback dengan kontrak JSON sama. Status baseline: belum terhubung ke lab |
| Batas AI | LLM tidak memiliki shell/root/akses eksekusi atau hak isolasi |
| Peran LLM | Penasihat: verdict hanya boleh menaikkan eskalasi atau menahan aksi otomatis; tidak masuk rumus R dan tidak pernah menjadi izin |
| Risk Engine | Target: `P_attack` dari classifier berlabel dan terkalibrasi. Status baseline: skor/keputusan berbasis aturan deterministik, belum berupa probabilitas classifier |
| Formula | `R = P_attack × I_CIA`; `I_CIA = (C + I + A) / 3`; skala 0-3; adaptasi prototipe; `I_max` dicatat dan dipakai sebagai pengaman |
| Policy Gate | Empat tingkat (catat, alert, operator, otomatis); aksi otomatis hanya jika semua prasyarat bagian 11 terpenuhi |
| Anti-manipulasi respons | Maksimal satu backend di-drain, cooldown, rate limit, aturan lintas-host, dan penanda lonjakan alert |
| Respons awal | Baseline: `DRY_RUN` dan playbook canary khusus lab yang dapat mengeluarkan satu backend dari rotasi HAProxy. Policy Gate umum serta kebijakan fail-safe lintas kondisi masih target |
| Data cloud | Samarkan dan minimalkan data; local-only jika cloud dilarang |
| Evaluasi | Target: ablasi A-D dan uji lab. Hasil hanya boleh diklaim setelah test harness, ground truth, dan metrik benar-benar dijalankan |

## 2. Perubahan utama pada v3

| Topik | Pembaruan v3 | Alasan |
| ------------------ | -------------------------------------------------------------------------------------------------- | ---------------- |
| Implementasi vs rancangan | Membuat daftar eksplisit fitur yang sudah ada, belum ada, dan menjadi target | Mencegah proposal mengklaim kemampuan yang belum diimplementasikan |
| Patrol | Menetapkan Cyber Intrusion Patrol sebagai lapisan visualisasi dan Scenario Driver sebagai jalur demo terkontrol | Animasi harus membantu memahami bukti, bukan menggantikan bukti |
| Sumber kebenaran | Event collector, state backend, health check, dan hasil request menjadi sumber status keamanan; gerak karakter hanya representasi | Memisahkan tampilan dari mekanisme keamanan |
| Skenario utama | Memformalkan alur normal → rekognisi → canary → keputusan → containment → karantina → verifikasi/rejoin | Demo dapat diulang dan dinilai dengan kriteria penerimaan |
| Skenario negatif | Menambahkan skenario backend survivor tidak sehat/evidence invalid yang wajib menahan containment | Menunjukkan perilaku fail-safe, tidak hanya jalur sukses |
| Novelty dan SoA | Mempersempit positioning setelah AIT-ADS (2024), CIPHER-A (2026), dan AIDA preprint (2026) | Klaim generik AI/alert correlation/safe response sudah terlalu luas |
| Prioritas engineering | Memprioritaskan integrasi event-to-demo dan continuity-of-service sebelum memperbesar UI atau mengklaim AI penuh | Mengamankan proof-of-function yang bisa didemonstrasikan |

### 2.1 Baseline implementasi yang terverifikasi dari source

Bagian ini mendeskripsikan keadaan kode yang diperiksa, bukan target arsitektur.

| Komponen | Keadaan baseline | Batas klaim saat ini |
|---|---|---|
| Infrastruktur | Docker Compose menyiapkan dua backend aplikasi, HAProxy, collector, dua agent, worker remediation, dan dashboard | Lab lokal; bukan deployment produksi |
| File Integrity Monitoring | Agent melakukan polling pada `/data` dan mengirim snapshot/event perubahan hash SHA-256 | Tidak memantau seluruh filesystem host; tidak setara EDR |
| Event aplikasi | App mencatat request yang diizinkan/ditolak pada route tertentu; file publik dibatasi oleh konfigurasi | Tidak ada telemetry Wazuh/Suricata yang terintegrasi pada baseline ini |
| Bukti | Collector menyimpan event dan tahapan playbook di SQLite dengan hash chain | Hash chain tidak otomatis tahan manipulasi jika database/keadaan terakhir bisa diganti pihak yang sama |
| Risk/decision | Skor serta verdict utama berbasis aturan deterministik | Belum ada classifier terlatih/terkalibrasi; angka skor heuristik tidak boleh disebut probabilitas model |
| Patrol UI | Canvas 2D memetakan file berdasarkan snapshot, karakter agent dan aktor, daftar event, filter, dan kontrol demo browser | Aktor sintetis berjalan di browser; event itu sendiri tidak masuk database dan tidak memicu containment |
| Respons canary | Overlay canary dapat memproses file uji dengan path/marker khusus, mengeluarkan target dari rotasi HAProxy, mengarantina file, menjalankan health check, lalu rejoin bila sehat | Playbook terbatas; bukan antivirus, bukan isolasi host penuh, dan bukan Policy Gate umum |
| AI lanjutan | Belum ditemukan integrasi LLM Cloud/Local atau classifier terkalibrasi pada lab yang diperiksa | Semua kemampuan tersebut adalah target, bukan fitur saat ini |

### 2.2 Positioning: research gap, novelty, dan SoA

**SoA yang relevan.** AIT-ADS menyediakan dataset alert multi-step untuk menguji korelasi dan attack graph (Landauer et al., 2024). CIPHER-A (terbit open access, 29 Agustus 2026) membahas validasi konsekuensi respons sebelum eksekusi dan evaluasi ulang terhadap adaptasi penyerang. AIDA (preprint 7 Oktober 2026) membahas verifikasi investigasi triase SOC berbasis bukti, ledger investigasi, dan adjudikasi. NIST SP 800-82 Rev. 3 (final, 2023) menegaskan kontrol keamanan OT harus memperhatikan performa, reliabilitas, dan keselamatan; Rev. 4 masih Initial Public Draft (21 September 2026, komentar s.d. 30 November 2026). DEFNETT **tidak** mengklaim kebaruan tunggal pada LLM, korelasi multi-step, validasi bukti, atau respons otomatis yang aman keempatnya sudah ada publikasinya.

**Research gap yang diuji.** Trade-off antara containment backend yang terindikasi terkompromi dan kontinuitas layanan pada topologi dua backend redundan sering dibahas kualitatif, tetapi nyaris tidak pernah diukur bersama bukti dan gate kebijakan pada satu harness sederhana yang bisa direproduksi. Empat pertanyaan evaluasi DEFNETT, masing-masing sudah punya pengukuran di lab:

1. Bukti + prasyarat kebijakan menahan containment yang tidak tepat? → `containment_blocked_evidence_invalid` (rejected; `EVIDENCE_INSUFFICIENT`).
2. Survivor tetap melayani request ketika target diisolasi? → `containment_allowed` (probe saat drain: 6/6 sukses kedua backend) dan burst pada jendela drain **terverifikasi timestamp** (`measure_burst.py`, 3 run): **88/88 request baru (koneksi baru per request) → 0 ke target, 88/88 ke survivor, 100% HTTP 200**.
3. Respons ditolak bila survivor tidak sehat / bukti tak memadai? → `containment_blocked_survivor_down` (rejected; `SURVIVOR_NOT_HEALTHY`) dan #1.
4. Pemulihan hanya setelah syarat kesehatan terpenuhi? → tahap `HEALTH_VERIFICATION → RECOVERY → COMPLETE`, health check HAProxy pada rejoin (`sh lab/test-scenarios.sh`).

**Novelty yang diusulkan.** Kontribusi dibagi tiga lapis untuk defensibilitas: (a) **desain** — ladder evidence-gated, availability-aware containment dengan prasyarat survivor dan fail-closed; (b) **implementasi** — lab dua backend + HAProxy dengan 11 skenario state, 11 pemeriksaan Policy Gate, dan audit SQLite ber-hash-chain; (c) **hasil terukur** — verdict PASS 3 skenario + guard HTTP 409, latensi per tahap, rasio keberhasilan request selama drain (lihat `lab/METRICS_REPORT.md`). Hasil lapisan (c) terbatas pada lab; belum ada perbandingan baseline A-D (ablasi) — klaim "menurunkan false containment" tetap hipotesis. Demo game Patrol adalah antarmuka penjelas, bukan novelty akademik utama.

Rujukan utama: [AIT-ADS / CSET 2024](https://doi.org/10.1145/3675741.3675748), [CIPHER-A (2026)](https://link.springer.com/article/10.1007/s44163-026-02058-6), [AIDA preprint (7 Oktober 2026)](https://arxiv.org/abs/2610.10608), [NIST SP 800-82 Rev. 3](https://csrc.nist.gov/pubs/sp/800/82/r3/final) dan [Rev. 4 IPD (21 September 2026)](https://csrc.nist.gov/pubs/sp/800/82/r4/ipd). AIDA ditandai preprint, bukan publikasi peer-reviewed.

### 2.3 Cyber Intrusion Patrol: peran dan prinsip desain

Cyber Intrusion Patrol adalah lapisan visual top-down yang terinspirasi oleh cara game stealth menggambarkan karakter, ruangan, objek target, dan urutan kejadian. Tujuannya agar juri memahami urutan serangan dan respons tanpa harus membaca log mentah. Ini bukan game keamanan independen; antarmuka hanya mengendalikan skenario lab yang telah ditentukan.

**Prinsip inti:** *backend drives the story, not the other way around.* Status deteksi, containment, karantina, kesehatan backend, dan rejoin harus berasal dari API collector/monitor/test harness. Posisi penyusup dan agent patroli hanya boleh disebut animasi atau simulasi. Gerakan karakter tidak boleh menulis evidence, menaikkan risk score, atau memicu respons.

#### Skenario demo utama

| Tahap | Aksi lab/sumber kebenaran | Yang divisualisasikan | Bukti yang ditunjukkan |
|---|---|---|---|
| 0. Normal | Health check dan request baseline ke layanan melalui HAProxy | Dua backend sehat; agent patroli bergerak | Status backend dan baseline request |
| 1. Rekognisi | Browser/client meminta route atau file yang dibatasi; aplikasi menolak dan mencatat event | Aktor penyusup mendekati ruang server | Event request ditolak, waktu, host, dan path relatif yang telah disanitasi |
| 2. Canary | Scenario Driver memanggil fixture terbatas yang menulis marker canary pada path tetap di backend target | Aktor mendekati file target; file berubah status | Event FIM, hash sebelum/sesudah, host target, evidence ID |
| 3. Keputusan | Collector/Policy Gate memvalidasi bukti, mode operasi, backend survivor, serta batas keselamatan | Panel keputusan berubah dari investigasi ke tindakan/ditahan | Reason code dan daftar prasyarat lulus/gagal |
| 4. Containment | Dalam mode canary lab dan setelah prasyarat lulus, hanya backend target dikeluarkan dari rotasi HAProxy | Rute trafik bergeser ke survivor | Status HAProxy dan request yang berhasil/gagal selama interval |
| 5. Karantina | Worker hanya memindahkan fixture yang path, tipe, ukuran, dan marker-nya sesuai allowlist | File canary masuk area karantina | SHA-256, path sumber/tujuan, status verifikasi |
| 6. Recovery | Health check dijalankan; target hanya rejoin jika lulus | Status target kembali sehat | Log health check, perubahan backend, dan request end-to-end |

Jeda pemulihan 180 detik yang ada sekarang adalah konfigurasi demo saat ini. Untuk presentasi dapat dibuat profil demo terpisah dengan jeda 10–15 detik, tetapi perubahan itu harus diimplementasikan sebagai konfigurasi `DEMO_RECOVERY_DELAY_SECONDS` dan tidak boleh mengubah kebijakan produksi. Jika konfigurasi tersebut belum dibuat, dokumentasi dan demo harus tetap menyebut jeda aktual.

#### Skenario negatif yang wajib disiapkan

- Backend survivor tidak sehat: Policy Gate menahan drain/containment otomatis dan meminta operator.
- Bukti invalid atau canary tidak cocok: worker tidak memindahkan file dan tindakan tidak dilanjutkan.
- Agent/collector kehilangan telemetry: UI menunjukkan status `unknown`/`telemetry_gap`, bukan hijau/aman.
- Reset atau interupsi skenario: tidak menghapus data di luar file fixture yang ditetapkan dan tidak menjalankan perintah arbitrer.

#### Perilaku antarmuka yang ditargetkan

- Tombol **Mulai skenario**, **Jeda/Lanjutkan**, dan **Reset demo**; reset hanya mengembalikan state visual dan fixture demo yang ditentukan.
- Pilihan skenario **Containment diizinkan** dan **Containment ditahan** untuk menampilkan jalur positif serta fail-safe.
- Panel timeline dengan timestamp, host, event/evidence ID, risk/decision status, alasan Policy Gate, aksi, hasil health check, serta service request success rate.
- Filter/legend yang membedakan `LIVE EVENT`, `LAB FIXTURE`, dan `VISUAL ONLY`.
- Event sintetis dari tombol **Mulai demo** yang lama tidak boleh masuk ke evidence store. Fitur itu boleh dipertahankan sebagai mode animasi terpisah, tetapi harus diberi label dan tidak boleh dicampur dengan hasil skenario terpadu.

#### Kontrak keselamatan Scenario Driver

- Hanya aktif pada profile lab lokal dan endpoint yang diizinkan; jangan terbitkan mode scenario ke jaringan operasional.
- Gunakan fixture canary dengan path dan marker tetap; jangan menerima nama file/path/perintah shell bebas dari UI atau LLM.
- Rate limit, idempotency key, run ID, timeout, dan status akhir yang eksplisit (`COMPLETE`, `FAILED`, `CANCELLED`).
- Simpan event dan hasil tiap tahap sebagai audit terpisah; UI tidak boleh menyimpulkan sukses hanya dari animasi.
- Bila hasil API tak tersedia atau tidak cocok dengan keadaan backend, status ditampilkan sebagai `UNKNOWN/FAILED` dan tidak mengeksekusi tahap berikutnya.

#### Kontrak API Scenario Driver (terimplementasi di lab, `lab/scenario.py`)

| Method dan route aktual | Fungsi | Pembatasan |
|---|---|---|
| `POST /api/demo/scenarios` | Memulai skenario `containment_allowed`, `containment_blocked_survivor_down`, `containment_blocked_evidence_invalid`; server membuat `run_id` | Enum skenario allowlist; hanya profile lab; tidak menerima shell command atau path arbitrer; run aktif ganda mendapat HTTP 409 |
| `POST /api/demo/scenarios/{run_id}/pause` | Menjeda kemajuan urutan demo | Tidak membatalkan aksi backend yang sudah terjadi; status aktual tetap dibaca dari backend |
| `POST /api/demo/scenarios/{run_id}/resume` | Melanjutkan langkah yang belum dieksekusi | Validasi ulang state backend dan idempotency sebelum melanjutkan |
| `POST /api/demo/scenarios/{run_id}/cancel` | Membatalkan langkah yang belum dieksekusi | Tidak otomatis mengaktifkan backend kembali atau menghapus evidence; recovery lewat playbook terpisah |
| `GET /api/demo/scenarios` | Daftar run skenario | Ringkas per run |
| `GET /api/demo/scenarios/{run_id}` | Membaca status skenario dan langkah terakhir | `UNKNOWN` jika collector/health API tidak tersedia |
| `GET /api/demo/metrics` dan `GET /api/demo/metrics.csv` | Latensi per tahap dan metrik request | CSV dapat diunduh untuk laporan |

Implementasi mengikuti semantics di atas: scenario state di SQLite (`scenario_runs`, `scenario_steps`, `policy_decisions`), ladder state eksplisit dari `IDLE` melalui `PRECHECK → RECONNAISSANCE → CANARY_EVENT → EVIDENCE_VALIDATION → POLICY_EVALUATION`, lalu bercabang `POLICY_APPROVED` (drain → quarantine → verify → rejoin) atau `POLICY_REJECTED` (rejection recorded → service preserved) menuju terminal `COMPLETE`/`FAILED`/`CANCELLED`; pause/resume/cancel diminta via endpoint dan diverifikasi runner sebelum langkah berikutnya; guard idempotency; dan uji integrasi `sh lab/test-scenarios.sh` (3 skenario + guard double-start).

## 3. Model ancaman dan asumsi

### Kemampuan penyerang yang diasumsikan

- Penyerang dapat memperoleh akses hingga level root pada salah satu server yang dipantau (A atau B).

- Dari host itu, penyerang dapat menghapus atau mengubah log lokal, menghentikan agent, memalsukan event atas nama host tersebut, dan menyisipkan teks (termasuk instruksi untuk AI) pada nama file, command line, log, dan payload jaringan.

- Penyerang dapat berusaha memicu respons otomatis dengan sengaja (misalnya membanjiri alert) untuk menurunkan ketersediaan layanan.

### Asumsi dan di luar lingkup v1

- Control plane (collector, evidence store, model, Risk Engine, Policy Gate, audit store) diasumsikan tidak terkompromi. Jika control plane terkompromi, jaminan dokumen ini tidak berlaku.

- Kanal host ke collector dilindungi (TLS dan kredensial terpisah per host); jam semua host disinkronkan dengan toleransi yang dicatat.

- Penyedia Cloud LLM diperlakukan sebagai pihak ketiga yang hanya menerima data yang sudah disamarkan.

- Di luar lingkup: kompromi control plane, serangan rantai pasok terhadap Wazuh atau model, DDoS volumetrik dari luar, dan lebih dari dua server.

- Batas yang diterima: host terkompromi dapat memalsukan event tentang dirinya sendiri. Dampaknya dibatasi (lihat tabel), bukan dihilangkan.

### Ancaman, kontrol, dan pengujian

| Ancaman | Kontrol | Diuji melalui |
| -------------------------------------- | ------------------------------------------------------------------------ | -------------------------------------------------- |
| Log lokal dihapus atau agent dihentikan | Salinan event di Evidence Store terpisah; status telemetry; gap ditandai, bukan dianggap aman | Skenario log tampering dan agent berhenti |
| Event palsu dari host terkompromi | Kredensial per host; event host X hanya boleh memicu aksi otomatis terhadap host X; aksi lintas-host butuh konfirmasi independen atau operator | Server A mengirim event palsu tentang Server B |
| Prompt injection di nama file, log, atau payload | Data terstruktur; LLM tanpa tool; allowlist; validasi evidence ID | Set uji injection pada nama file dan teks log |
| Respons otomatis dipicu berulang untuk menurunkan ketersediaan | Maksimal satu backend di-drain; cooldown; rate limit; lonjakan alert dieskalasi ke operator | Skenario alert storm |
| Cloud LLM lambat atau tidak tersedia | Timeout, fallback ke Local LLM; jika keduanya gagal, tanpa aksi otomatis berisiko tinggi | Skenario timeout dan kedua model gagal |
| Kebocoran data ke cloud | Redaction dan minimalisasi; local-only jika dilarang | Pemeriksaan sampel payload yang dikirim: tanpa secret, token, atau kredensial |
| Output model tidak valid atau mengarang bukti | Validator JSON Schema, allowlist, cek evidence ID | JSON invalid dan evidence ID palsu |
| Bukti dihapus atau diubah setelah tersimpan | Ingest write-only; hash chain; backup terpisah | Upaya hapus dari host yang dipantau dan dari akun collector |

## 4. Arsitektur

![Arsitektur dasar v2 (belum memuat Patrol/Scenario Driver)](arch_v2.png){width="4.9in"}

> **Catatan gambar:** ini diagram target lama, bukan kondisi implementasi. Wazuh, classifier, dan LLM pada gambar belum terpasang pada baseline yang diperiksa.

### Zona kepercayaan

- **Zona yang dipantau:** Server A dan B. Anggap log dan teks di host sebagai data yang tidak tepercaya.

- **Zona kontrol:** collector, evidence store, Trajectory Engine, model, Risk Engine, Policy Gate, dan audit store. Letakkan di VM/host terpisah dari server yang dipantau.

- **Zona cloud:** Cloud LLM menerima data minimal yang telah disamarkan. Jangan kirim secret, token, private key, kredensial, atau isi file sensitif.

- **Zona respons:** Response Orchestrator hanya menyediakan aksi allowlist. Model AI tidak pernah memanggil shell atau API load balancer secara langsung.

- **Zona visualisasi/demo:** Dashboard Patrol mengonsumsi state melalui API collector dan Scenario Driver. Lapisan ini tidak menjadi trust boundary dan tidak boleh menulis evidence langsung ke database. Tombol skenario hanya memicu fixture yang telah ditetapkan di lab; event/status keamanan tetap berasal dari komponen backend.

## 5. Komponen dan tanggung jawab

| Komponen | Tugas | Batas penting |
| ---------------------------------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------ |
| Host monitoring | Mengirim event FIM, log sistem, dan indikator aktivitas | Status agent juga dipantau dari control plane |
| Remote Event Collector | Menerima salinan event dari dua host | Kredensial terpisah per host; host agent tidak boleh menghapus bukti terdahulu |
| Normalizer + Redactor | Memetakan field ke format event umum dan menyamarkan nilai sensitif | Pertahankan ID samaran konsisten supaya korelasi tetap mungkin; kunci pseudonimisasi disimpan di control plane |
| Evidence Store | Menyimpan event asli yang diperlukan untuk forensik dan event ternormalisasi | Ingest write-only dari collector; hash chain antar-record dengan ringkasan berkala disimpan di lokasi terpisah; backup terpisah. Hash saja tidak mencegah penghapusan; mekanisme konkret dipilih di Milestone 2 |
| Trajectory Engine | Mengelompokkan event berdasarkan host, waktu, user/proses yang sudah disamarkan, dan hubungan antar-event | Batasi window waktu dan ukuran konteks; tandai gap dan hilangnya telemetry |
| LLM Gateway | Memilih Cloud LLM atau Local LLM, menerapkan timeout dan fallback | Kontrak request/response dan validasi sama untuk dua model |
| Output Validator | Validasi JSON Schema, enum, panjang field, dan referensi evidence ID | Tolak evidence ID yang tidak ada; jangan mempercayai penjelasan tanpa bukti |
| Attack Probability Estimator | Menghasilkan `P_attack` per trajectory dari fitur terstruktur dan label data | Probabilitas harus dikalibrasi dan diuji; bukan confidence LLM; verdict LLM tidak dipakai sebagai fitur |
| Risk Engine | Menghitung indeks risiko dan menyimpan komponen perhitungannya | Semua nilai input (termasuk `I_max`) dan versi konfigurasi tercatat |
| Policy Gate | Memutuskan tingkat tindakan: catat, alert, persetujuan operator, atau aksi otomatis | LLM hanya memberi rekomendasi, bukan izin eksekusi |
| Availability Guard | Memastikan backend yang tersisa sehat, mampu melayani beban, dan tidak berstatus diwaspadai; menegakkan cooldown dan rate limit | Jika kondisi tidak diketahui/tidak sehat, jangan jalankan isolasi otomatis biasa |
| Response Orchestrator | Menjalankan tindakan dari allowlist, awalnya DRY_RUN | Aksi idempoten, batas waktu, hasil tindakan diverifikasi, dan audit wajib |
| Audit/Operator UI | Menampilkan timeline, bukti, model terpakai, skor, policy, dan hasil aksi | Catat juga kegagalan dan perubahan konfigurasi |
| Scenario Driver (target v3) | Mengatur urutan skenario Patrol dengan run ID, fixture canary, timeout, dan status akhir | Aktif hanya pada lab; path/marker tetap; event browser sintetis tidak menjadi evidence; tidak menerima perintah bebas |

## 6. Normalisasi event

Semua sumber log dinormalisasi ke struktur event internal. Contoh:

```json
{
  "schema_version": "1.0",
  "event_id": "EVT-000123",
  "timestamp_utc": "2026-01-01T12:00:00Z",
  "host_id": "HOST-A",
  "source": "wazuh_fim",
  "event_type": "file_change",
  "severity_original": "medium",
  "actor_id": "USER-03",
  "process_id": "PROC-09",
  "asset_criticality": "medium",
  "redacted_summary": "Perubahan file pada direktori aplikasi",
  "raw_evidence_ref": "EVID-000123",
  "integrity_hash": "<hash-event>",
  "trust_level": "untrusted_telemetry"
}
```

Ini contoh schema internal; bukan format wajib dari Wazuh. Gunakan timestamp UTC, ID stabil, sumber yang jelas, dan referensi ke bukti mentah di penyimpanan terpisah. Jangan menganggap satu field seperti `severity_original` setara antarproduk sebelum pemetaan dibuat.

Buat tabel pemetaan field sebagai artefak tertulis untuk setiap sumber: Wazuh, Suricata, dan AMiner pada AIT-ADS, serta Wazuh di lab. Field yang tidak tersedia di suatu sumber diisi `null`, tidak ditebak. Pemetaan ini penting karena classifier dilatih pada alert AIT-ADS dan harus bisa dijalankan pada event lab dengan fitur yang sama.

## 7. Trajectory Engine

Trajectory Engine menyimpan rangkaian event terstruktur, bukan hanya percakapan AI. Minimum yang disimpan:

- trajectory_id, event_id, timestamp, host ID, source, dan urutan event;

- hubungan event yang memiliki host, proses, user, file, atau indikator terkait;

- status telemetry: normal, terputus, terlambat, atau tidak dapat diverifikasi;

- ID bukti yang mendukung setiap hubungan;

- label ground truth untuk evaluasi ketika tersedia.

Gunakan window waktu yang dapat dikonfigurasi. Pisahkan event duplikat, tandai gap telemetry, dan jangan menyimpulkan bahwa server aman ketika agent/log berhenti. Simpan event yang masuk terlambat dan dokumentasikan bagaimana timeline diperbarui.

### Hubungan lintas-host

Trajectory menandai apakah rangkaian event melibatkan lebih dari satu host (misalnya koneksi dari A ke B, kredensial yang sama dipakai di kedua host, atau indikator yang sama muncul di keduanya). Jika ada, host lain itu diberi status **diwaspadai** yang dipakai Availability Guard pada bagian 11.

### Batas ukuran dan seleksi konteks untuk LLM

AIT-ADS berisi jutaan alert, sehingga trajectory dibentuk secara offline dan LLM tidak dipanggil per alert. Untuk setiap permintaan LLM:

- tetapkan batas jumlah event dan anggaran token yang dapat dikonfigurasi;

- gabungkan event berulang menjadi satu entri (jumlah, contoh, dan seluruh evidence ID yang diwakili);

- pertahankan event pertama dan terakhir, event yang menjadi dasar hubungan dan fitur classifier, serta event yang tidak normal menurut tipe atau severity asli;

- ringkas sisanya menjadi statistik (jumlah per tipe dan per host);

- jika masih terpotong, set `context_truncated = true`. Analisis seperti itu tidak boleh melewati status `partial` dan tidak boleh memicu tindakan otomatis.

## 8. Kontrak keluaran LLM

Cloud LLM dan Local LLM harus menghasilkan schema yang sama. Nilai verdict dan reason_codes adalah analisis, bukan izin tindakan atau skor risiko.

```json
{
  "schema_version": "1.1",
  "request_id": "REQ-0007",
  "trajectory_id": "TRJ-001",
  "analysis_status": "completed",
  "model_used": "cloud",
  "context_truncated": false,
  "verdict": "suspicious",
  "reason_codes": ["UNAUTHORIZED_FILE_CHANGE", "SUSPICIOUS_PROCESS"],
  "evidence_ids": ["EVT-000123", "EVT-000124"],
  "summary": "Perubahan file berkaitan waktu dengan proses yang tidak biasa."
}
```

Aturan validasi:

- analysis_status: completed, partial, atau unavailable;

- model_used: cloud atau local;

- verdict: benign, suspicious, malicious, atau insufficient_evidence;

- reason_codes hanya dari daftar allowlist;

- semua evidence_ids harus ada dalam Evidence Store;

- batasi panjang summary dan jangan jalankan perintah yang muncul dalam field tersebut;

- output JSON tidak valid ditolak. Setelah retry terbatas gagal, status menjadi unavailable.

### Daftar awal reason_codes

`UNAUTHORIZED_FILE_CHANGE`, `SUSPICIOUS_PROCESS`, `LOG_TAMPERING_SUSPECTED`, `AGENT_TELEMETRY_GAP`, `ABNORMAL_AUTH_ACTIVITY`, `PERSISTENCE_INDICATOR`, `PRIVILEGE_ESCALATION_INDICATOR`, `LATERAL_MOVEMENT_INDICATOR`, `NETWORK_SCAN_INDICATOR` (jika Suricata aktif), dan `INSUFFICIENT_CONTEXT`. Ini daftar awal; dibekukan di Milestone 5 setelah dipetakan ke fase serangan AIT-ADS dan skenario lab. Perubahan daftar menaikkan versi schema.

### Peran verdict dalam keputusan

- Verdict **tidak** menjadi input R dan tidak dipakai sebagai fitur classifier.

- **Eskalasi:** verdict `suspicious` atau `malicious` dengan evidence ID valid, saat R masih di bawah ambang otomatis, menaikkan trajectory minimal ke tingkat alert atau persetujuan operator. Tidak pernah ke aksi otomatis.

- **Penahan:** verdict `benign` atau `insufficient_evidence` saat R sudah memenuhi ambang otomatis mengalihkan keputusan ke persetujuan operator.

- **Tidak tersedia:** analysis_status `unavailable` atau `partial` berarti tidak ada aksi otomatis, kecuali ada aturan darurat deterministik yang sudah didefinisikan dan diuji secara eksplisit (tidak ada di MVP kecuali tim membuatnya).

- Akibatnya aksi otomatis membutuhkan kesepakatan classifier dan LLM. Bahwa aturan ini menurunkan isolasi keliru adalah hipotesis; diuji lewat perbandingan konfigurasi D dengan C pada bagian 12.

### Fallback Cloud → Local

- Coba Cloud LLM jika kebijakan organisasi memperbolehkan pengiriman data yang telah disamarkan.

- Terapkan timeout dan jumlah retry yang kecil serta terkonfigurasi.

- Jika error/timeout, kirim konteks yang sama secara logis ke Local LLM dengan schema yang sama.

- Validasi keluaran lokal melalui validator yang sama; jangan memberi kepercayaan tambahan hanya karena model lokal dipakai.

- Jika kedua model gagal, tandai analisis unavailable. Monitoring dan pengumpulan bukti tetap berjalan, tetapi respons otomatis berisiko tinggi menunggu bukti deterministik atau persetujuan operator.

### Pemilihan model

Nama dan versi Cloud LLM dan Local LLM belum dipilih di v3. Pilih di Milestone 5 dan catat: nama, versi, kuantisasi (untuk model lokal), kebutuhan hardware lab, batas konteks, biaya, dan kemampuan menghasilkan JSON yang sesuai schema. Model dan versi prompt dicatat di audit.

## 9. Pertahanan terhadap prompt injection dan manipulasi log

- Perlakukan semua isi log, nama file, command line, dan payload jaringan sebagai data tidak tepercaya, bukan instruksi.

- Pisahkan instruksi tetap dari payload event; berikan data sebagai objek terstruktur dengan batas yang jelas.

- LLM tidak memiliki tool untuk menjalankan shell, mengubah firewall, menghapus file, atau memanggil load balancer.

- Terapkan allowlist reason_codes dan action enum; jangan menjalankan teks bebas dari LLM.

- Cocokkan semua evidence ID dari model dengan event nyata. Tolak ID palsu dan field yang tidak dikenal.

- Simpan prompt version, model version, request ID, model pilihan, status validasi, dan hasil fallback di audit.

- Uji prompt injection yang disisipkan pada nama file dan teks log; jangan hanya menguji prompt injection langsung ke chat.

- Karena verdict hanya bisa menaikkan eskalasi atau menahan aksi, uji juga injection yang berusaha membuat model mengeluarkan verdict `benign` untuk menahan respons sah, bukan hanya yang berusaha memicu aksi.


## 10. Risk Engine v2

### Unit prediksi

`P_attack` dihitung **per trajectory** (jendela waktu), bukan per alert. Fitur diambil dari trajectory, misalnya jumlah dan keragaman tipe alert, jumlah host yang terlibat, kemajuan fase yang terlihat, severity asli tertinggi, rentang waktu, penanda gap telemetry, dan jumlah kelas bukti berbeda. Daftar fitur final dibekukan di Milestone 4 dan dicatat. Konfigurasi pembanding B pada bagian 12 memakai classifier yang sama pada fitur alert tunggal.

### Rumus operasional awal

Gunakan output probabilitas dari classifier berlabel yang telah dikalibrasi:

`P_attack ∈ [0, 1]`

Tentukan dampak dari matriks aset yang terdokumentasi, dengan masing-masing aspek 0-3 (huruf A di sini berarti Availability, bukan Server A):

- C: dampak pada kerahasiaan;

- I: dampak pada integritas;

- A: dampak pada ketersediaan.

```
I_CIA = (C + I + A) / 3
R     = P_attack × I_CIA
I_max = max(C, I, A)      # dicatat; dipakai sebagai pengaman di Policy Gate
```

Dengan desain ini, R berada pada rentang 0-3. Ini adalah **adaptasi indeks risiko untuk prototipe**, terinspirasi oleh praktik penilaian risiko berbasis ancaman/kerentanan/dampak; jangan mengklaim bahwa rumus sederhana ini adalah reproduksi persis YACRAF. Artikel YACRAF memberi kerangka formal penilaian risiko, sedangkan rumus dan matriks DEFNETT perlu didokumentasikan sebagai pilihan implementasi tersendiri.

### Dari mana P_attack berasal?

- Gunakan classifier baseline sederhana (misalnya Logistic Regression atau Random Forest) pada fitur trajectory dan label yang bisa dipertanggungjawabkan.

- AIT-ADS memiliki label fase serangan berbasis rentang waktu; petakan alert ke label dengan aturan yang terdokumentasi (bagian 12) dan tandai event ambigu/boundary secara terpisah.

- Pisahkan data berdasarkan skenario serangan untuk mencegah kebocoran antara train dan test.

- Kalibrasi output probabilitas pada data validasi. Laporkan Brier score atau reliability plot selain Precision/Recall.

- LLM tidak mengisi `P_attack` dengan confidence-nya dan verdict LLM tidak dipakai sebagai fitur. LLM memberi ringkasan konteks dan referensi bukti; classifier terkalibrasi yang menghasilkan probabilitas.

### Dampak

Buat matriks dampak C/I/A per aset, disetujui tim sebelum Milestone 4, dan dokumentasikan alasan setiap nilai. Nilai 0 berarti tidak ada dampak yang teridentifikasi; nilai 3 berarti dampak kritis menurut kriteria laboratorium yang ditulis sebelum pengujian. Format yang disarankan (baris di bawah hanya ilustrasi format, belum disetujui tim):

| Aset | C | I | A | Alasan | Status |
| ---------------------------------- | ----- | ----- | ----- | ---------------------------------------------- | -------------- |
| Direktori aplikasi di Server A | 1 | 3 | 2 | Contoh: perubahan file mengubah perilaku layanan | ilustrasi |
| Konfigurasi HAProxy | 0 | 3 | 3 | Contoh: salah konfigurasi menghentikan layanan | ilustrasi |
| Log aplikasi di Server B | 2 | 2 | 1 | Contoh: berisi data pengguna dan bukti | ilustrasi |

Rata-rata `I_CIA` dapat menyembunyikan satu aspek yang kritis. Karena itu Policy Gate menerapkan **aturan dampak kritis**: jika `I_max = 3` dan `P_attack ≥ p_review`, trajectory minimal naik ke tingkat persetujuan operator, berapa pun nilai R.

### Ambang risiko

**Jangan menetapkan threshold final sebelum uji validasi.** Uji beberapa threshold pada data validasi, pilih yang memenuhi batas false positive dan target recall yang disepakati, lalu ukur kembali pada data uji yang tidak dipakai memilih threshold. Ambang dan bobot (`T_watch`, `T_review`, `T_auto(k)`, `p_review`) adalah parameter eksperimen, bukan angka yang diambil langsung dari jurnal.

## 11. Policy Gate dan respons aman

Respons awal disetel ke DRY_RUN agar prototipe dapat mencatat tindakan yang akan dilakukan tanpa mengubah layanan.

**Catatan status implementasi:** alur canary yang ada saat ini merupakan playbook terbatas berdasarkan file/path dan marker khusus. Itu belum sama dengan Policy Gate generik pada tabel di bawah. Kebijakan kesehatan survivor, bukti, status lintas-host, dan mode aktif harus dibuktikan melalui tes terpisah sebelum disebut diterapkan penuh. Default pengembangan tetap `DRY_RUN`; mode canary aktif hanya untuk fixture yang terkunci di lab.

### Tingkat tindakan

| Tingkat | Kondisi | Tindakan |
| ---------------- | -------------------------------------------------------------- | ---------------------------------------------- |
| 0 - Catat | `R < T_watch` | Catat dan perbarui timeline |
| 1 - Alert | `T_watch ≤ R < T_review` | Alert operator dan amankan bukti mentah |
| 2 - Operator | `T_review ≤ R < T_auto(k)`; atau aturan dampak kritis; atau salah satu kondisi ambigu di bawah | Rekomendasi aksi ke operator; tidak ada aksi otomatis |
| 3 - Otomatis | `R ≥ T_auto(k)` dan semua prasyarat di bawah terpenuhi | Aksi allowlist, misalnya `DRAIN_BACKEND_A` (DRY_RUN secara default) |

`k` adalah kategori biaya aksi (0-3) dari Availability Guard: makin tipis kapasitas yang tersisa setelah aksi, makin besar `k`, dan `T_auto(k)` tidak boleh turun ketika `k` naik. Dengan begitu biaya tindakan (kehilangan kapasitas) ikut menentukan, bukan hanya risiko serangan.

Kondisi ambigu yang selalu mengarah ke tingkat 2: telemetry host target tidak diketahui tanpa jalur verifikasi lain; classifier dan LLM tidak sepakat; analisis LLM `unavailable` atau `partial`; konteks terpotong; trajectory melibatkan host lain (status diwaspadai); atau lonjakan alert yang tidak wajar dari satu host.

### Prasyarat tingkat 3

Sebelum drain Server A dari load balancer, Policy Gate wajib mengecek semuanya:

- bukti yang dirujuk oleh analisis benar-benar ada dan integritasnya lulus;

- `R ≥ T_auto(k)` menurut kebijakan aktif;

- setidaknya dua kelas bukti yang berbeda mendukung (misalnya perubahan file dan aktivitas proses, atau bukti host dan jaringan). Ini aturan kebijakan yang efeknya diuji, bukan angka yang sudah terbukti;

- verdict LLM `suspicious` atau `malicious` dan sejalan dengan classifier;

- telemetry host target berstatus normal atau terverifikasi lewat jalur lain;

- Server B sehat, kapasitasnya cukup untuk beban yang tersisa, dan tidak berstatus diwaspadai;

- batas anti-manipulasi terpenuhi (bagian berikut);

- tindakan diizinkan pada mode operasional dan tercatat di audit.

### Pengaman terhadap respons yang dipicu penyerang

Penyerang yang bisa menghasilkan alert dapat mencoba membuat DEFNETT menguras backend sendiri. Pengaman, semuanya parameter konfigurasi yang nilainya ditentukan di Milestone 6:

- `max_drained_backends = 1`: tidak pernah ada lebih dari satu backend yang di-drain pada saat yang sama;

- cooldown setelah setiap aksi dan setelah pemulihan, tanpa aksi otomatis baru selama periode itu (mencegah flapping);

- rate limit jumlah aksi otomatis per jendela waktu;

- lonjakan alert yang jauh di atas baseline dari satu host dianggap kemungkinan manipulasi dan dieskalasi ke operator, bukan diproses sebagai bukti tambahan;

- event dari host X tidak boleh memicu aksi otomatis terhadap host lain; aksi lintas-host membutuhkan konfirmasi independen atau persetujuan operator.

### Apa yang dilakukan dan tidak dilakukan drain

`DRAIN_BACKEND_A` mengeluarkan Server A dari rotasi load balancer (misalnya dengan state drain HAProxy) sehingga permintaan baru tidak lagi dilayani oleh host yang mungkin terkompromi, sambil layanan tetap berjalan di B. Aksi ini **tidak** memutus akses langsung penyerang ke A (misalnya SSH di luar load balancer), tidak menghentikan proses, dan tidak menghapus persistensi. Jangan menyajikan drain sebagai containment penuh.

- `ISOLATE_HOST_NETWORK` (opsional) hanya dijalankan lewat persetujuan operator, tidak masuk jalur otomatis di MVP. Jika lab memungkinkan, amankan bukti volatil sebelum isolasi.

- Karena serangan multi-step dapat sudah menjalar ke B, drain A tidak dianggap cukup bila trajectory melibatkan B: B berstatus diwaspadai, aksi otomatis ditahan, dan operator mendapat eskalasi.

### Verifikasi, kegagalan, dan pemulihan

Setelah aksi, verifikasi hasilnya melalui health check dan catat di audit. Jangan menghentikan server atau menghapus file hanya berdasarkan skor LLM. Pemulihan/rejoin server bersifat manual: periksa ulang integritas (misalnya baseline FIM atau pemulihan dari image bersih) dan butuh persetujuan sesuai policy.

Jika Server B tidak sehat atau kedua model AI gagal, jangan otomatis mengisolasi Server A melalui jalur biasa. Buat alert, simpan bukti, dan eskalasi ke operator kecuali tersedia aturan darurat deterministik yang secara eksplisit sudah diuji.

## 12. Data dan evaluasi

### Dataset publik

- **AIT-ADS:** [Zenodo record 8263181](https://zenodo.org/records/8263181). Berisi 2.655.821 alert dari Wazuh, Suricata, dan AMiner di delapan skenario multi-step, dengan simulasi aktivitas normal dan label fase serangan. Sangat sesuai untuk alert correlation, filtering, dan attack-chain analysis. Data ini sintetis, sehingga tidak membuktikan kinerja di jaringan operasional nyata.

- Publikasi dataset: Landauer, Skopik, Wurzenberger (2024), *Introducing a New Alert Data Set for Multi-Step Attack Analysis*, CSET 2024, [DOI 10.1145/3675741.3675748](https://doi.org/10.1145/3675741.3675748).

- Dasar penilaian risiko: Ekstedt et al. (2023), *Yet another cybersecurity risk assessment framework*, *International Journal of Information Security*, [DOI 10.1007/s10207-023-00713-y](https://doi.org/10.1007/s10207-023-00713-y), open access. Gunakan sebagai landasan konsep model risiko, bukan sebagai sumber threshold/bobot yang belum dipilih.

### Peran AIT-ADS dan lab

AIT-ADS dan lab berbeda lingkungan, aturan deteksi, dan sumber alert, sehingga classifier yang baik di AIT-ADS belum tentu baik di lab.

- **AIT-ADS:** evaluasi offline untuk korelasi trajectory dan classifier (konfigurasi A-D).

- **Lab:** uji integrasi end-to-end, uji keselamatan, dan respons. Classifier juga dijalankan pada data lab (skenario normal dan serangan terkontrol) dan hasilnya **dilaporkan terpisah** dari hasil AIT-ADS.

- Jika kinerja turun di lab, itu temuan yang dilaporkan, bukan kegagalan yang disembunyikan. Opsi lanjutan (latih ulang atau fine-tune dengan data lab) dicatat sebagai eksperimen terpisah.

### Pelabelan

Aturan pelabelan ditulis sebelum eksperimen dan tidak diubah setelah melihat hasil uji. Titik awal yang diusulkan:

- label alert berasal dari rentang waktu fase serangan AIT-ADS;

- trajectory berlabel positif jika memuat sedikitnya satu alert berlabel fase serangan, selain itu negatif;

- alert dan trajectory pada batas fase atau yang ambigu ditandai `ambiguous`, dikeluarkan dari metrik utama, dan dilaporkan sebagai analisis sensitivitas (ambigu dihitung sebagai positif dan sebagai negatif).

### Pemisahan data

Karena hanya ada delapan skenario, split tetap train/validation/test akan memberi sangat sedikit skenario untuk test dan hasil yang sangat bervariasi. Gunakan **leave-one-scenario-out**:

- setiap skenario bergantian menjadi data uji (delapan lipatan);

- kalibrasi probabilitas dan pemilihan threshold dilakukan hanya di dalam data latih lipatan itu (validasi internal juga per skenario);

- laporkan hasil tiap skenario, rata-rata, dan rentang minimum-maksimum;

- kesimpulan tidak boleh bergantung pada satu skenario, dan jangan mengklaim signifikansi statistik dengan delapan skenario tanpa uji yang sesuai.

### Test set laboratorium sendiri

Selain test set keamanan di bawah, tambahkan test harness Patrol agar animasi dan bukti tidak tertukar:

- mode `VISUAL_ONLY`: aktor browser bergerak, tetapi jumlah event database dan status backend tidak berubah;
- mode `SCENARIO`: fixture canary menghasilkan event FIM yang sama dengan yang ditampilkan di timeline;
- jalur containment yang diizinkan: satu backend target di-drain, survivor menerima request, lalu target hanya rejoin setelah health check lulus;
- jalur containment ditahan: backend survivor tidak sehat atau evidence invalid; tidak ada drain dan UI menampilkan alasan;
- jeda, timeout, refresh browser, dan reset tidak menggandakan aksi atau menghapus data di luar fixture;
- seluruh metrik request berasal dari health/test client independen, bukan animasi.

Tambahkan skenario normal dan serangan yang aman serta terkontrol:

- pembaruan aplikasi yang sah dan perubahan file normal;

- rangkaian aktivitas mencurigakan multi-step;

- penghapusan log lokal setelah event berhasil dikirim;

- agent berhenti atau pengiriman log terputus;

- Cloud LLM timeout dan perpindahan ke Local LLM;

- kedua model tidak tersedia;

- JSON invalid atau evidence ID palsu;

- prompt injection di teks event, termasuk yang berusaha menahan respons sah;

- Server B tidak sehat atau kapasitasnya tidak cukup;

- alert storm dari satu host;

- Server A mengirim event palsu tentang Server B;

- trajectory sangat besar sehingga konteks terpotong;

- tindakan drain backend dan pemulihan setelah verifikasi.

### Perbandingan untuk menguji penurunan false positive

Perbandingan dua konfigurasi tidak cukup untuk menunjukkan apa yang menurunkan false positive. Gunakan ablasi bertingkat pada skenario dan ground truth yang sama:

| Konfigurasi | Isi | Pertanyaan yang dijawab |
| -------------------------- | ---------------------------------------------------------------------- | -------------------------------------------- |
| A | Alert asli (misalnya level rule Wazuh) dengan ambang level tetap, tanpa korelasi dan tanpa classifier | Titik acuan tanpa DEFNETT |
| B | Classifier terkalibrasi per alert, tanpa trajectory dan tanpa LLM | Efek classifier (B terhadap A) |
| C | Trajectory + classifier per trajectory + Risk Engine + Policy Gate, tanpa LLM | Efek korelasi trajectory (C terhadap B) |
| D | C ditambah LLM (DEFNETT penuh) | Efek LLM (D terhadap C) |

- Metrik tingkat alert (konfigurasi A dan B) dan tingkat insiden (A-D). Untuk perbandingan yang adil, hasil A dan B dikelompokkan ke trajectory yang sama hanya saat menghitung metrik tingkat insiden.

- Laporkan False Positive Rate, Precision, Recall, F1, detection latency, response latency, layanan yang tetap tersedia (misalnya persentase permintaan berhasil selama skenario), jumlah isolasi atau drain keliru, dan jumlah eskalasi ke operator (beban operator).

- Laporkan Brier score atau reliability plot untuk `P_attack`, serta penggunaan token, latensi, dan biaya LLM.

- Jika biaya Cloud LLM membatasi, evaluasi konfigurasi D dilakukan pada subset trajectory yang dipilih acak berstrata per skenario dengan seed tercatat, dan C dibandingkan pada subset yang sama.

- Threshold dipilih hanya pada data latih/validasi dan hanya dilaporkan final setelah diuji pada skenario yang ditahan.

- Target awal FPR (misalnya ≤5%) boleh dipakai sebagai target rekayasa, tetapi harus ditulis sebagai target tim, bukan standar universal atau hasil yang sudah tercapai.

## 13. Struktur kode yang disarankan

```
defnett/
├── collector/        # input alert, status agent
├── normalizer/       # normalisasi + redaction
├── mapping/          # pemetaan field ke skema
├── trajectory/       # korelasi, timeline, konteks
├── llm_gateway/      # cloud utama, local fallback
├── schemas/          # skema event dan output LLM
├── detector/         # classifier + kalibrasi
├── risk_engine/      # matriks dampak, R
├── policy_gate/      # tingkat tindakan, DRY_RUN
├── evidence/         # store + cek integritas
├── audit/            # audit keputusan/tindakan
├── eval/             # ablasi A-D, metrik
├── response/         # adapter aksi allowlist ke HAProxy
├── scenario_driver/  # target: orkestrasi demo terkontrol dan fixture canary
├── dashboard/        # Patrol, timeline, hasil dan status keamanan
├── tests/            # unit, adversarial, skenario dan integrasi UI-backend
└── docs/             # arsitektur, threat model
```

Jangan bangun dashboard kompleks dulu. Pastikan event masuk, JSON lolos validasi, risk calculation reproducible, dan Policy Gate menghasilkan keputusan yang dapat diaudit.

## 14. Pembagian tiga anggota

| Anggota | Pemilik komponen | Hasil yang harus diserahkan |
| ------------------------------ | ---------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| 1 - Infrastruktur | Dua server lab, HAProxy, agent FIM, collector, evidence store, autentikasi event, health/request monitor, threat model | Event dan status backend tervalidasi; containment hanya menyasar backend target; survivor tetap melayani request; skenario kegagalan teruji |
| 2 - AI dan data | AIT-ADS preprocessing, pemetaan field, normalizer/trajectory, classifier dan kalibrasi, LLM gateway/validator bila masuk cakupan final, dokumentasi SoA | Eksperimen terpisah dari event demo; label/split tercatat; kontribusi model diukur tanpa mengklaim hasil sebelum uji |
| 3 - UI, keputusan, dan respons | Patrol/Scenario Driver, timeline evidence, Policy Gate, Availability Guard, worker remediation, test harness A-D dan metrik | Demo positif/negatif berjalan ulang; animasi tidak menjadi evidence; keputusan dan hasil tindakan dapat ditelusuri; hasil A-D dapat direproduksi |

Integrasi, ground truth, matriks dampak, dan test plan harus ditinjau bersama seluruh anggota.

## 15. Urutan implementasi

Urutan berikut memprioritaskan bukti end-to-end dan keselamatan demo sebelum ekspansi fitur. Ukuran S/M/L adalah perkiraan relatif, bukan estimasi waktu kalender. Milestone AI tetap penting untuk klaim penelitian, tetapi tidak boleh menghalangi verifikasi alur dasar lebih awal.

| Milestone | Isi dan artefak keluar | Pemilik utama | Ukuran |
|---|---|---|---|
| 0 | Reproduksi baseline, rekam versi compose, health check, event dasar, dan tes containment yang ada. Simpan hasil sebelum perubahan. | Semua | S |
| 1 | Scenario Driver dalam profile lab; start/pause/reset; run ID dan state machine; visual-only dipisah dari skenario terhubung | 3 | M |
| 2 | Hubungkan langkah scenario ke fixture canary yang terkunci; event FIM/collector menjadi sumber kebenaran; timeline menautkan evidence ID | 1 + 3 | M |
| 3 | Monitor request dan status survivor; validasi prasyarat sebelum drain; skenario survivor tidak sehat harus menahan aksi; jalur pemulihan terverifikasi | 1 + 3 | M |
| 4 | Hardening event/evidence: autentikasi host, batas ingest, gap telemetry, strategi hash-chain/backup terpisah, uji tampering | 1 | M/L |
| 5 | AIT-ADS preprocessing, skema fitur, pelabelan, split leave-one-scenario-out dan baseline A; dokumentasi mapping Wazuh/Suricata/AMiner | 2 | M |
| 6 | Trajectory offline/online dan classifier; kalibrasi probabilitas; konfigurasi B/C; unit test Risk Engine dan matriks dampak aset | 2 + 3 | L |
| 7 | LLM Gateway Cloud/Local, JSON Schema, redaction, timeout/fallback, prompt-injection test; konfigurasi D. Jika waktu/hardware tidak cukup, dokumentasikan tidak tersedia dan jangan klaim fitur selesai | 2 | L |
| 8 | Policy Gate dan Availability Guard disatukan dengan pipeline; uji bukti invalid, alert storm, host lintas-waspada, model unavailable, DRY_RUN dan canary aktif | 1 + 3 | L |
| 9 | Evaluasi A-D serta demo utama/negatif; laporkan deteksi, false containment, latency, request success rate, hasil per skenario dan kegagalan | Semua | L |

**Gate sebelum mode aktif:** jangan mengaktifkan containment selain playbook canary terbatas sampai pengujian survivor, batas maksimum satu backend, idempotensi, cooldown, pemulihan, dan pencatatan audit lulus. Kegagalan pada satu prasyarat berarti respons ditahan dan operator diberi alasan yang dapat dilihat.

**Profil waktu demo:** konfigurasi canary yang ada saat ini menahan tahap pemulihan selama 180 detik. Jika presentasi membutuhkan 10–15 detik, implementasikan parameter demo eksplisit (misalnya `DEMO_RECOVERY_DELAY_SECONDS`) dan verifikasi bahwa hanya timer demo yang berubah. Jangan mengubah kebijakan umum diam-diam.

## 16. Kriteria selesai MVP

Bedakan **MVP demo end-to-end** dari **MVP penelitian AI**. Keduanya tidak boleh disamakan.

### 16.1 MVP demo end-to-end

- Compose lab dapat dijalankan ulang dan baseline versi/konfigurasi tercatat.
- Skenario Patrol membedakan `VISUAL_ONLY` dari `SCENARIO`; aktor animasi tanpa fixture tidak mengubah database, file, backend, atau keputusan.
- Saat skenario terhubung dijalankan, fixture canary yang path dan markernya tetap menghasilkan event FIM yang dapat ditelusuri dari dashboard ke collector.
- Timeline menampilkan event ID/evidence reference, host target, keputusan, tindakan, health check, karantina, rejoin, dan hasil request.
- Dalam jalur sukses, hanya backend target yang dikeluarkan dari HAProxy; backend survivor tetap sehat dan berhasil melayani request yang diuji.
- Dalam jalur negatif (survivor tak sehat, evidence invalid, atau status tidak diketahui), sistem menahan aksi otomatis dan menampilkan alasan. Tidak ada backend kedua yang ikut di-drain.
- Worker hanya memindahkan fixture canary yang lolos cek path, tipe, ukuran, marker, dan hash; tidak menyentuh file lain.
- Reset/cancel/refresh tidak membuat aksi ganda dan tidak menghapus data di luar fixture yang ditetapkan.
- Profil demo dengan jeda singkat (bila dibuat) dicatat terpisah dari konfigurasi 180 detik saat ini.
- Waktu deteksi/respons dan persentase request berhasil berasal dari event log serta test client independen.

### 16.2 MVP penelitian AI

- Event dari sumber yang benar-benar terintegrasi dinormalisasi dengan mapping field yang terdokumentasi.
- Evidence store memiliki kontrol akses/write boundary yang diuji; hash chain tidak disebut sebagai jaminan anti-manipulasi penuh tanpa anchor/backup independen.
- Trajectory mengandung event, hubungan, telemetry gap, dan evidence ID; pengelompokan waktu/host saja tidak boleh disebut korelasi multi-step tervalidasi.
- Classifier dilatih pada data berlabel, memiliki split bebas leakage, dikalibrasi, dan diuji pada skenario yang ditahan. Nilai heuristik tidak diberi nama `P_attack` dari model.
- Jika LLM dipakai, output melewati validator, evidence IDs diverifikasi, data cloud direduksi/redaksi, dan LLM tidak memiliki kuasa eksekusi.
- Policy Gate/Availability Guard menjalankan test terhadap evidence invalid, host lintas-waspada, survivor tak sehat, alert storm, model unavailable, serta kapasitas tidak diketahui.
- Hasil A-D, false positive, precision, recall, F1, Brier score/reliability, false containment, detection/response latency, request success rate, dan escalation rate dilaporkan per skenario.
- AIT-ADS dan hasil lab dilaporkan terpisah; kesimpulan tidak digeneralisasikan ke jaringan operasional tanpa validasi tambahan.

## 17. Keputusan yang masih terbuka

- Nama dan versi Cloud LLM dan Local LLM, hardware lab, batas konteks, dan biaya (Milestone 5).

- Nilai `T_watch`, `T_review`, `T_auto(k)`, `p_review`, dan parameter pengaman respons (setelah validasi, Milestone 4 dan 6).

- Matriks dampak C/I/A per aset yang disetujui tim (sebelum Milestone 4).

- Mekanisme konkret write-only dan hash chain untuk Evidence Store (Milestone 2).

- Aturan pelabelan final dan ukuran window trajectory (Milestone 3).

- Kalender dan tenggat setiap milestone.

- Lengkapi systematic review dan matriks perbandingan sebelum menyatakan novelty akademik; CIPHER-A (2026) dan AIDA preprint (2026) sudah menunjukkan bahwa klaim respons aman/triase berbasis bukti secara umum terlalu luas.
- Tetapkan kontrol interaksi Patrol (hanya start/pause/reset atau juga langkah manual), state machine skenario, dan batas yang mencegah UI memanggil perintah bebas.
- Tentukan kriteria kesehatan dan kapasitas minimum backend survivor, durasi test window, serta cara mengukur request success rate.
- Putuskan apakah Cloud/Local LLM benar-benar dapat diimplementasikan dan diuji dalam waktu kompetisi; bila tidak, kurangi klaim, bukan menyamarkan stub sebagai model aktif.
- Tentukan apakah profil demo menggunakan delay pemulihan 10–15 detik; implementasi baseline saat ini memakai 180 detik.

## 18. Sumber rujukan utama

- Landauer, M., Skopik, F., & Wurzenberger, M. (2023). **AIT Alert Data Set**, Zenodo. [https://zenodo.org/records/8263181](https://zenodo.org/records/8263181)

- Landauer, M., Skopik, F., & Wurzenberger, M. (2024). **Introducing a New Alert Data Set for Multi-Step Attack Analysis**. CSET 2024. [https://doi.org/10.1145/3675741.3675748](https://doi.org/10.1145/3675741.3675748)

- Ekstedt, M., Afzal, Z., Mukherjee, P., Hacks, S., & Lagerström, R. (2023). **Yet another cybersecurity risk assessment framework**. *International Journal of Information Security*, 22, 1713-1729. [https://doi.org/10.1007/s10207-023-00713-y](https://doi.org/10.1007/s10207-023-00713-y)

- OWASP GenAI Security Project, **LLM Top 10** (gunakan sebagai daftar risiko dan bahan uji prompt injection; periksa edisi yang dipakai dalam dokumentasi). [https://genai.owasp.org/llm-top-10/](https://genai.owasp.org/llm-top-10/)

- Kizhakel, S. P., & Pande, S. D. (2026). **An adaptive agentic AI framework for counterfactual validation and adversarial lookahead in automated incident response (CIPHER-A)**. *Discover Artificial Intelligence*, 6, article 970. Open access; published 29 August 2026. [https://link.springer.com/article/10.1007/s44163-026-02058-6](https://link.springer.com/article/10.1007/s44163-026-02058-6)

- Tsegai, S. A., Kantchelian, A., Yao, D., & Gao, P. (2026). **From Investigation Failures to Reliable SOC Agents: Understanding and Improving LLM-Based Alert Triage**. Preprint, arXiv:2610.10608, 7 October 2026. [https://arxiv.org/abs/2610.10608](https://arxiv.org/abs/2610.10608). Status: preprint, bukan publikasi jurnal peer-reviewed.

- Stouffer, K. et al. (2023). **Guide to Operational Technology (OT) Security**, NIST SP 800-82 Rev. 3. [https://csrc.nist.gov/pubs/sp/800/82/r3/final](https://csrc.nist.gov/pubs/sp/800/82/r3/final). NIST mencatat draf awal Rev. 4 pada 21 September 2026; Rev. 3 tetap merupakan versi final yang dirujuk dalam blueprint ini.
