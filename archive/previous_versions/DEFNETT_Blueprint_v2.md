# DEFNETT v2 - Blueprint Teknis

**Status:** Rancangan untuk mulai membangun prototipe laboratorium (revisi dari v1)\
**Nama:** DEFNETT\
**Tujuan:** Mendeteksi rangkaian aktivitas mencurigakan, mempertahankan bukti, menghitung risiko secara terukur, lalu menjalankan respons yang dibatasi kebijakan sambil menjaga layanan tetap tersedia.

> Batas klaim: blueprint ini adalah rancangan. Penurunan false positive, keandalan Risk Engine, dan waktu respons belum terbukti sampai pengujian dilakukan. Semua ambang, bobot, dan target dalam dokumen ini adalah parameter eksperimen atau target tim, bukan hasil.

## 1. Keputusan desain v2

| Bagian | Keputusan |
| ------------------------ | -------------------------------------------------------------------------------------------------------------- |
| Lingkungan | Dua server Linux, HAProxy, dan satu control plane terpisah |
| Monitoring | Wazuh agent + FIM/log; Suricata opsional |
| Peran dataset | AIT-ADS untuk evaluasi offline korelasi dan classifier; lab sendiri untuk uji integrasi, keselamatan, dan respons |
| Unit keputusan | Trajectory (rangkaian event dalam jendela waktu), bukan alert tunggal |
| Konteks | Trajectory Engine menyusun alert menurut waktu, host, bukti, dan hubungan kejadian, dengan batas ukuran konteks |
| AI | Cloud LLM utama; Local LLM fallback; kontrak JSON sama |
| Batas AI | LLM tidak memiliki shell/root/akses eksekusi atau hak isolasi |
| Peran LLM | Penasihat: verdict hanya boleh menaikkan eskalasi atau menahan aksi otomatis; tidak masuk rumus R dan tidak pernah menjadi izin |
| Risk Engine | `P_attack` per trajectory dari classifier berlabel yang dikalibrasi; dampak dari matriks aset |
| Formula | `R = P_attack × I_CIA`; `I_CIA = (C + I + A) / 3`; skala 0-3; adaptasi prototipe; `I_max` dicatat dan dipakai sebagai pengaman |
| Policy Gate | Empat tingkat (catat, alert, operator, otomatis); aksi otomatis hanya jika semua prasyarat bagian 11 terpenuhi |
| Anti-manipulasi respons | Maksimal satu backend di-drain, cooldown, rate limit, aturan lintas-host, dan penanda lonjakan alert |
| Respons awal | `DRY_RUN` default; drain A setelah uji lulus; isolasi jaringan hanya lewat persetujuan operator |
| Data cloud | Samarkan dan minimalkan data; local-only jika cloud dilarang |
| Evaluasi | Ablasi A-D, split per skenario (leave-one-scenario-out), hasil dilaporkan per skenario |

## 2. Perubahan dari v1

| Topik | Perubahan di v2 | Bagian |
| ------------------ | -------------------------------------------------------------------------------------------------- | ---------------- |
| Peran LLM | v1 tidak menyebut bagaimana verdict dipakai. Sekarang: verdict tidak masuk R; hanya menaikkan eskalasi atau menahan aksi otomatis | 8, 11 |
| Unit prediksi | `P_attack` dihitung per trajectory dengan fitur dan aturan pelabelan yang ditulis sebelum eksperimen | 10, 12 |
| Perbandingan evaluasi | Dua konfigurasi (A vs B) diganti ablasi A-D agar kontribusi classifier, trajectory, dan LLM terpisah | 12 |
| Split data | Delapan skenario AIT-ADS: leave-one-scenario-out dengan pemilihan ambang di dalam data latih; hasil per skenario | 12 |
| AIT-ADS ke lab | Peran data dipisah; classifier tidak diasumsikan berlaku di lab tanpa diuji di data lab | 6, 12 |
| Model ancaman | Bagian baru: kemampuan penyerang, asumsi, dan tabel ancaman-kontrol-pengujian | 3 |
| Respons otomatis | Pengaman terhadap penyerang yang memicu respons (self-DoS); penjelasan tujuan dan batas drain; status B "diwaspadai" | 11 |
| Konteks LLM | Batas ukuran, aturan seleksi, dan penanda `context_truncated` | 7, 8 |
| Kebijakan | Tabel tingkat tindakan, daftar awal `reason_codes`, aturan dampak kritis per aspek | 8, 10, 11 |
| Evidence Store | Mekanisme write-only dan hash chain dijadikan keputusan eksplisit (dipilih di Milestone 2) | 5 |
| Milestone | Mulai dari irisan tipis end-to-end; ada ketergantungan dan ukuran relatif; keputusan terbuka dicatat | 15, 17 |

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

![Arsitektur DEFNETT v2](arch_v2.png){width="4.9in"}

### Zona kepercayaan

- **Zona yang dipantau:** Server A dan B. Anggap log dan teks di host sebagai data yang tidak tepercaya.

- **Zona kontrol:** collector, evidence store, Trajectory Engine, model, Risk Engine, Policy Gate, dan audit store. Letakkan di VM/host terpisah dari server yang dipantau.

- **Zona cloud:** Cloud LLM menerima data minimal yang telah disamarkan. Jangan kirim secret, token, private key, kredensial, atau isi file sensitif.

- **Zona respons:** Response Orchestrator hanya menyediakan aksi allowlist. Model AI tidak pernah memanggil shell atau API load balancer secara langsung.

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

Nama dan versi Cloud LLM dan Local LLM belum dipilih di v2. Pilih di Milestone 5 dan catat: nama, versi, kuantisasi (untuk model lokal), kebutuhan hardware lab, batas konteks, biaya, dan kemampuan menghasilkan JSON yang sesuai schema. Model dan versi prompt dicatat di audit.

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
├── response/         # adapter allowlist ke LB
├── evidence/         # store + cek integritas
├── audit/            # audit keputusan/tindakan
├── eval/             # ablasi A-D, metrik
├── dashboard/        # timeline dan hasil
├── tests/            # unit, adversarial, skenario
└── docs/             # arsitektur, threat model
```

Jangan bangun dashboard kompleks dulu. Pastikan event masuk, JSON lolos validasi, risk calculation reproducible, dan Policy Gate menghasilkan keputusan yang dapat diaudit.

## 14. Pembagian tiga anggota

| Anggota | Pemilik komponen | Hasil yang harus diserahkan |
| ------------------------------ | ---------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| 1 - Infrastruktur | Dua Linux server, load balancer, agent monitoring, collector, evidence store, kredensial per host, pemilik dokumen threat model | Event dapat dikirim ke luar host; skenario log tampering dan event palsu lintas-host dapat diuji; mekanisme write-only terbukti |
| 2 - AI dan data | AIT-ADS preprocessing, tabel pemetaan field, normalizer, batas konteks, LLM gateway, schema validator, prompt injection test | JSON kontrak konsisten; fallback cloud/local diuji; aturan pelabelan dan split data terdokumentasi |
| 3 - Keputusan/respons | Trajectory Engine (bersama anggota 2 bila perlu), classifier/Risk Engine, Policy Gate, Availability Guard, pengaman anti-manipulasi, response adapter, skrip ablasi dan metrik | Perhitungan teruji; tindakan default DRY_RUN; failover dan isolasi lab dapat didemonstrasikan; hasil A-D dapat direproduksi |

Integrasi, ground truth, matriks dampak, dan test plan harus ditinjau bersama seluruh anggota.

## 15. Urutan implementasi

Mulai dari irisan tipis yang melewati seluruh jalur dengan komponen sementara (stub), lalu ganti stub satu per satu. Dengan begitu masalah integrasi muncul di awal, bukan di Milestone terakhir. Ukuran adalah perkiraan relatif (S/M/L); tanggal belum ditetapkan karena tenggat belum diketahui, jadi isi kolom kalender setelah tim menyepakatinya.

| Milestone | Isi | Pemilik utama | Bergantung pada | Ukuran |
| ---------------- | ---------------------------------------------------------------------------------- | ------------------ | ------------------------ | -------------- |
| 1 | Irisan tipis end-to-end: dua server lab, HAProxy, agent, collector, normalizer, evidence store sederhana, trajectory sederhana, stub LLM, R tetap, Policy Gate DRY_RUN mencatat keputusan | Semua | - | M |
| 2 | Infrastruktur dan bukti sebenarnya: kredensial per host, mekanisme write-only + hash chain, deteksi gap telemetry, uji log tampering dan agent berhenti | 1 | 1 | M |
| 3 | Data: subset AIT-ADS, tabel pemetaan field, aturan pelabelan, pembentukan trajectory offline, konfigurasi A | 2 (review 3) | 1 | M |
| 4 | Classifier dan Risk Engine: fitur trajectory, latih dan kalibrasi (leave-one-scenario-out), konfigurasi B dan C, unit test R, matriks dampak disetujui | 3 | 3 | L |
| 5 | LLM Gateway: Cloud, Local, validator, redaction, batas konteks, uji injection dan fallback, pilih model (dapat paralel dengan 4) | 2 | 1, 3 | L |
| 6 | Policy Gate + Availability Guard dalam DRY_RUN: tingkat 0-3, pengaman anti-manipulasi, uji B tidak sehat, alert storm, event palsu lintas-host | 3 (dengan 1) | 4, 5 | M |
| 7 | Aktifkan drain backend hanya di lab setelah kondisi lulus; dokumentasikan pemulihan; uji classifier pada data lab | 1 dan 3 | 2, 6 | M |
| 8 | Evaluasi penuh konfigurasi A-D (AIT-ADS, leave-one-scenario-out) dan lab; laporkan semua metrik tanpa menyembunyikan kegagalan | Semua | 4-7 | L |

## 16. Kriteria selesai MVP

- Event dari Server A dan B masuk ke collector terpisah.

- Penghapusan log lokal tidak menghapus salinan event yang sudah disimpan terpusat.

- Satu trajectory menunjukkan event, waktu, host, sumber bukti, dan hubungan yang dapat ditelusuri.

- Cloud dan Local LLM menghasilkan JSON valid melalui validator yang sama; fallback teruji.

- Log tidak dipercaya sebagai instruksi; tidak ada akses shell dari model.

- Risk Engine menghitung hasil deterministik yang dapat direproduksi dari input tersimpan.

- Policy Gate menolak aksi jika bukti tidak valid atau Availability Guard gagal.

- Mode DRY_RUN bekerja; drain backend hanya aktif setelah test keselamatan lulus.

- Threat model tertulis dan setiap ancaman pada tabel bagian 3 punya uji yang sudah dijalankan.

- Alert storm dan event palsu lintas-host tidak menyebabkan lebih dari satu backend di-drain; cooldown teruji.

- Drain tidak dijalankan ketika B berstatus diwaspadai; konteks yang terpotong ditandai dan tidak memicu aksi otomatis.

- Hasil konfigurasi A-D, false positive, recall, latency, dan service availability didokumentasikan per skenario, termasuk skenario yang hasilnya buruk.

- Hasil AIT-ADS dan hasil lab dilaporkan terpisah, dengan catatan batas generalisasi.

## 17. Keputusan yang masih terbuka

- Nama dan versi Cloud LLM dan Local LLM, hardware lab, batas konteks, dan biaya (Milestone 5).

- Nilai `T_watch`, `T_review`, `T_auto(k)`, `p_review`, dan parameter pengaman respons (setelah validasi, Milestone 4 dan 6).

- Matriks dampak C/I/A per aset yang disetujui tim (sebelum Milestone 4).

- Mekanisme konkret write-only dan hash chain untuk Evidence Store (Milestone 2).

- Aturan pelabelan final dan ukuran window trajectory (Milestone 3).

- Kalender dan tenggat setiap milestone.

- Tinjauan pustaka tambahan (korelasi alert, LLM untuk triase SOC, respons otomatis, dan posisi terhadap Wazuh Active Response) sebelum mengklaim kebaruan. Di blueprint ini baru ada sumber pada bagian 18.

## 18. Sumber rujukan utama

- Landauer, M., Skopik, F., & Wurzenberger, M. (2023). **AIT Alert Data Set**, Zenodo. [https://zenodo.org/records/8263181](https://zenodo.org/records/8263181)

- Landauer, M., Skopik, F., & Wurzenberger, M. (2024). **Introducing a New Alert Data Set for Multi-Step Attack Analysis**. CSET 2024. [https://doi.org/10.1145/3675741.3675748](https://doi.org/10.1145/3675741.3675748)

- Ekstedt, M., Afzal, Z., Mukherjee, P., Hacks, S., & Lagerström, R. (2023). **Yet another cybersecurity risk assessment framework**. *International Journal of Information Security*, 22, 1713-1729. [https://doi.org/10.1007/s10207-023-00713-y](https://doi.org/10.1007/s10207-023-00713-y)

- OWASP GenAI Security Project, **LLM Top 10** (gunakan sebagai daftar risiko dan bahan uji prompt injection; periksa edisi yang dipakai dalam dokumentasi). [https://genai.owasp.org/llm-top-10/](https://genai.owasp.org/llm-top-10/)
