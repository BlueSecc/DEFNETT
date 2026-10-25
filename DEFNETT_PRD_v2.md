# DEFNETT — Product Requirements Document (PRD)

**Versi PRD:** 2.0 (revisi 24 Oktober 2026)\
**Produk:** DEFNETT, prototipe laboratorium pertahanan insiden dengan demo visual *Cyber Intrusion Patrol*\
**Dokumen terkait:** DEFNETT Blueprint v3 (rancangan teknis); PRD menjelaskan kebutuhan dan kriteria penerimaan, blueprint menjelaskan rancangan serta urutan implementasi\
**Pemilik:** Tim DEFNETT (3 anggota)

> **Batas klaim dan status:** kebutuhan dalam dokumen ini adalah target produk, bukan pernyataan bahwa semua fitur telah tersedia. Pada baseline lab yang diperiksa, pemantauan file, collector, dashboard, Patrol Canvas 2D, event aplikasi, playbook canary terbatas, Policy Gate deterministik cakupan lab, dan Scenario Driver tiga skenario containment (dengan uji integrasi `test-scenarios.sh`) sudah ada. Classifier terkalibrasi, korelasi trajectory yang matang, dan integrasi Cloud/Local LLM masih merupakan pekerjaan yang direncanakan. Angka target merupakan target tim sampai hasil uji dipublikasikan.

## 1. Ringkasan

DEFNETT adalah prototipe laboratorium untuk memantau perubahan dan aktivitas mencurigakan pada dua server aplikasi Linux, menghubungkan event dengan bukti yang dapat diperiksa, lalu membatasi respons agar tidak menjatuhkan seluruh layanan. Produk ini memiliki dua lapisan yang harus tetap dipisahkan: **mesin pertahanan yang menghasilkan event dan keputusan nyata**, serta **visualisasi Patrol bergaya game stealth** yang membantu juri memahami urutan kejadian.

Mode demo yang ditargetkan bernama **Cyber Intrusion Patrol**. Penyusup virtual bergerak menuju aset digital, agent patroli memvisualisasikan pemeriksaan, dan panel timeline menampilkan event yang benar-benar diterima collector. Untuk skenario canary, sistem dapat mengeluarkan satu backend dari rotasi HAProxy, mengarantina artefak uji yang telah diverifikasi, memeriksa kesehatan, lalu mengaktifkan kembali backend jika memenuhi syarat. Animasi karakter bukan bukti serangan dan tidak boleh menjadi satu-satunya pemicu tindakan keamanan.

Nilai yang akan diuji adalah apakah korelasi bukti dan kebijakan respons dapat mengurangi *false containment* serta mempertahankan ketersediaan layanan. Klaim tersebut belum boleh dinyatakan berhasil sebelum evaluasi komparatif dan pengukuran layanan dilakukan.
## 2. Latar belakang dan masalah

- Alert dari Wazuh dan sumber sejenis datang sebagai kejadian terpisah. Serangan multi-step baru terlihat jika kejadian dikaitkan menurut waktu, host, proses, dan bukti.

- Triase manual atau berbasis ambang level alert cenderung menghasilkan false positive yang tinggi, sedangkan respons otomatis yang salah dapat menghentikan layanan yang sah.

- Penyerang yang menguasai satu host dapat menghapus log lokal, menghentikan agent, memalsukan event, atau menyisipkan teks untuk memanipulasi AI.

- LLM berguna untuk merangkum konteks, tetapi tidak boleh menjadi sumber skor risiko atau izin eksekusi.

### Posisi penelitian dan batas klaim

Korelasi alert multi-step sudah memiliki benchmark publik melalui AIT-ADS (Landauer et al., 2024). Penelitian CIPHER-A (2026) juga mengusulkan validasi konsekuensi respons sebelum eksekusi dan evaluasi ulang respons terhadap adaptasi penyerang; sementara AIDA, sebuah preprint Oktober 2026, membahas verifikasi investigasi triase SOC berbasis bukti. Karena itu, DEFNETT **tidak** mengklaim baru karena menggunakan LLM, mengorelasikan alert, atau melakukan respons otomatis.

Kontribusi yang hendak diuji dipersempit pada penerapan *evidence-gated, availability-aware containment* dalam skenario dua backend redundan: membatasi tindakan pada backend target, memeriksa kesiapan backend survivor, mengukur dampak ke permintaan layanan, dan memverifikasi pemulihan. Klaim ini tetap merupakan hipotesis kontribusi sampai ditinjau terhadap literatur lebih luas dan dibuktikan secara eksperimen.

Rujukan latar yang relevan: [AIT-ADS / CSET 2024](https://doi.org/10.1145/3675741.3675748), [CIPHER-A (2026)](https://link.springer.com/article/10.1007/s44163-026-02058-6), [AIDA preprint (7 Oktober 2026)](https://arxiv.org/abs/2610.10608), dan [NIST SP 800-82 Rev. 3](https://csrc.nist.gov/pubs/sp/800/82/r3/final).

### Konteks pengguna TNI AD: kasus penggunaan layanan pendukung satu satuan

Kasus penggunaan yang dituju: sebuah satuan menjalankan layanan IT pendukung operasi/administrasi (mis. portal administrasi internal atau antrean data sistem lapangan) pada **dua backend redundan di balik satu load balancer**. Ancaman terdeteksi pada backend pertama; kebijakan organisasi menuntut seluruh respons berbasis bukti dan tidak boleh menghentikan backend kedua. DEFNETT menempelkannya sebagai berikut:

| Aspek operasi | Prinsip yang dituntut | Yang dilakukan lab DEFNETT |
|---|---|---|
| Deteksi pada backend target | Bukti harus bisa ditelusuri (hash, path, waktu, evidence ID) | Agent FIM mengirim snapshot hash; event tersimpan di SQLite ber-hash-chain; setiap keputusan menyimpan alasan lengkap di `policy_decisions` |
| Respons tak boleh mematikan survivor | Ketersediaan layanan lebih diutamakan daripada aksi agresif | Policy Gate mengecek kesehatan **dan** kapasitas survivor sebelum izin; skenario `containment_blocked_survivor_down` membuktikan penolakan (PASS, alasan `SURVIVOR_NOT_HEALTHY`) |
| Rejoin hanya setelah pemeriksaan pemulihan | Host terinfeksi tidak boleh kembali melayani tanpa verifikasi | Health check HAProxy + verifikasi integritas sebelum `REJOINING`; tanpa kelulusan cek, host tetap di luar rotasi |
| Akuntabilitas keputusan | Setiap izin/penolakan punya jejak audit | Ladder skenario `PRECHECK → … → POLICY_EVALUATION → …` terekam per langkah; metrik latensi terekam per run |

Sekaligus pengeluaran yang perlu jujur:

1. **Diimplementasikan pada lab**: lab Linux (Docker) dengan HAProxy, dua backend aplikasi, dua agent, collector, worker remediasi per-host, dashboard; Policy Gate deterministik; playbook canary drain/quarantine/verify/rejoin; tiga skenario containment teruji (`sh lab/test-scenarios.sh`).
2. **Relevansi desain** dengan prinsip keandalan/ketersediaan: maksimal satu backend di-drain, verifikasi survivor, cooldown/rate limit, dan fail-closed bila bukti/kesehatan tidak terpenuhi — selaras dengan tuntutan SP 800-82 agar kontrol keamanan tidak mengorbankan **performa, reliabilitas, dan keselamatan** layanan.
3. **Pengembangan potensial ke OT** adalah *desain lanjutan*, bukan fakta implementasi: pola ganda backend/standby dan kontrol berbasis bukti dapat dipetakan ke lapisan pengawasan OT (mis. pasangan server HMI redudansi), tetapi kebutuhan OT (siklus deterministik, latensi hard-realtime, keselamatan proses) membutuhkan pengujian terpisah. Terakhir, kerangka acuan OT adalah NIST SP 800-82 Rev. 3 (final, September 2023; [DOI](https://doi.org/10.6028/NIST.SP.800-82r3)) dan per 21 September 2026 tersedia SP 800-82 Rev. 4 **Initial Public Draft** (komentar s.d. 30 November 2026; [layout r4/ipd](https://csrc.nist.gov/pubs/sp/800/82/r4/ipd), restruktur mengikuti CSF 2.0 dan prinsip zero trust) — Rev. 4 masih draf, bukan final.
4. **Belum diuji**: tidak ada pengujian terhadap PLC, SCADA, HMI, perangkat OT nyata, jaringan industrial, maupun environment satuan riil; nama `server-a`/`server-b` adalah aplikasi uji lab, **bukan** proksi perangkat OT. DEFNETT belum dipakai atau divalidasi di lingkungan operasional TNI AD; penjelasan di atas adalah pemetaan kebutuhan organisasi ke prinsip desain.


## 3. Tujuan, non-tujuan, dan metrik

### Tujuan

- **G1.** Mengelompokkan alert dari dua host menjadi trajectory yang menunjukkan event, waktu, host, bukti, dan hubungan.

- **G2.** Menghitung risiko per trajectory secara deterministik dan dapat direproduksi dari input tersimpan.

- **G3.** Menjaga bukti tetap tersedia walaupun log lokal dihapus atau agent dihentikan.

- **G4.** Menjalankan respons terbatas (awalnya DRY_RUN, lalu drain backend di lab) hanya jika semua prasyarat kebijakan terpenuhi.

- **G5.** Menunjukkan lewat evaluasi terkontrol kontribusi komponen terhadap false positive, false containment, latensi, dan ketersediaan layanan.
- **G6.** Menyediakan demo Patrol bergaya game stealth yang memvisualisasikan skenario, tetapi selalu menautkan tahap demo ke event, bukti, dan hasil respons dari lab.

### Non-tujuan (di luar lingkup versi ini)

- Penggunaan di lingkungan produksi atau jaringan operasional nyata.

- Lebih dari dua server yang dipantau.

- Mitigasi DDoS volumetrik dari luar, serta kompromi control plane atau rantai pasok Wazuh/model.

- Isolasi jaringan otomatis (hanya lewat persetujuan operator).

- Pelatihan atau fine-tuning LLM sendiri.

- Game stealth penuh dengan sistem pertarungan, level, inventori, atau tujuan hiburan yang terpisah dari keamanan.
- Menggunakan gerak karakter atau event sintetis browser sebagai bukti keamanan atau pemicu containment.
- Integrasi langsung dengan PLC, SCADA, atau perangkat OT nyata pada versi kompetisi ini.
- Klaim deployment produksi atau kesiapan operasional TNI AD.

### Metrik keberhasilan

| Metrik | Definisi singkat | Target | Status target |
| ------------------------------ | ------------------------------------------------ | ---------------------------------------- | -------------------------- |
| False Positive Rate (insiden) | Proporsi trajectory negatif yang diberi tingkat tindakan tinggi | ≤5% (contoh target awal) | Target tim, belum terbukti |
| Recall (insiden) | Proporsi trajectory serangan yang terdeteksi | Ditetapkan tim sebelum Milestone 8 | Ditetapkan kemudian |
| Kalibrasi `P_attack` | Brier score dan reliability plot | Dilaporkan; ambang ditetapkan tim | Ditetapkan kemudian |
| Detection latency | Waktu dari event pertama serangan sampai alert/keputusan | Dilaporkan; target ditetapkan setelah baseline | Ditetapkan kemudian |
| Response latency | Waktu dari keputusan sampai aksi terverifikasi | Dilaporkan; target ditetapkan setelah baseline | Ditetapkan kemudian |
| Ketersediaan layanan | Persentase permintaan berhasil selama skenario | Ditetapkan tim; tanpa penurunan akibat respons keliru | Ditetapkan kemudian |
| Drain/isolasi keliru | Jumlah aksi otomatis pada trajectory negatif | 0 pada skenario normal sah (usulan) | Usulan, perlu persetujuan tim |
| Kontribusi komponen | Selisih metrik konfigurasi B-A, C-B, D-C | Dilaporkan apa adanya, termasuk bila tidak membaik | Tanpa target arah |

Baseline pertama dua metrik ini sudah diukur di lab (24 Oktober 2026, `lab/METRICS_REPORT.md`): detection latency median ≈0,8 s dan ketersediaan layanan 100% pada n=289 request (37 baseline / 114 containment / 138 recovery; dua pengukuran via HTTP nyata, bukan status container). Pengecekan ulang dengan `measure_burst.py` pada jendela drain yang **terverifikasi timestamp** (3 run, 88 request semua dengan koneksi HTTP baru): **0 request** diarahkan ke target yang di-drain, seluruhnya dilayani survivor dengan HTTP 200. Kedua hasil terbatas pada lab dan belum menjadi bukti target produksi; kalibrasi `P_attack`, recall, dan FPR insiden menunggu classifier dan test harness A-D.

## 4. Pengguna dan skenario

### Peran pengguna

| Peran | Kebutuhan utama |
| -------------------------- | ---------------------------------------------------------------------------------------------------- |
| Operator keamanan | Melihat trajectory, bukti, skor, kebijakan yang berlaku, dan hasil aksi; menyetujui atau menolak rekomendasi |
| Administrator infrastruktur | Memastikan agent, collector, evidence store, dan load balancer berjalan; mengatur parameter dan mode (DRY_RUN atau aktif) |
| Penguji/evaluator | Menjalankan skenario uji dan ablasi A-D, serta mereproduksi hasil dari data dan konfigurasi tersimpan |

### Skenario pengguna utama

- **S1 - Serangan multi-step terdeteksi.** Beberapa alert pada Server A (perubahan file, proses tak biasa) dikelompokkan menjadi satu trajectory. Operator melihat timeline dengan bukti dan menerima rekomendasi sesuai tingkat risiko.

- **S2 - Manipulasi host.** Penyerang menghapus log lokal dan menghentikan agent. Salinan event tetap ada di Evidence Store; status telemetry ditandai terputus, bukan dianggap aman.

- **S3 - Respons aman.** Risiko memenuhi ambang, verdict LLM sejalan, Server B sehat dan tidak diwaspadai. Dalam DRY_RUN sistem mencatat aksi yang akan dilakukan; di mode aktif di lab, Server A di-drain dan hasilnya diverifikasi lewat health check.

- **S4 - Respons ditahan.** Server B tidak sehat, kedua model gagal, atau kondisi ambigu. Sistem tidak mengisolasi otomatis; operator mendapat eskalasi dengan bukti.

- **S5 - Pemicu palsu.** Penyerang membanjiri alert atau memalsukan event atas nama host lain. Pengaman membatasi aksi dan mengeskalasi ke operator.

- **S6 - Cyber Intrusion Patrol (demo utama).** Operator memulai skenario terkontrol. Karakter penyusup memvisualisasikan urutan rekognisi, akses ke aset lab, dan perubahan canary. Collector menjadi sumber kebenaran event. Setelah bukti memenuhi kebijakan, satu backend target dapat di-drain; backend survivor harus tetap sehat dan melayani request. Hasil containment, karantina, health check, serta rejoin ditampilkan dalam timeline.

- **S7 - Respons ditolak (demo keselamatan).** Kondisi backend survivor dibuat tidak sehat atau bukti tidak cukup. Policy Gate deterministik menolak containment otomatis, mencatat seluruh alasan, dan meminta pemeriksaan operator. Tersedia di lab via Scenario Driver (`sh lab/test-scenarios.sh`): skenario `containment_blocked_survivor_down` dan `containment_blocked_evidence_invalid` PASS beserta guard double-start.

## 5. Ruang lingkup

| Dalam lingkup versi kompetisi | Di luar lingkup |
| -------------------------------------------------- | -------------------------------------------------- |
| Lab lokal dua backend aplikasi Linux, HAProxy, collector, dua agent, dan dashboard | Lingkungan produksi, lebih dari dua backend, atau jaringan operasional nyata |
| FIM dan event aplikasi pada baseline; adapter Wazuh/Suricata merupakan target lanjutan, bukan fitur yang sudah terpasang | Klaim bahwa Wazuh/Suricata telah terintegrasi sebelum dibuktikan |
| Mode Patrol 2D top-down sebagai lapisan visualisasi skenario | Game stealth penuh yang menentukan tindakan keamanan berdasarkan gerak karakter |
| Event canary terkontrol, DRY_RUN, drain satu backend, karantina canary, health check dan rejoin di lab | Penghapusan file sembarang, isolasi jaringan host penuh, atau aksi terhadap perangkat OT |
| Target rancangan: trajectory, classifier terkalibrasi, LLM sebagai penasihat, Policy Gate, dan Availability Guard | Klaim bahwa classifier/LLM/policy umum sudah aktif sebelum implementasi dan pengujian |
| Evaluasi AIT-ADS terpisah dari eksperimen integrasi lab | Klaim generalisasi ke lingkungan operasional nyata |

## 6. Kebutuhan fungsional

Prioritas: **Wajib** (untuk target MVP yang disepakati), **Sebaiknya** (bernilai tinggi), **Opsional**. Kebutuhan berikut mendefinisikan keadaan target; tabel ini bukan daftar fitur yang sudah selesai. Baseline implementasi dan status pekerjaan dijelaskan di Blueprint v3 bagian 2.1. Kolom terakhir merujuk ke bagian Blueprint v3.

### Pengumpulan dan bukti

| ID | Kebutuhan | Prioritas | Kriteria penerimaan | Blueprint |
| ---------------- | ------------------------------------------ | -------------------- | ---------------------------------------------------------- | -------------------- |
| FR-01 | Mengumpulkan event dari Server A dan B ke collector terpisah dengan kredensial per host | Wajib | Event dari kedua host masuk; status agent dipantau dari control plane | 5 |
| FR-02 | Menormalisasi event ke skema internal dan menyamarkan nilai sensitif | Wajib | Pemetaan field per sumber terdokumentasi; field tak tersedia bernilai `null`; ID samaran konsisten | 6 |
| FR-03 | Menyimpan event asli dan ternormalisasi di Evidence Store write-only dengan hash chain | Wajib | Penghapusan log lokal tidak menghapus salinan; upaya hapus dari host dan akun collector ditolak | 3, 5 |
| FR-04 | Mendeteksi dan menandai gap telemetry | Wajib | Status normal/terputus/terlambat/tidak dapat diverifikasi tercatat; sistem tidak menyimpulkan server aman saat agent berhenti | 7 |

### Trajectory

| ID | Kebutuhan | Prioritas | Kriteria penerimaan | Blueprint |
| ---------------- | ------------------------------------------ | -------------------- | ---------------------------------------------------------- | -------------------- |
| FR-05 | Membentuk trajectory menurut window waktu, host, proses/user tersamarkan, dan hubungan antar-event | Wajib | Satu trajectory menunjukkan event, waktu, host, sumber, hubungan, dan ID bukti; duplikat dipisah; event terlambat tercatat | 7 |
| FR-06 | Menandai hubungan lintas-host dan status host "diwaspadai" | Wajib | Trajectory yang melibatkan host lain menandai host itu diwaspadai dan Availability Guard membacanya | 7, 11 |
| FR-07 | Membatasi ukuran konteks untuk LLM dan menandai pemotongan | Sebaiknya | Event berulang digabung dengan evidence ID tetap tertelusuri; `context_truncated = true` bila terpotong dan tanpa aksi otomatis | 7, 8 |

### Analisis AI

| ID | Kebutuhan | Prioritas | Kriteria penerimaan | Blueprint |
| ---------------- | ------------------------------------------ | -------------------- | ---------------------------------------------------------- | -------------------- |
| FR-08 | LLM Gateway dengan Cloud LLM utama dan Local LLM fallback | Wajib | Timeout dan retry terkonfigurasi; fallback teruji; jika keduanya gagal status `unavailable` | 8 |
| FR-09 | Output Validator untuk keluaran LLM | Wajib | JSON Schema, enum, panjang field, allowlist `reason_codes`, dan evidence ID diperiksa; output tidak valid ditolak | 8 |
| FR-10 | Minimalisasi dan redaksi data yang dikirim ke cloud, serta mode local-only | Wajib | Tidak ada secret, token, private key, kredensial, atau isi file sensitif pada sampel payload; local-only dapat diaktifkan | 3, 9 |
| FR-11 | Pertahanan prompt injection dan manipulasi log | Wajib | Log diperlakukan sebagai data; LLM tanpa tool eksekusi; uji injection pada nama file dan teks log lulus, termasuk upaya memunculkan verdict `benign` | 9 |

### Risiko dan keputusan

| ID | Kebutuhan | Prioritas | Kriteria penerimaan | Blueprint |
| ---------------- | ------------------------------------------ | -------------------- | ---------------------------------------------------------- | -------------------- |
| FR-12 | Estimator `P_attack` per trajectory dari classifier terkalibrasi | Wajib | Probabilitas dikalibrasi; Brier score atau reliability plot dilaporkan; verdict LLM bukan fitur | 10 |
| FR-13 | Risk Engine menghitung `R = P_attack × I_CIA` dan mencatat `I_max` | Wajib | Hasil deterministik dan reproducible dari input tersimpan; versi konfigurasi dan semua komponen tercatat; unit test lulus | 10 |
| FR-14 | Matriks dampak C/I/A per aset | Wajib | Disetujui tim sebelum Milestone 4; alasan tiap nilai terdokumentasi | 10 |
| FR-15 | Policy Gate dengan empat tingkat tindakan (catat, alert, operator, otomatis) | Wajib | Aksi ditolak jika bukti tidak valid; aturan dampak kritis diterapkan; kondisi ambigu mengarah ke operator | 11 |
| FR-16 | Peran verdict LLM sebagai penasihat | Wajib | Verdict tidak masuk R; dapat menaikkan eskalasi atau menahan aksi otomatis; tidak pernah menjadi izin | 8, 11 |

### Respons

| ID | Kebutuhan | Prioritas | Kriteria penerimaan | Blueprint |
| ---------------- | ------------------------------------------ | -------------------- | ---------------------------------------------------------- | -------------------- |
| FR-17 | Availability Guard dengan pengaman anti-manipulasi | Wajib | Maksimal satu backend di-drain; cooldown dan rate limit berlaku; lonjakan alert dieskalasi; event host X tidak memicu aksi otomatis terhadap host lain; drain ditahan bila B tidak sehat atau diwaspadai | 11 |
| FR-18 | Response Orchestrator dengan aksi allowlist, DRY_RUN default, dan `DRAIN_BACKEND_A` | Wajib | Aksi idempoten dengan batas waktu; hasil diverifikasi lewat health check; semua tercatat di audit; drain aktif hanya setelah uji keselamatan lulus | 11 |
| FR-19 | Persetujuan operator untuk tingkat 2; `ISOLATE_HOST_NETWORK` bersifat opsional dan hanya lewat operator | Wajib | Rekomendasi aksi menunggu keputusan operator; isolasi tidak ada di jalur otomatis | 11 |
| FR-20 | Pemulihan/rejoin backend secara manual | Sebaiknya | Pemeriksaan ulang integritas dan persetujuan sesuai policy sebelum rejoin; prosedur terdokumentasi | 11 |

### Audit, antarmuka, dan evaluasi

| ID | Kebutuhan | Prioritas | Kriteria penerimaan | Blueprint |
| ---------------- | ------------------------------------------ | -------------------- | ---------------------------------------------------------- | -------------------- |
| FR-21 | Audit log lengkap | Wajib | Mencatat prompt version, model version, request ID, model terpakai, status validasi, hasil fallback, skor, kebijakan, aksi, kegagalan, dan perubahan konfigurasi | 5, 9 |
| FR-22 | Operator UI minimal | Sebaiknya | Menampilkan timeline, bukti, model terpakai, skor, kebijakan, dan hasil aksi; tanpa fitur kompleks | 5, 13 |
| FR-23 | Harness evaluasi konfigurasi A-D | Wajib | Leave-one-scenario-out; hasil per skenario, rata-rata, dan rentang; metrik pada tingkat alert dan insiden; dapat direproduksi | 12 |
| FR-24 | Test set laboratorium | Wajib | Mencakup seluruh skenario daftar di Blueprint bagian 12 (normal sah, multi-step, log tampering, agent berhenti, kegagalan model, injection, B tidak sehat, alert storm, event palsu lintas-host, konteks terpotong, drain dan pemulihan) | 12 |

### Patrol dan orkestrasi skenario demo

| ID | Kebutuhan | Prioritas | Kriteria penerimaan | Blueprint |
| ---------------- | ------------------------------------------ | -------------------- | ---------------------------------------------------------- | -------------------- |
| FR-25 | Mode Cyber Intrusion Patrol | Wajib | Peta top-down menampilkan Server A/B, file yang dipantau, agent patroli, aktor penyusup, status backend, dan event terbaru; visual dibedakan dari status keamanan terverifikasi | 2.3, 4, 13 |
| FR-26 | Scenario Driver yang aman dan dapat diulang | Wajib | Tombol Mulai/Jeda/Reset menjalankan urutan skenario versi lab; hanya fixture canary dan aksi allowlist yang boleh digunakan; status skenario dapat dibaca dari API lab | 2.3, 15 |
| FR-27 | Tautan animasi-ke-bukti | Wajib | Setiap animasi yang merepresentasikan aksi keamanan harus menunjuk ke event ID atau diberi label eksplisit “visualisasi”; event sintetis browser tidak masuk sebagai evidence dan tidak dapat memicu containment | 2.3, 9, 11 |
| FR-28 | Timeline end-to-end | Wajib | Menampilkan timestamp, host target, evidence ID, status kebijakan, aksi yang dicoba, hasil health check, status karantina, dan hasil rejoin | 2.3, 5, 13 |
| FR-29 | Skenario keselamatan negatif | Wajib | Jika backend survivor tidak sehat, kapasitas tidak terverifikasi, atau evidence invalid, respons otomatis ditolak/ditahan dan alasan terlihat pada UI; tidak ada backend kedua yang di-drain | 11, 12, 15 |
| FR-30 | Profil demo terisolasi | Wajib | Skenario hanya dapat berjalan pada lab lokal/isolasi yang ditentukan; target path dan marker dikunci; reset tidak menghapus volume atau data pengguna di luar fixture yang ditetapkan | 3, 11, 15 |
| FR-31 | Hasil ukur selama demo | Wajib | Menampilkan request berhasil/gagal, waktu deteksi, waktu containment, backend aktif, dan hasil verifikasi; nilai berasal dari monitor/test harness, bukan animasi | 12, 15 |

## 7. Kebutuhan non-fungsional

| ID | Kategori | Kebutuhan |
| ---------------- | ------------------------ | -------------------------------------------------------------------------------------- |
| NFR-01 | Keselamatan AI | Tidak ada akses shell/root/eksekusi atau API load balancer bagi model; hanya aksi enum allowlist yang dapat dijalankan |
| NFR-02 | Ketersediaan | Tidak ada aksi otomatis jika kapasitas tersisa tidak cukup atau kondisi tidak diketahui; target ketersediaan ditetapkan tim |
| NFR-03 | Integritas bukti | Bukti tidak dapat dihapus atau diubah dari host yang dipantau; hash saja tidak dianggap cukup |
| NFR-04 | Auditabilitas | Setiap keputusan dan aksi dapat ditelusuri ke input, versi konfigurasi, model, dan bukti |
| NFR-05 | Reprodusibilitas | Hasil Risk Engine dan evaluasi dapat diulang dari data, seed, dan konfigurasi tersimpan |
| NFR-06 | Privasi | Data ke cloud disamarkan dan diminimalkan; local-only tersedia bila cloud dilarang |
| NFR-07 | Degradasi anggun | Cloud gagal berarti Local; keduanya gagal berarti `unavailable`, monitoring dan pengumpulan bukti tetap jalan |
| NFR-08 | Performa | Detection dan response latency diukur dan dilaporkan; target ditetapkan setelah baseline |
| NFR-09 | Konfigurasi | Ambang, window, batas konteks, cooldown, dan rate limit adalah parameter terkonfigurasi, bukan nilai tertanam |
| NFR-10 | Kejujuran pelaporan | Semua metrik dilaporkan termasuk kegagalan; hasil AIT-ADS dan lab dilaporkan terpisah |
| NFR-11 | Isolasi demo | Scenario Driver hanya memanipulasi fixture canary yang ditentukan; tidak menerima path atau perintah bebas dari browser/LLM |
| NFR-12 | Kejelasan visual | Animasi sintetis selalu dilabeli; status deteksi, respons, dan kesehatan layanan berasal dari collector/monitor independen |

## 8. Asumsi, batasan, dan dependensi

### Asumsi

- Control plane tidak terkompromi; kanal host ke collector dilindungi (TLS dan kredensial per host); jam host disinkronkan.

- Penyedia Cloud LLM diperlakukan sebagai pihak ketiga yang hanya menerima data tersamarkan.

- Penyerang dapat menguasai satu server yang dipantau dan memanipulasi log, agent, serta teks di host tersebut.

### Batasan

- AIT-ADS bersifat sintetis dan hanya memiliki delapan skenario; hasilnya tidak membuktikan kinerja di jaringan nyata.

- Classifier yang dilatih pada AIT-ADS tidak diasumsikan berlaku di lab tanpa diuji pada data lab.

- Tim berjumlah tiga anggota; cakupan dijaga lewat prioritas dan irisan tipis lebih dulu.

### Dependensi

- Wazuh agent dan FIM/log, HAProxy, dan (opsional) Suricata.

- Dataset AIT-ADS (Zenodo record 8263181) dan pemetaan fieldnya.

- Akses Cloud LLM (jika kebijakan mengizinkan) dan sumber daya lab untuk Local LLM.

## 9. Risiko dan mitigasi

| Risiko | Dampak | Mitigasi |
| ---------------------------------------------- | ---------------------------------------- | ---------------------------------------------------------------- |
| Pergeseran distribusi AIT-ADS ke lab | Classifier menurun di lab | Peran data dipisah; uji pada data lab dan laporkan terpisah; opsi latih ulang sebagai eksperimen |
| Hanya delapan skenario | Hasil sangat bervariasi, kesimpulan lemah | Leave-one-scenario-out, laporan per skenario, tanpa klaim signifikansi yang tidak didukung |
| Penyerang memicu respons otomatis | Penurunan ketersediaan akibat DEFNETT sendiri | Maksimal satu backend, cooldown, rate limit, eskalasi lonjakan alert, aturan lintas-host |
| LLM menghasilkan keluaran tidak valid atau mengarang bukti | Keputusan salah | Validator, allowlist, cek evidence ID, LLM tanpa kuasa eksekusi |
| Prompt injection lewat nama file atau log | Verdict dimanipulasi | Data terstruktur, uji injection (termasuk upaya menahan respons sah) |
| Biaya atau latensi Cloud LLM | Evaluasi tidak lengkap | Sampling berstrata dengan seed tercatat; Local LLM sebagai fallback |
| Cakupan terlalu besar untuk tiga orang | Milestone terlambat | Irisan tipis end-to-end dahulu; prioritas Wajib/Sebaiknya; dashboard minimal |
| Label ground truth ambigu | Metrik bias | Aturan pelabelan ditulis sebelum eksperimen; sensitivitas ambigu sebagai positif dan negatif |
| Hardware lab tidak memadai untuk Local LLM | Fallback tidak berjalan | Pilih model sesuai kemampuan hardware di Milestone 5 dan catat kebutuhan |

## 10. Rencana rilis

Rilis mengikuti milestone pada Blueprint v3 bagian 15. Kalender belum ditetapkan karena tenggat belum diketahui.

| Rilis | Cakupan | Kebutuhan utama | Keluaran yang dapat didemonstrasikan |
| ---------- | ---------------------------------------------- | ------------------------------------ | -------------------------------------------------- |
| R0 | Baseline lab direproduksi | FR-01, FR-18 | Compose, event dasar, jalur canary, dan konfigurasi awal terdokumentasi |
| R1 | Patrol dan Scenario Driver | FR-25, FR-26 | Mode visual-only terpisah dari skenario; run ID dan state skenario dapat dibaca |
| R2 | Integrasi event-to-demo | FR-27, FR-28 | Canary menghasilkan event nyata yang terlihat pada timeline dengan evidence ID |
| R3 | Respons aman dan metrik layanan | FR-17 sampai FR-20, FR-29 sampai FR-31 | Jalur containment dan jalur ditahan diuji; survivor tetap melayani request pada skenario yang diizinkan |
| R4 | Analisis penelitian | FR-05 sampai FR-16, FR-21 sampai FR-24 | Trajectory/classifier/LLM yang benar-benar selesai dievaluasi; komponen yang belum selesai dinyatakan eksplisit |
| R5 | Evaluasi dan paket submission | FR-21 sampai FR-31 | Hasil A-D bila sudah tersedia, bukti demo, hasil negatif, batasan, dan dokumentasi dapat direproduksi |

### Status implementasi aktual (per 24 Oktober 2026, hasil pengukuran lab; bukan klaim produksi)

- **Teruji di lab:** R0, R1, R2, R3 — integration test `sh lab/test-scenarios.sh` 3 skenario + guard double-start (HTTP 409), 64 unit test mandiri, dan jalur `test-containment.sh` lulus. Skenario negatif (S7) menolak containment dengan alasan lengkap di UI dan `policy_decisions`. Metrik latensi per skenario terekam (`/api/demo/metrics[.csv]`).
- **Sebagian (stub):** FR-15 Policy Gate baru cakupan lab — tingkat "catat" dan "otomatis" berjalan, `DRY_RUN` default dipertahankan; tingkat "operator" (persetujuan manual) dan eskalasi alert belum ada.
- **Belum diimplementasi:** classifier terkalibrasi, korelasi trajectory lintas-host yang matang, integrasi Cloud/Local LLM nyata (advisor LLM berstatus lab/HOLD-only sekadar melewati pipeline validasi), dan evaluasi konfigurasi A-D (FR-23, FR-24) kini masih stub berbentuk 3 skenario lab — R4 dan R5 tetap pekerjaan tersisa.
- SOP diverifikasi: alert storm, log tampering, agent berhenti, dan skenario adversarial lain dalam daftar Blueprint bagian 12 belum diujikan sebagai test otomatis.

### Definisi selesai (MVP)

MVP demonstrasi kompetisi dianggap selesai hanya jika kriteria dasar di Blueprint v3 bagian 16 terpenuhi: skenario Patrol dapat dijalankan ulang; aksi canary menghasilkan event nyata; event tersebut dapat ditelusuri di timeline; DRY_RUN dan containment lab bekerja sesuai konfigurasi; backend survivor tetap melayani request; skenario negatif menahan respons saat syarat keselamatan gagal; dan seluruh hasil dicatat. Komponen classifier/LLM dan evaluasi A-D merupakan bagian target penelitian yang harus ditandai belum selesai sampai masing-masing lolos kriteria penerimaan. Tidak boleh menyatakan keseluruhan MVP AI selesai hanya karena mode game berjalan.

## 11. Pertanyaan terbuka

- Tenggat dan format penilaian (siapa pemangku kepentingan dan bagaimana hasil akan dinilai).

- Nama dan versi Cloud LLM dan Local LLM, hardware lab, dan batas biaya.

- Nilai ambang (`T_watch`, `T_review`, `T_auto(k)`, `p_review`) dan parameter pengaman respons.

- Matriks dampak C/I/A per aset.

- Mekanisme konkret write-only dan hash chain untuk Evidence Store.

- Aturan pelabelan final dan ukuran window trajectory.

- Target numerik untuk recall, latency, dan ketersediaan layanan.

- Tinjauan pustaka tambahan (korelasi alert, LLM untuk triase SOC, respons otomatis, posisi terhadap Wazuh Active Response) sebelum mengklaim kebaruan.

## 12. Glosarium

| Istilah | Arti |
| -------------------- | ---------------------------------------------------------------------------------------------------- |
| Trajectory | Rangkaian event terstruktur dalam jendela waktu yang dikaitkan menurut host, proses, user, file, atau indikator |
| `P_attack` | Probabilitas serangan per trajectory dari classifier berlabel yang dikalibrasi |
| `I_CIA`, `I_max` | Rata-rata dan nilai maksimum dampak kerahasiaan (C), integritas (I), dan ketersediaan (A) |
| `R` | Indeks risiko prototipe: `P_attack × I_CIA`, skala 0-3 |
| DRY_RUN | Mode yang mencatat aksi yang akan dilakukan tanpa mengubah layanan |
| Drain | Mengeluarkan backend dari rotasi load balancer; bukan containment penuh |
| AIT-ADS | Dataset alert publik untuk analisis serangan multi-step |
| Diwaspadai | Status host lain yang terlibat dalam trajectory sehingga aksi otomatis ditahan |
| Cyber Intrusion Patrol | Lapisan visualisasi top-down bergaya game untuk menjelaskan skenario keamanan; bukan sumber bukti itu sendiri |
| Scenario Driver | Pengendali urutan aksi demo yang dibatasi ke fixture dan aksi allowlist di lab |
| Canary | Berkas uji dengan marker khusus yang aman dan hanya digunakan untuk membuktikan jalur deteksi/remediasi |
