# DEFNETT - Product Requirements Document (PRD)

**Versi PRD:** 1.0 (draf)\
**Produk:** DEFNETT, prototipe laboratorium deteksi serangan multi-step dengan respons terbatas kebijakan\
**Dokumen terkait:** DEFNETT Blueprint v2 (rancangan teknis; PRD ini menjawab "apa dan mengapa", blueprint menjawab "bagaimana")\
**Pemilik:** Tim DEFNETT (3 anggota)

> Batas klaim: PRD ini mendefinisikan kebutuhan dan target rekayasa. Penurunan false positive, keandalan Risk Engine, dan waktu respons belum terbukti sampai pengujian dilakukan. Angka target berstatus target tim atau "ditetapkan kemudian", bukan hasil atau standar universal.

## 1. Ringkasan

DEFNETT adalah prototipe laboratorium yang mengubah banyak alert terpisah dari dua server Linux menjadi rangkaian kejadian (trajectory) yang dapat ditelusuri, menghitung risiko secara terukur, lalu menjalankan respons yang dibatasi kebijakan tanpa mengorbankan ketersediaan layanan. AI (LLM) berperan sebagai penasihat yang merangkum konteks dan merujuk bukti; AI tidak pernah memegang kuasa eksekusi.

Nilai utama yang ingin dibuktikan:

- korelasi trajectory dan penilaian risiko terkalibrasi dapat menurunkan false positive dibandingkan triase per alert;

- bukti tetap utuh meskipun host yang dipantau dimanipulasi;

- respons otomatis dapat dibatasi sehingga tidak menjadi celah serangan terhadap ketersediaan.

## 2. Latar belakang dan masalah

- Alert dari Wazuh dan sumber sejenis datang sebagai kejadian terpisah. Serangan multi-step baru terlihat jika kejadian dikaitkan menurut waktu, host, proses, dan bukti.

- Triase manual atau berbasis ambang level alert cenderung menghasilkan false positive yang tinggi, sedangkan respons otomatis yang salah dapat menghentikan layanan yang sah.

- Penyerang yang menguasai satu host dapat menghapus log lokal, menghentikan agent, memalsukan event, atau menyisipkan teks untuk memanipulasi AI.

- LLM berguna untuk merangkum konteks, tetapi tidak boleh menjadi sumber skor risiko atau izin eksekusi.

## 3. Tujuan, non-tujuan, dan metrik

### Tujuan

- **G1.** Mengelompokkan alert dari dua host menjadi trajectory yang menunjukkan event, waktu, host, bukti, dan hubungan.

- **G2.** Menghitung risiko per trajectory secara deterministik dan dapat direproduksi dari input tersimpan.

- **G3.** Menjaga bukti tetap tersedia walaupun log lokal dihapus atau agent dihentikan.

- **G4.** Menjalankan respons terbatas (awalnya DRY_RUN, lalu drain backend di lab) hanya jika semua prasyarat kebijakan terpenuhi.

- **G5.** Menunjukkan lewat evaluasi terkontrol komponen mana yang menurunkan false positive.

### Non-tujuan (di luar lingkup versi ini)

- Penggunaan di lingkungan produksi atau jaringan operasional nyata.

- Lebih dari dua server yang dipantau.

- Mitigasi DDoS volumetrik dari luar, serta kompromi control plane atau rantai pasok Wazuh/model.

- Isolasi jaringan otomatis (hanya lewat persetujuan operator).

- Pelatihan atau fine-tuning LLM sendiri.

- Dashboard yang kompleks.

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

## 5. Ruang lingkup

| Dalam lingkup | Di luar lingkup |
| -------------------------------------------------- | -------------------------------------------------- |
| Dua server Linux, HAProxy, satu control plane terpisah | Lingkungan produksi, lebih dari dua server |
| Wazuh agent + FIM/log (Suricata opsional) | Sumber telemetry lain di luar yang disebut |
| Trajectory Engine, Risk Engine, Policy Gate | Dashboard kompleks |
| Cloud LLM utama dan Local LLM fallback | Pelatihan atau fine-tuning LLM |
| DRY_RUN dan drain backend A di lab | Isolasi jaringan otomatis |
| Evaluasi pada AIT-ADS dan skenario lab | Klaim kinerja di jaringan operasional nyata |

## 6. Kebutuhan fungsional

Prioritas: **Wajib** (harus ada untuk MVP), **Sebaiknya** (bernilai tinggi, boleh bergeser), **Opsional**. Kolom terakhir merujuk ke bagian Blueprint v2.

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

Rilis mengikuti milestone pada Blueprint v2 bagian 15. Kalender belum ditetapkan karena tenggat belum diketahui.

| Rilis | Cakupan | Kebutuhan utama | Keluaran yang dapat didemonstrasikan |
| ---------- | ---------------------------------------------- | ------------------------------------ | -------------------------------------------------- |
| R1 | Irisan tipis end-to-end dengan stub (Milestone 1) | FR-01, FR-02, FR-05, FR-15, FR-18 (DRY_RUN) | Satu alert melintasi seluruh jalur dan menghasilkan keputusan tercatat |
| R2 | Bukti dan data (Milestone 2-3) | FR-03, FR-04, FR-06 | Uji log tampering; trajectory offline dari subset AIT-ADS |
| R3 | Analisis dan risiko (Milestone 4-5) | FR-07 sampai FR-14, FR-16 | Classifier terkalibrasi; Risk Engine teruji; LLM Cloud/Local dengan validator |
| R4 | Kebijakan dan respons (Milestone 6-7) | FR-15, FR-17 sampai FR-20 | DRY_RUN lengkap; drain di lab dan pemulihan |
| R5 | Evaluasi dan laporan (Milestone 8) | FR-21 sampai FR-24 | Hasil A-D per skenario dan hasil lab, termasuk kegagalan |

### Definisi selesai (MVP)

MVP dianggap selesai bila seluruh kriteria pada Blueprint v2 bagian 16 terpenuhi, khususnya: event dari A dan B masuk ke collector terpisah; bukti tetap ada setelah log lokal dihapus; JSON model lolos validator dengan fallback teruji; Risk Engine deterministik; Policy Gate menolak aksi jika bukti tidak valid atau Availability Guard gagal; pengaman anti-manipulasi teruji; dan hasil A-D serta hasil lab dilaporkan apa adanya.

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
