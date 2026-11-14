# DEFNETT

Lab pertahanan siber dua server di balik load balancer. Agent memantau integritas file, collector menilai risiko, dan saat file penting diubah, playbook respons dimulai hanya setelah operator menyetujui: server target dikeluarkan dari HAProxy, dipulihkan dari salinan master tervalidasi, lalu dimasukkan kembali, sementara situs tetap melayani lewat server lainnya.

Karya untuk Kartika Cyber Hackathon 2026, kategori **Penangkalan** (Automated Incident Response).

## Relevansi untuk pengamanan sistem satuan

- **Layanan tetap hidup.** Server yang diserang diisolasi tanpa memutus pengguna, selama ada server lain yang sehat.
- **Operator yang menentukan.** Temuan tidak pernah langsung dieksekusi; playbook menunggu persetujuan operator yang lolos login, lalu dijalankan executor terpisah yang hanya bisa bekerja lewat persetujuan itu.
- **Bukti terjaga.** File yang rusak dikarantina, dan event dicatat di SQLite dengan hash chain; setiap tindakan operator tercatat di berita acara.
- **Sumber pemulihan tervalidasi.** Salinan master kunci diproteksi manifes sha256; pemulihan menolak berjalan bila master tidak cocok.
- **Bisa di jaringan tertutup.** Kode tim hanya memakai pustaka standar Python, ditambah HAProxy dan SQLite, tanpa layanan cloud.
- **Waktu respons terukur.** Setiap insiden mencatat waktu deteksi, isolasi, dan pulih.

Ini purwarupa lab. Penerapan di lingkungan satuan memerlukan pengujian lanjutan.

## Cara mencoba

Pilih salah satu:

- **Docker (satu komputer):** jalankan `sh lab/build.sh` (token m2m, akun operator, sertifikat CA lab, dan trust anchor disiapkan oleh skrip), lalu buka dashboard di `https://127.0.0.1:8443/`. Browser perlu mempercayai CA lab.
- **Empat VM VirtualBox:** konfigurasi ada di [lab/vm](lab/vm); dashboard HTTPS di `https://192.168.56.20:8443/` setelah [TLS dan Approval Authority cutover](lab/vm/SECURITY_CUTOVER_RUNBOOK.md).
- **Tanpa menjalankan apa pun:** lihat bagian Tampilan di bawah dan video demo.

Langkah lengkapnya ada di [Petunjuk penggunaan](#petunjuk-penggunaan).

Pengujian otomatis: `python3 -m unittest discover -s lab/tests`. Dokumen lengkap: [Dokumentasi Teknis](docs/DOKUMENTASI_TEKNIS.md) dan [Hasil Uji](docs/HASIL_UJI.md).

## Petunjuk penggunaan

### 1. Menyiapkan lab

**Docker (satu komputer)**

```bash
sh lab/build.sh
```

Skrip menyiapkan token, sertifikat CA lab, data contoh, dan trust anchor, lalu mencetak kata sandi akun operator `admin`. Simpan kata sandi itu. Percayai `~/.config/defnett-lab/tls/ca.crt` di browser, lalu buka `https://127.0.0.1:8443/`. Di Docker, Patrol hanya menampilkan satu pintu karena agent berjalan di container terpisah; tab Terminal tidak dipakai.

**Empat VM VirtualBox (jaringan host-only `192.168.56.0/24`)**

| VM | Alamat | Isi |
|---|---|---|
| Gateway | `192.168.56.10` | HAProxy, situs di `http://192.168.56.10:8080/` |
| Server A | `192.168.56.11` | Blog WordPress, agent, remediator |
| Server B | `192.168.56.12` | Blog WordPress, agent, remediator |
| Collector | `192.168.56.20` | Dashboard `https://192.168.56.20:8443/`, Approval Authority, Executor |

Konfigurasi tiap VM ada di [lab/vm](lab/vm). Pembaruan dikirim dari laptop dengan skrip berikut; password SSH dan sudo diketik sendiri, dan file lama selalu dicadangkan sebagai `<nama>.bak-<waktu>`.

| Perintah | Kegunaan |
|---|---|
| `sh lab/vm/deploy-dashboard.sh` | Kirim file dashboard ke Collector (tanpa restart) |
| `sh lab/vm/deploy-terminal.sh` | Kirim `collector.py`, `web_terminal.py`, dan dashboard, restart Collector, lalu izinkan SSH dari Collector di ufw Server A/B. Tambah `SKIP_FIREWALL=1` bila aturan ufw sudah ada |
| `sh lab/vm/fix-server-a-keys.sh` | Pulihkan kunci Server A dari `/master` secara manual (menampilkan alasan gagal dulu, lalu minta konfirmasi `y`) |

### 2. Masuk sebagai operator

Klik **Masuk operator** di kanan atas dan isi akun operator. Tanpa login, dashboard hanya menampilkan "Belum masuk": status server, port, dan Playbook tidak dimuat, dan tombol **SERANG!** serta tab **Terminal** tidak bisa dipakai. Akun *viewer* bisa melihat, tetapi tidak bisa menyetujui atau menyerang.

### 3. Tab Overview

Peta topologi Operator → Collector → HAProxy → Server A/B, plus status ringkas di baris atas.

- **Node dan kabel hijau:** komponen hidup dan tersambung.
- **Merah putus-putus:** mati atau terputus. Contohnya kabel HAProxy → Server A saat Server A diisolasi, atau semuanya merah bila Collector tidak terjangkau.
- **LB:** hijau selama minimal satu server masih UP (situs tetap melayani), merah bila tidak ada server UP.

### 4. Tab Patrol

Visualisasi game dari aktivitas di kedua server:

- **Polisi AI** berpatroli memeriksa hash file. **Satpam** menjaga pos dan memperbaiki file.
- **Pintu** di bawah tiap ruang adalah port yang terbuka di server: `22 SSH`, `80 HTTP`, `8080 APP`, `8091 REPAIR`.
- **Penyusup** masuk lewat pintu port. Bila server diisolasi, semua pintu tertutup dan penyusup terjebak, lalu dilumpuhkan saat perbaikan.

Dua cara memicu serangan:

1. **Demo** (simulasi lokal di browser, tidak mengubah server): klik **Demo**. Penyusup bergantian masuk ke Server A dan B lewat port acak, server yang dibobol diisolasi, diperbaiki, lalu kembali online; server lain tetap melayani dan menolak penyusup di pintunya. Klik **Hentikan demo** untuk berhenti.
2. **SERANG!** (serangan lab sungguhan): pilih **Server A** atau **Server B**, pilih jalur **SSH** atau **Web**, lalu tekan **SERANG!**. Executor menambahkan satu baris penanda ke `etc/kunci1.dat` di server target, agent mendeteksinya, dan approval pemulihan muncul di tab Playbook.

**SERANG!** ditolak bila server target atau server lainnya tidak UP (supaya situs tetap hidup), atau bila kunci server masih rusak dari serangan sebelumnya. Alasannya tampil di samping tombol.

### 5. Tab Playbook (di panel Detail)

Klik **Detail**, lalu tab **Playbook**. Di sini operator memutuskan:

| Tombol | Akibat |
|---|---|
| **Setujui** | Server dikeluarkan dari HAProxy, file rusak dikarantina, kunci dipulihkan dari master yang cocok manifes sha256, health check, lalu server masuk kembali ke rotasi |
| **Tolak** | Tidak ada tindakan. Server tetap melayani, penyusup pergi, tetapi kunci dibiarkan rusak |
| **Pulihkan kunci** | Muncul setelah Tolak atau approval kedaluwarsa. Membuat approval pemulihan baru (tetap harus disetujui) |

Approval kedaluwarsa setelah 15 menit. Selama kunci belum dipulihkan, **SERANG!** ke server itu akan gagal dengan alasan *kunci masih rusak*; pakai **Pulihkan kunci → Setujui** untuk membereskannya. Tahapan playbook dan waktu deteksi, isolasi, dan pulih tercatat di panel yang sama.

### 6. Tab Terminal

Shell SSH ke Server A atau Server B langsung dari dashboard (lab VM saja):

1. Buka tab **Terminal**, pilih **Server A** atau **Server B**.
2. Isi **username** akun server, lalu klik **Hubungkan**.
3. Ketik **password server** saat prompt `...'s password:` muncul di terminal.
4. Ketik `exit` atau klik **Putuskan** bila selesai.

Login tetap memakai akun server itu sendiri; kunci SSH tidak dipakai dan password tidak disimpan. Hanya operator yang bisa membuka terminal, maksimal 2 sesi per operator, dan sesi yang menganggur 15 menit ditutup otomatis. Tampilan terminal memakai xterm.js dari `cdn.jsdelivr.net`, jadi browser perlu akses internet.

### 7. Skenario demo lengkap

1. Buka dashboard, masuk sebagai operator, lalu buka `http://192.168.56.10:8080/` di tab lain dan muat ulang beberapa kali: judul blog berganti antara **SERVER A** dan **SERVER B**.
2. Di tab **Patrol**, pilih **Server A** dan **SSH**, lalu tekan **SERANG!**. Penyusup masuk lewat pintu 22 dan mengubah file kunci.
3. Buka **Detail → Playbook**, tekan **Setujui** pada approval *Pulihkan kunci dari master*.
4. Amati: pintu Server A tertutup, kabel HAProxy putus (Overview merah untuk Server A), blog tetap tampil lewat Server B, penyusup dilumpuhkan, file diverifikasi, dan Server A kembali online.
5. Ulangi dengan **Server B** dan **Web**, lalu coba **Tolak** dan **Pulihkan kunci** untuk melihat alur penolakan.

### 8. Pemecahan masalah

| Gejala | Penyebab | Solusi |
|---|---|---|
| Dashboard menampilkan "Belum masuk" dan data kosong | Belum login operator | Klik **Masuk operator** |
| **SERANG!** abu-abu | Server sedang insiden atau tidak UP | Tunggu insiden selesai atau cek status di Overview |
| **SERANG!** jalan tetapi tidak terjadi apa-apa | Kunci masih rusak (`key_not_pristine`) | **Detail → Playbook → Pulihkan kunci → Setujui** |
| Approval berstatus EXPIRED | Tidak disetujui dalam 15 menit | **Pulihkan kunci**, lalu Setujui |
| Terminal: "xterm.js tidak bisa dimuat" | Browser tanpa akses internet | Sambungkan laptop ke internet |
| Terminal langsung tertutup | SSH dari Collector diblok ufw | Jalankan `sh lab/vm/deploy-terminal.sh` atau cek aturan ufw di bawah |

Mengecek firewall di sebuah VM:

```bash
sudo ufw status numbered
```

Membandingkan dengan port yang benar-benar terbuka:

```bash
ss -ltn
```

## Hasil uji

- **Uji lab dengan persetujuan operator, 3 November 2026:** enam insiden di empat VM (Server A dan B, jalur SSH dan Web), semuanya disetujui operator, diisolasi, dan pulih. 506 permintaan ke blog selama uji semuanya HTTP 200. Deteksi 0,4–2,8 detik, isolasi 0,05–0,34 detik setelah disetujui, pemulihan 0,5–2,0 detik di luar jeda demo. Rantai bukti utuh.
- **Uji keamanan VM:** TLS (CA tak dikenal, hostname salah, dan sertifikat kedaluwarsa ditolak), token, viewer tidak bisa menyetujui, Collector tidak bisa menjangkau HAProxy maupun remediator, dan login gagal tertutup saat Approval Authority mati.
- **Uji browser:** login, Serang, Setujui, Tolak, dan logout lewat Safari dengan HTTPS tepercaya.
- **Uji otomatis:** 96 test, 95 lulus dan 1 dilewati di macOS (butuh alamat `127.0.0.2`, yang hanya ada di Linux).
- **Belum diuji:** jalur Docker dan gateway OT Modbus di deployment.

Rincian ada di [Hasil Uji](docs/HASIL_UJI.md).

## Materi submission

Sesuai bagian G rulebook. Batas akhir 15 November 2026 pukul 23:59 WIB.

| Kelengkapan | Ketentuan rulebook | Isi |
|---|---|---|
| Link karya | Publik, bisa dicoba juri | https://github.com/BlueSecc/DEFNETT |
| Thumbnail | 1200×630 px, JPG/PNG/WebP, maks. 500 KB | [docs/thumbnail.jpg](docs/thumbnail.jpg) (1200×630, 117 KB) |
| Screenshot | Maks. 5 gambar | `01-overview`, `04-serangan-ssh-masuk`, `04-serangan-patrol`, `06-pulih`, `11-playbook-metrik` di [lab/screenshots](lab/screenshots) |
| Video | Maks. 10 menit, di YouTube | [isi tautan YouTube] |
| Slide | Fitur, arsitektur, teknologi | https://www.canva.com/d/iTrcMg9nvcdA7o1 |

Kategori: **Penangkalan**. Tim maksimal 3 orang.

## Peta kriteria penilaian

| Kriteria (bobot) | Bagian di repo |
|---|---|
| Relevansi dan manfaat (25%) | [Relevansi](#relevansi-untuk-pengamanan-sistem-satuan) |
| Inovasi teknis (25%) | [Dokumentasi Teknis](docs/DOKUMENTASI_TEKNIS.md): persetujuan operator, executor terpisah, rantai bukti |
| Fungsionalitas purwarupa (25%) | [Cara mencoba](#cara-mencoba), [Hasil Uji](docs/HASIL_UJI.md) |
| Kelayakan implementasi (15%) | [Rencana pengembangan](#rencana-pengembangan), [Batasan](docs/DOKUMENTASI_TEKNIS.md#batasan) |
| Kualitas dokumentasi (10%) | README ini, Dokumentasi Teknis, video demo |

## Arsitektur

| VM | Alamat | Peran |
|---|---|---|
| Gateway | `192.168.56.10` | HAProxy, port 8080 |
| Server A | `192.168.56.11` | App, agent FIM, remediator |
| Server B | `192.168.56.12` | App, agent FIM, remediator |
| Collector | `192.168.56.20` | Dashboard HTTPS :8443, Collector, Approval Authority, dan Executor dengan UID terpisah; deployment belum runtime-verified |

## Tampilan

Screenshot diambil 2 November 2026, sebelum panel Persetujuan ditambahkan.

Overview:

![Overview](lab/screenshots/01-overview.png)

Patrol. Jumlah pintu tiap server mengikuti port yang benar-benar terbuka (`22 SSH`, `80 HTTP`, `8080 APP`, `8091 REPAIR`):

![Patrol](lab/screenshots/02-patrol.png)

Tab File, menampilkan file system tiap server per folder:

![File system](lab/screenshots/03-file-system.png)

Tombol **Serang!** punya pilihan jalur **SSH** atau **Web**. Dengan jalur SSH, intruder masuk lewat pintu 22:

![Intruder masuk lewat SSH](lab/screenshots/04-serangan-ssh-masuk.png)

Setelah file kunci diubah, Server A keluar dari HAProxy dan trafik pindah ke Server B:

![Serangan di Patrol](lab/screenshots/04-serangan-patrol.png)

![Serangan di Overview](lab/screenshots/05-serangan-overview.png)

Setelah file dipulihkan dan health check lolos, Server A kembali ke rotasi:

![Pulih](lab/screenshots/06-pulih.png)

Dengan jalur Web, intruder masuk lewat pintu 80, dan Server B yang keluar dari rotasi:

![Intruder masuk lewat Web](lab/screenshots/09-serangan-web-masuk.png)

![Serangan web di Patrol](lab/screenshots/10-serangan-web-patrol.png)

## Situs yang dilayani

Kedua server melayani blog WordPress di port 80, dan HAProxy membagi trafik ke keduanya. Setiap halaman memuat lencana serta judul **SERVER A** atau **SERVER B**, sehingga server yang menjawab langsung terlihat.

![Blog di Server A](lab/screenshots/07-blog-server-a.png)

![Blog di Server B](lab/screenshots/08-blog-server-b.png)

Konfigurasi gateway ada di [lab/vm/gateway/haproxy.cfg](lab/vm/gateway/haproxy.cfg). WordPress 5.0 memerlukan satu perbaikan agar halaman daftar tulisan tampil di PHP 8, yaitu [lab/vm/fix-wp-php8-home.sh](lab/vm/fix-wp-php8-home.sh).

## Catatan keamanan

Lab ini sengaja dibuat rentan dan **hanya untuk jaringan lab yang terisolasi**.

- **Perangkat lunak lama:** blog memakai WordPress 5.0, versi lama yang memiliki kerentanan publik yang sudah diketahui. Versi itu dipilih karena tujuan lab ini adalah mengamati deteksi dan respons terhadap serangan, bukan menjaga situs tetap aman.
- **Data contoh:** `kunci1.dat` dan `kunci2.dat`, akun blog, dan seluruh isi `/data` adalah data buatan, bukan data nyata.
- **Jangan dipasang di jaringan publik:** jangan dibuka ke internet dan jangan diisi data pribadi. Jaringan antar VM memakai host-only, dan firewall tiap VM hanya mengizinkan lalu lintas yang diperlukan.
- **Skor risiko berbasis aturan:** penilaian di dashboard bukan model AI terlatih, dan tombol **Serang!** hanya membuat permintaan persetujuan untuk mengubah file kunci demo di server lab.

## Komponen dan atribusi

Dibuat tim: agent FIM (`lab/agent.py`), collector (`lab/collector.py`), lapisan pengaman tahap 1 (`lab/db.py`, `lab/policy_gate.py`, `lab/approvals.py`, `lab/operator_auth.py`, `lab/provision_operators.py`, `lab/provision_master.py`), executor (`lab/executor.py`), remediator (`lab/remediator.py`), aplikasi demo (`lab/app.py`), dan dashboard (`lab/dashboard`).

Seluruh kode di atas dibuat tim selama periode program, mulai Oktober 2026. Karya pre-existing yang dipakai hanya perangkat pihak ketiga di bawah ini, sesuai lisensi masing-masing:

| Pihak ketiga | Lisensi | Dipakai untuk |
|---|---|---|
| HAProxy | GPL-2.0 | Load balancer dan isolasi server |
| WordPress 5.0 | GPL-2.0 | Situs contoh di Server A dan B |
| Python, SQLite | PSF, domain publik | Runtime dan penyimpanan bukti |
| Docker, VirtualBox | Apache-2.0, GPL-2.0 | Menjalankan lab |
| Playwright | Apache-2.0 | Hanya untuk mengambil screenshot (`lab/screenshot-dashboard.js`), bukan bagian sistem yang berjalan |

Dataset untuk eksperimen luring skor risiko tidak disertakan di repo karena ukurannya, dan tidak dipakai saat sistem berjalan:

- Sen, Ö., Bader, L., Emara, M., dkk. (2026). *Data4Cyber: Labeled Cyber-Physical Dataset for Distribution-Grid Management Systems Under Representative OT Attacks*. Zenodo. https://doi.org/10.5281/zenodo.19965384 (CC BY 4.0).
- ICS Telemetry Dataset, https://github.com/davidivory/ICS-telemetry-dataset (CC0 1.0).

Repo ini tidak memuat data pribadi pihak ketiga.

## Rencana pengembangan

Jika lolos ke babak selanjutnya, kami akan:

- **Membuat model ML untuk skor risiko**, agar penilaian lebih akurat daripada skor berbasis aturan yang dipakai sekarang.
- **Membatasi Polisi AI (agent FIM) ke izin read-only**, sehingga agent hanya bisa membaca dan memantau file.
- **Membatasi Satpam (remediator) ke izin execute dan write saja**, sehingga Satpam hanya menjalankan perbaikan dan menulis file pemulihan.

## Dokumentasi

Cara menjalankan dan detail teknis ada di [lab/README.md](lab/README.md). Konfigurasi VM ada di [lab/vm](lab/vm).

Proyek ini hanya untuk lab terisolasi. Berkas `kunci1.dat` dan `kunci2.dat` adalah data contoh, dan skor risiko berbasis aturan, bukan model AI terlatih.
