# Naskah Video DEFNETT

Target durasi: sekitar 8 menit (batas rulebook 10 menit, diunggah ke YouTube). Teks di dalam tanda kutip dibaca langsung. Teks dalam kurung siku adalah petunjuk layar atau hal yang harus kamu isi sendiri.

## Persiapan sebelum rekam

- Nyalakan keempat VM (Gateway, Server A, Server B, Collector) yang sudah menjalankan versi dengan persetujuan operator (lihat `lab/vm/SECURITY_CUTOVER_RUNBOOK.md`), lalu buka `https://192.168.56.20:8443/`. Browser harus sudah mempercayai CA lab.
- Masuk operator sebelum merekam, supaya kata sandi tidak terekam.
- Pastikan kedua server berstatus UP dan LB menunjukkan 2/2.
- Buka slide di satu jendela dan dashboard di jendela lain.
- Latih demo sekali agar tahu kapan server kembali ke rotasi. Satu serangan butuh satu klik **Setujui** untuk pemulihan (persetujuan muncul sekitar 6 detik setelah Serang), dan tahap perbaikan ditahan 15 detik agar isolasi terlihat.
- Rekam layar dengan suara jelas. Bagian tunggu boleh dipercepat, asal diberi keterangan "dipercepat".

## 1. Pembuka (0:00–0:40) · slide Cover

[Slide cover]

"Halo, kami [nama tim] dari [instansi/komunitas]. Karya kami DEFNETT, untuk kategori Penangkalan di Kartika Cyber Hackathon 2026."

"DEFNETT adalah lab pertahanan siber dua server di balik load balancer. Saat file penting diubah, DEFNETT menyiapkan playbook respons. Setelah operator menyetujui, server target dikeluarkan dari layanan, dipulihkan, lalu dimasukkan kembali. Selama itu, situs tetap melayani lewat server lainnya."

## 2. Masalah (0:40–1:30) · slide Masalah

[Slide Masalah]

"Masalahnya ada tiga. Pertama, perubahan pada file penting sering baru ketahuan setelah dicek manual. Kedua, setelah tahu pun, operator harus mengerjakan isolasi dan pemulihan secara manual, langkah demi langkah. Ketiga, kalau satu-satunya server dimatikan, pengguna kehilangan layanan."

[Tambahkan satu kalimat konteks satuan dari pengetahuanmu sendiri, misalnya layanan internal yang tidak boleh berhenti.]

## 3. Solusi dan alur (1:30–2:40) · slide Solusi, lalu Alur playbook

[Slide Solusi]

"DEFNETT menyelesaikannya dengan satu siklus: deteksi, setujui, isolasi, pulihkan, kembali. Agent di tiap server menghitung hash file di folder /data setiap tiga detik. Keputusan tetap di tangan operator, sistem mengerjakan sisanya."

[Slide Alur playbook]

"Ini alur lengkapnya. FIM melihat hash file kunci berubah. Collector menilai risiko dengan aturan, mencatat event ke SQLite dengan hash chain, dan menyiapkan playbook yang menunggu persetujuan. Setelah operator menekan Setujui, executor, yaitu proses terpisah yang hanya bisa bekerja dari persetujuan sekali pakai, memastikan server lain sehat, lalu HAProxy menonaktifkan server target. Worker di server itu menyimpan file rusak sebagai bukti di karantina, memulihkan kedua file kunci dari salinan master yang dicek dengan manifes sha256, dan setelah health check lolos server diaktifkan lagi."

## 4. Arsitektur (2:40–3:20) · slide Arsitektur

[Slide Arsitektur]

"Labnya berjalan di empat VM VirtualBox. Gateway menjalankan HAProxy di port 8080. Server A dan Server B masing-masing punya aplikasi, agent FIM, dan remediator. Collector menjalankan dashboard HTTPS di port 8443, ditambah Approval Authority dan Executor sebagai proses dengan akun terpisah. Jaringannya host-only, dan firewall tiap VM hanya mengizinkan lalu lintas yang diperlukan. Remediator tiap server hanya menulis ke volume servernya sendiri."

## 5. Demo langsung (3:20–6:20) · dashboard

[Pindah ke dashboard, tab Overview]

"Kita mulai dari kondisi normal. Server A dan Server B sama-sama UP, dan HAProxy menunjukkan 2 dari 2."

[Buka blog lewat `http://192.168.56.10:8080/` dan muat ulang beberapa kali]

"Blog WordPress ini dilayani bergantian. Lihat lencana SERVER A dan SERVER B di tiap halaman, jadi kita tahu server mana yang menjawab."

[Pindah ke tab Patrol]

"Di tab Patrol, tiap server digambar sebagai ruangan berisi file. Jumlah pintu mengikuti port yang benar-benar terbuka: 22 SSH, 80 HTTP, 8080 aplikasi, dan 8091 worker."

[Pilih Server A, jalur SSH, tekan Serang!]

"Sekarang kita serang Server A lewat jalur SSH. Hanya operator yang sudah login yang bisa menekan tombol ini, dan permintaannya tercatat sebagai persetujuan, karena mengubah file di server."

[Buka tab Playbook; baris "Simulasi serangan lab" sudah berstatus disetujui]

"Tombol ini menjalankan insiden sungguhan di lab: satu baris penanda ditambahkan ke file kunci1.dat di server itu. Intruder masuk lewat pintu 22."

[Tunggu baris "Pulihkan kunci dari master" muncul]

"Agent mendeteksi perubahan hash, dan playbook pemulihan sudah siap. Sistem tidak bertindak sendiri, playbook menunggu persetujuan operator."

[Tekan Setujui, lalu tunggu Server A keluar dari rotasi]

"Server A DOWN dan masuk maintenance, HAProxy menunjukkan 1 dari 2, dan Server B menjaga layanan. Intruder terjebak di server yang diisolasi."

[Refresh blog beberapa kali]

"Blog tetap terbuka, dan sekarang selalu dijawab Server B."

[Buka tab Playbook atau Events]

"Di sini terlihat tahapan playbook dan event file berubah pada etc/kunci1.dat."

[Tunggu pemulihan, boleh dipercepat]

"File rusak dikarantina, kedua kunci dipulihkan dari master, health check dijalankan, dan Server A kembali ke rotasi. LB kembali 2 dari 2."

[Ulangi singkat dengan jalur Web, pilih Server B, lalu Setujui pemulihan]

"Kita coba jalur Web. Intruder lewat pintu 80, dan kali ini Server B yang keluar dari rotasi sementara Server A melayani."

## 6. Relevansi (6:20–7:00) · slide Relevansi

[Slide Relevansi]

"Untuk pengamanan sistem satuan, ada empat manfaat. Layanan tetap hidup selama ada server lain yang sehat. Operator tetap memegang keputusan dengan satu klik, dan setiap tindakannya tercatat. Bukti terjaga lewat karantina dan hash chain. Dan komponennya sederhana, yaitu Python, HAProxy, dan SQLite, sehingga bisa berjalan di VM biasa."

## 7. Teknologi, atribusi, dan batasan (7:00–7:40) · slide Teknologi, lalu Batasan

[Slide Teknologi]

"Agent, collector, remediator, dan dashboard adalah karya tim. HAProxy, WordPress 5.0, Python, SQLite, Docker, dan VirtualBox adalah perangkat pihak ketiga, dipakai sesuai lisensinya. Daftar lengkap, termasuk dataset untuk eksperimen skor risiko, ada di README."

[Slide Batasan]

"Kami jujur soal batasannya. Skor risiko berbasis aturan, bukan model AI terlatih. Tombol Serang! hanya mengubah file kunci demo. Lab ini hanya untuk jaringan terisolasi, dan WordPress 5.0 sengaja dipilih agar mudah diserang dan hasilnya bisa diamati."

## 8. Rencana dan penutup (7:40–8:20) · slide Rencana, lalu Penutup

[Slide Rencana]

"Jika lolos ke babak berikutnya, kami akan membuat model ML untuk skor risiko, membatasi agent FIM ke izin read-only, dan membatasi remediator ke izin execute dan write saja."

[Slide Penutup]

"DEFNETT: layanan tetap hidup saat diserang. Kode dan dokumentasi ada di github.com/BlueSecc/DEFNETT. Terima kasih."

## Catatan agar nilai dokumentasi aman

- **Jangan tekan Tolak saat rekaman,** kecuali sengaja memperagakan penolakan. Setelah Tolak, kunci server tetap berubah dan Serang berikutnya ditolak; pulihkan dengan `lab/vm/restore-kunci.sh`.
- **Percayai CA lab sebelum merekam** agar browser tidak menampilkan peringatan, lalu cabut lagi setelah selesai.

- Sebut selalu bahwa penilaian risiko berbasis aturan. Jangan menyebut "AI" tanpa penjelasan, termasuk saat membahas karakter Polisi AI.
- Tulis di deskripsi YouTube: link repo, daftar slide, dan satu paragraf cara menjalankan lab (rujuk `lab/README.md`).
- Pastikan video tidak memuat data pribadi, password, atau alamat yang bukan milik lab.
