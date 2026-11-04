# Naskah Video DEFNETT: Atnan, Adiva, Qilah

Durasi sekitar 8 menit 30 detik (batas rulebook 10 menit, unggah ke YouTube). Naskah ini mengikuti demo sungguhan di lab, bukan urutan slide. Bacakan teks dalam tanda kutip, sedangkan teks dalam kurung siku adalah petunjuk layar.

Video harus menjelaskan tiga hal yang diminta rulebook: apa karyanya, apa manfaatnya, dan bagaimana cara kerjanya.

| Orang | Tugas |
|---|---|
| **Atnan** | Membuka video dan menjelaskan masalah serta manfaat |
| **Adiva** | Mengoperasikan demo di dashboard |
| **Qilah** | Menjelaskan hal teknis dan batasan, serta menutup video |

## Persiapan sebelum rekam

- Pastikan keempat VM sudah menjalankan versi dengan persetujuan operator (ikuti `lab/vm/SECURITY_CUTOVER_RUNBOOK.md`).
- Buka `https://192.168.56.20:8443/` dan tekan `Cmd+Shift+R`. Browser harus sudah mempercayai CA lab, supaya tidak muncul peringatan sertifikat di video.
- **Masuk operator sebelum mulai merekam**, supaya kata sandi tidak terekam.
- Pastikan Mode **AKTIF**, Server A dan B **UP**, dan LB **2/2**.
- Buka tiga tab: dashboard, blog `http://192.168.56.10:8080/`, dan terminal.
- Tutup jendela yang memuat password atau data pribadi.
- Latihan sekali. Catat berapa lama satu serangan sampai server pulih, termasuk satu klik **Setujui** untuk pemulihan. Pada uji 3 November, persetujuan muncul sekitar 6 detik setelah SERANG!.

## 1. Pembuka (0:00–0:50)

[Kamera atau layar menampilkan dashboard Overview]

**Atnan:** "Halo, kami tim [nama tim] dari [instansi]. Saya Atnan, bersama Adiva dan Qilah. Karya kami DEFNETT, untuk kategori Penangkalan di Kartika Cyber Hackathon 2026."

**Atnan:** "Bayangkan server satuan diretas, tapi layanan harus tetap berjalan. Kalau server dimatikan, pengguna ikut terputus. Kalau perbaikan dikerjakan manual, penyerang punya waktu. DEFNETT mendeteksi perubahan, menyiapkan langkah respons, lalu menjalankannya dengan satu persetujuan operator, sementara layanan tetap hidup."

## 2. Kondisi normal (0:50–2:00)

[Adiva membuka tab Overview]

**Adiva:** "Ini Overview. Kedua server UP, dan load balancer menunjukkan 2 dari 2. Semua angka ini dibaca dari HAProxy asli."

[Adiva membuka tab blog dan refresh beberapa kali]

**Adiva:** "Ini blog yang dilayani lab kami. Lihat lencana di kiri atas: kalau saya refresh, berganti antara Server A dan Server B. Artinya trafik memang dibagi dua."

[Adiva membuka tab Patrol]

**Qilah:** "Di tab Patrol, tiap server digambar sebagai ruangan. Kotak-kotak ini file di folder `/data`, yang hash-nya diperiksa agent setiap tiga detik. Pintu di bawah adalah port yang benar-benar terbuka, yaitu 22 SSH, 80 HTTP, 8080 aplikasi, dan 8091 worker."

[Adiva membuka sidebar tab File, lalu membuka folder `/etc`]

**Qilah:** "Di tab File, kita bisa menelusuri file system server dari dashboard. Isinya hanya daftar nama dan ukuran file, bukan isi file."

## 3. Serangan lewat SSH (2:00–4:40)

[Adiva memilih Server A, jalur SSH, lalu menekan SERANG!]

**Adiva:** "Sekarang kita serang Server A lewat jalur SSH. Hanya operator yang sudah login yang bisa menekan tombol ini, dan permintaannya tercatat sebagai persetujuan."

[Adiva membuka tab Playbook di sidebar. Tunjuk baris "Simulasi serangan lab" di panel Persetujuan, yang sudah berstatus disetujui]

**Qilah:** "Jalur masuk intruder ini simulasi, jadi tidak ada eksploit sungguhan. Tapi sistem benar-benar menambah satu baris penanda ke file kunci di Server A."

[Intruder masuk lewat pintu 22]

**Adiva:** "Intruder masuk lewat pintu 22, sesuai jalur yang kita pilih."

[Tunggu baris baru "Pulihkan kunci dari master" muncul di panel Persetujuan]

**Qilah:** "Agent melihat hash file kunci berubah. Collector mencatatnya ke rantai bukti, menilai risikonya, lalu menyiapkan playbook pemulihan. Tapi sistem tidak bertindak sendiri. Playbook menunggu persetujuan operator."

**Atnan:** "Ini sengaja. Di lingkungan satuan, keputusan mengeluarkan server dari layanan tetap di tangan manusia. Sistem menyiapkan semuanya, operator cukup satu klik."

[Adiva menekan Setujui. Tunggu status berubah]

**Adiva:** "Setelah disetujui, Server A berubah menjadi DOWN, dan load balancer tinggal 1 dari 2."

**Qilah:** "Yang menjalankan ini adalah executor, proses terpisah yang hanya bisa bekerja dari persetujuan yang sah dan hanya sekali pakai. Executor memastikan Server B sehat dulu, baru memerintahkan HAProxy mengeluarkan Server A."

[Adiva pindah ke tab blog dan refresh beberapa kali]

**Adiva:** "Blognya tetap terbuka. Sekarang lencananya selalu Server B, jadi pengguna tidak merasakan gangguan."

[Adiva kembali ke tab Playbook]

**Qilah:** "File yang diubah disimpan ke karantina sebagai bukti, lalu kuncinya dipulihkan dari salinan master. Salinan master itu dicek dulu dengan manifes sha256. Kalau master ikut diubah, pemulihan ditolak dan server tetap terisolasi."

[Tunggu sampai Server A UP]

**Adiva:** "Server A sudah kembali UP, dan load balancer 2 dari 2."

[Tunjuk tiga angka waktu dan baris Masuk di tab Playbook]

**Qilah:** "Setiap insiden punya catatan waktu: kapan terdeteksi, kapan terisolasi, dan kapan pulih. Baris ini juga mencatat dari IP dan port mana penyerang masuk."

[Tunjuk lencana Bukti utuh]

**Qilah:** "Lencana ini memeriksa rantai bukti. Kalau catatan event diubah, hasil pemeriksaannya berubah menjadi rusak. Siapa yang menyetujui juga tercatat di berita acara."

## 4. Serangan lewat Web (4:40–5:40)

[Tunggu tombol SERANG! aktif. Pilih Server B, jalur Web, tekan SERANG!, lalu Setujui pemulihan seperti tadi]

**Adiva:** "Sekarang kita coba jalur Web di Server B. Kali ini intruder masuk lewat pintu 80."

[Tunggu status DOWN, lalu refresh blog sekali]

**Adiva:** "Server B yang keluar dari rotasi, dan Server A yang menjaga layanan."

**Atnan:** "Jadi server mana pun yang diserang, layanan tetap hidup selama ada satu server lain yang sehat."

## 5. Login SSH sungguhan (5:40–6:30)

[Adiva membuka terminal dan memperlihatkan Patrol berdampingan. Jalankan perintah ini:]

```bash
ssh -o PubkeyAuthentication=no malas@192.168.56.11
```

**Qilah:** "Selain tombol tadi, agent juga membaca log login asli. Ini login SSH sungguhan ke Server A."

[Adiva salah memasukkan password sekali. Jangan tampilkan password yang benar]

**Adiva:** "Password salah: intruder berhenti di pintu 22 dengan tanda DENIED."

[Adiva memasukkan password yang benar]

**Adiva:** "Password benar: intruder masuk lewat pintu 22, lengkap dengan alamat IP-nya."

**Qilah:** "Login memakai SSH key kami anggap admin, jadi tidak muncul sebagai intruder. Ini hanya penanda di dashboard, dan tidak memicu isolasi."

## 6. Manfaat dan kejujuran batasan (6:30–7:40)

[Layar kembali ke Overview]

**Atnan:** "Untuk sistem satuan, ada empat manfaat. Layanan tetap berjalan saat satu server diamankan. Operator tetap memegang keputusan, cukup satu klik, dan setiap tindakannya tercatat. Bukti bisa diverifikasi. Dan DEFNETT berjalan tanpa cloud atau internet, jadi cocok untuk jaringan tertutup."

**Atnan:** "Kami mengujinya dengan enam insiden sungguhan di empat VM. Keenamnya disetujui, diisolasi, dan pulih, dan 506 permintaan ke blog selama uji semuanya berhasil. Setelah disetujui, server keluar dari layanan dalam kurang dari setengah detik, dan pulih dalam sekitar dua detik di luar jeda demo."

**Qilah:** "Kami juga jujur soal batasannya. Skor risiko masih berbasis aturan, bukan model AI. Karakter Polisi AI di peta hanya nama visual untuk agent. Jalur masuk tombol Serang adalah simulasi, dan blog WordPress 5.0 sengaja versi lama, jadi lab ini hanya untuk jaringan terisolasi."

## 7. Rencana dan penutup (7:40–8:30)

**Qilah:** "Jika lolos ke babak selanjutnya, kami akan membuat model ML agar skor risiko lebih akurat. Polisi AI akan dibatasi ke izin read-only, dan Satpam hanya punya izin execute dan write."

**Atnan:** "DEFNETT: server diserang, layanan tetap hidup, dan operator tetap memegang kendali. Kode dan dokumentasi ada di github.com/BlueSecc/DEFNETT. Terima kasih."

## Catatan rekaman

- **Jangan tekan Tolak saat rekaman,** kecuali sengaja memperagakan penolakan. Setelah Tolak, kunci server tetap berubah dan Serang berikutnya ditolak; pulihkan dengan `lab/vm/restore-kunci.sh`.
- **Percayai CA lab sebelum merekam** agar browser tidak menampilkan peringatan, lalu cabut lagi setelah selesai.

- **Bagian tunggu:** boleh dipercepat saat editing, tapi tulis keterangan "dipercepat" di layar.
- **Jeda demo:** kalau ditanya kenapa tertahan 15 detik, jawab bahwa jeda itu sengaja dipasang agar isolasi terlihat.
- **Jangan tunjukkan** password, alamat email, atau data pribadi, termasuk saat masuk operator.
- **Deskripsi YouTube:** isi link repo dan satu paragraf cara menjalankan lab.
- **Bagian 5 perlu latihan:** login SSH sungguhan sudah tertangkap datanya, tapi tampilannya di peta harus dicek dulu saat latihan. Kalau intruder tidak muncul, hapus bagian ini.
- **Babak final:** presentasi langsung juga 10 menit, sudah termasuk tanya jawab. Siapkan versi demo yang lebih pendek, misalnya hanya serangan SSH.
