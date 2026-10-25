# DEFNETT Docker Lab

Lab ini mengimplementasikan dua server aplikasi dalam container, HAProxy, dua agent pemantau file, collector, worker remediation terpisah, karantina artefak, dan dashboard. Collector menyimpan event serta tahapan playbook di SQLite dengan hash chain.

Agent hanya memantau isi `/data` pada masing-masing server, bukan seluruh filesystem. Hash dipindai setiap tiga detik. Skor risiko dan verdict merupakan aturan deterministik, bukan classifier atau LLM terlatih. Mode normal memakai `DRY_RUN`; overlay canary mengaktifkan satu playbook terbatas.

## Jalankan

Dari root proyek:

```sh
docker compose -f lab/compose.yaml config
docker compose -f lab/compose.yaml up -d --build
docker compose -f lab/compose.yaml ps
```

Docker Engine harus sudah aktif. Aplikasi tersedia hanya pada komputer lokal:

- Layanan di belakang HAProxy: `http://127.0.0.1:8080/`
- Dashboard patroli dan analisis lab: `http://127.0.0.1:8090/`
- Health collector: `http://127.0.0.1:8090/healthz`
- Event dan keputusan: `http://127.0.0.1:8090/v1/events`
- Ringkasan dashboard (status backend, heartbeat agent, keputusan): `http://127.0.0.1:8090/v1/dashboard`
- Ringkasan jumlah event: `http://127.0.0.1:8090/v1/summary`

Perintah dasar di atas menjalankan collector dalam `DRY_RUN`. Untuk menyalakan playbook otomatis khusus canary lab:

```sh
docker compose -f lab/compose.yaml -f lab/compose.canary.yaml up -d --build
```

Dashboard menampilkan kesiapan worker dan tahapan setiap pemulihan. Overlay demo menahan tahap perbaikan Server A selama 75 detik (`DEMO_REPAIR_DELAY_SECONDS`). Hitung mundurnya tampil di dashboard saat Server A terisolasi; setelah jeda, artefak canary dikarantina, health check dijalankan, lalu Server A aktif kembali jika sehat. Durasi 75 detik hanya untuk memperlihatkan alur demo dan muat dalam slot containment 2:00-3:15; penanganan insiden sebenarnya bergantung pada tingkat kesulitan.

Dashboard memiliki tab **Patrol**. Peta Canvas 2D menyusun file dari snapshot hash agent ke ruang per server, menampilkan agent patroli, aktor berdasarkan IP, event akses, severity, dan detail hash. Snapshot hanya mengirim path relatif dan SHA-256, bukan isi file. Agent memakai `WATCH_ROOT` sebagai konfigurasi folder yang dipantau.

- Snapshot patrol: `GET /api/patrol/state`
- Event live: `GET /api/patrol/stream` (SSE)
- Ingest event akses: `POST /api/patrol/events`
- Snapshot hash agent: `POST /v1/patrol/snapshot`

### Animasi insiden (tab Patrol)

Tab Patrol sekarang memainkan cerita insiden dengan karakter game:

1. **Maling masuk.** Event serangan (request ke app atau event FIM non-safe dari agent) memunculkan maling yang berjalan lewat jalan, masuk pintu server, lalu beraksi di file: mengintip (read), membawa kabur (download), merusak (modify), menghapus (delete), atau menanam malware (file baru). Polisi (agent AI) mengejar dan memberi peringatan.
2. **Isolasi.** Saat playbook masuk `ISOLATING`, gerbang server turun dan kabel ke HAProxy putus (percikan + label PUTUS). Maling terjebak di dalam. Status HAProxy `MAINT` tanpa playbook juga ditampilkan sebagai server terisolasi.
3. **Maintenance (`REPAIRING`).** Satpam menempelkan badge dan masuk, maling mencoba kabur, polisi menembak sampai maling KO. Satpam lalu memperbaiki file dengan bar progres yang mengikuti hitung mundur demo 75 detik.
4. **Verifikasi dan rejoin.** Satpam memeriksa file satu per satu (tanda centang), kabel tersambung kembali, gerbang dibuka, server kembali ONLINE, dan maling diamankan.

Urutan visual mengikuti tahap asli dari `/v1/dashboard`; tiap tahap punya durasi tayang minimum agar tahap singkat tetap terlihat. Membuka dashboard di tengah insiden langsung menampilkan keadaan terakhir. Tombol **Serang!** menjalankan simulasi lengkap di browser (tanpa menyentuh file atau database), dan kecepatan bisa diatur 0.5× sampai 4×.

Pilih **Patrol → Mulai demo** untuk menghasilkan dua aktor sintetis dengan aksi berbeda, atau **Serang!** untuk simulasi insiden lengkap. Simulator hanya berjalan pada browser dan tidak menulis file atau mengirim event palsu ke database. Event live berasal dari request ke app (`/` atau `/files/<path>`) serta event integritas agent. App hanya menyajikan file relatif yang terdaftar di `PATROL_PUBLIC_FILES` (default `index.txt`); file lain, file sensitif, dan metode tulis ditolak serta dicatat sebagai event. `WATCH_ROOT` pada tiap agent menentukan folder yang dipatroli. Analisis severity tetap berbasis aturan, bukan model AI terlatih.

## Simulasi containment yang aman

Untuk menguji siklus isolasi dan pemulihan otomatis, jalankan overlay canary lebih dahulu, lalu gunakan marker teks khusus. Skrip simulasi tidak membangun ulang atau me-restart kedua server:

```sh
sh lab/test-containment.sh
```

Playbook memilih host dari event. Setiap server memiliki worker dan volume karantina sendiri. Untuk event Server A, hanya worker A yang dapat menulis volume A; Server B hanya bertugas menjaga layanan tetap tersedia. Aturan yang sama berlaku sebaliknya untuk event Server B. Skrip simulasi menulis string `DEFNETT-LAB-MALWARE-CANARY` ke `/data/DEFNETT-LAB-CANARY.txt` pada Server A. Playbook kemudian:

1. Memastikan backend survivor sehat.
2. Mengeluarkan hanya host target dari rotasi HAProxy.
3. Untuk demo Server A, dashboard menampilkan jeda 75 detik saat A tetap terisolasi. Setelah jeda, worker host target mengarantina file canary terverifikasi ke volume terpisah.
4. HAProxy menjalankan health check dan mengaktifkan kembali hanya host target jika sehat.

Script default menguji Server A. Untuk menguji Server B sebagai host target:

```sh
sh lab/test-containment.sh server-b
```

Script menunggu status `REPAIRED`, memeriksa file sudah hilang dari `/data`, memastikan request kembali mencapai Server A dan B, dan memastikan ID container kedua server tidak berubah. Jika worker, karantina, atau health check gagal, sistem menjaga host target tetap diisolasi dan dashboard mencatat penyebabnya.

Ini hanya membersihkan satu artefak canary lab pada path tetap. Worker memeriksa tipe file, ukuran, dan isi marker sebelum memindahkannya serta memverifikasi SHA-256 salinan. Ini bukan antivirus, bukan perbaikan OS, dan tidak mendeteksi atau menghapus malware sungguhan. Tidak ada file lain yang disentuh.

Jika perlu mengaktifkan kembali backend secara manual setelah pemeriksaan operator:

```sh
curl --fail --request POST http://127.0.0.1:8090/v1/lab/recover/server-a
# Ganti server-a dengan server-b untuk memulihkan Server B.
```

API runtime HAProxy hanya tersedia di network kontrol internal. Worker remediation hanya berbagi network kontrol internal dengan collector dan memiliki akses tulis ke volume Server A serta volume karantina. Port worker tidak dipublikasikan ke host. Overlay canary mengaktifkan playbook khusus untuk file dan marker tetap di atas.

## Trafik sebelum, selama, setelah containment

Collector menjalankan probe kecil: satu `GET /healthz` per detik lewat HAProxy (`http://haproxy:8080/healthz`), lalu mencatat sukses/gagal dan backend yang menjawab (header `X-DEFNETT-Host`). Probe memakai `/healthz`, jadi tidak membuat event patrol atau aktor di peta. Hitungan dibagi tiga fase mengikuti playbook:

- **Sebelum:** sejak collector hidup (atau sejak pemulihan sebelumnya) sampai `ISOLATED`.
- **Selama:** dari `ISOLATED` sampai `REJOINING` selesai; host target sudah keluar dari rotasi.
- **Setelah:** mulai `REPAIRED`.

Hasil ada di `/v1/dashboard` pada kunci `traffic` dan di dashboard bagian "Request lewat HAProxy". Hitungan disimpan di memori collector, jadi reset saat collector restart. Nonaktifkan dengan `TRAFFIC_PROBE_ENABLED=false`; atur `TRAFFIC_PROBE_URL` dan `TRAFFIC_PROBE_INTERVAL` bila perlu.

## Demo perubahan file

```sh
sh lab/demo.sh
```

Agent akan mendeteksi file baru pada Server A dan mengirim event ke collector. Respons contoh tetap `DRY_RUN`; endpoint layanan tetap berjalan melalui HAProxy.

## Lihat log dan matikan lab

```sh
docker compose -f lab/compose.yaml logs -f
docker compose -f lab/compose.yaml down
```

`down` mempertahankan named volumes. Untuk menghapus seluruh data baseline dan bukti lab:

```sh
docker compose -f lab/compose.yaml down -v
```

Perintah terakhir menghapus data volume lab secara permanen.

## Dashboard dan batas purwarupa

Dashboard menampilkan heartbeat agent, status tiap worker, server yang menjadi target perbaikan, server survivor yang tetap berjalan, daftar event dan hash, serta tahapan `deteksi -> isolasi -> karantina -> verifikasi -> rejoin`. Worker hanya dapat menulis volume host pasangannya. Peta node adalah visualisasi alur layanan, bukan representasi neuron atau model AI sungguhan. Analisis yang berjalan adalah FIM dan aturan canary deterministik.

- Pemantauan polling membaca file di `/data`; belum menggunakan Wazuh agent atau memantau file sistem host.
- SQLite dan hash chain membantu demonstrasi audit, tetapi bukan penyimpanan bukti tahan manipulasi produksi.
- Collector menggabungkan ingestion, normalisasi minimal, penyimpanan, trajectory, scoring, dan policy dalam satu proses agar irisan end-to-end mudah dijalankan.
- Belum ada koneksi Cloud/Local LLM, classifier terkalibrasi, atau isolasi jaringan container penuh. Isolasi lab mengeluarkan backend dari rotasi HAProxy.
- Pemulihan otomatis terbatas pada satu file canary pada host yang terdeteksi. Kasus selain itu gagal tertutup dan perlu pemeriksaan operator.
- Network Compose untuk layanan, telemetri, kontrol HAProxy, dan remediation dibuat terpisah/internal. HAProxy dan collector saja yang mempublikasikan port ke `127.0.0.1`.
