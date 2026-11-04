# DEFNETT Lab

Lab ini mengimplementasikan dua server aplikasi dalam container, HAProxy, dua agent pemantau file, collector, worker remediation terpisah, karantina artefak, dan dashboard. Collector menyimpan event serta tahapan playbook di SQLite dengan hash chain.

Agent hanya memantau isi `/data` pada masing-masing server, bukan seluruh filesystem. Hash dipindai setiap tiga detik. Skor risiko dan verdict merupakan aturan deterministic, bukan classifier atau LLM terlatih. Temuan canary/kunci tidak dieksekusi sendiri; semua playbook menunggu persetujuan operator (tahap 1).

## Jalankan

Dari root proyek:

```sh
docker compose -f lab/compose.yaml config
sh lab/build.sh
docker compose -f lab/compose.yaml -f lab/compose.canary.yaml ps
```

Docker Engine harus sudah aktif. `docker compose config` hanya memvalidasi konfigurasi; `lab/build.sh` menyiapkan CA/token lalu menjalankan stack. Aplikasi tersedia hanya pada komputer lokal:

- Layanan di belakang HAProxy: `http://127.0.0.1:8080/`
- Dashboard patroli dan analisis lab: `https://127.0.0.1:8443/`
- Health collector: `https://127.0.0.1:8443/healthz`
- Event dan keputusan: `https://127.0.0.1:8443/v1/events`
- Ringkasan dashboard: `https://127.0.0.1:8443/v1/dashboard`
- Ringkasan jumlah event: `https://127.0.0.1:8443/v1/summary`
- Event group dan relasi: `https://127.0.0.1:8443/v1/trajectories` (sesi viewer/operator)

`sh lab/build.sh` membuat CA dan certificate lab di luar repository (`$HOME/.config/defnett-lab/tls`). Browser harus mempercayai `ca.crt`; jangan menonaktifkan certificate verification atau memakai CA lab untuk produksi. Internal service memakai HTTPS dengan CA verification serta bearer token berbeda; TLS ini bukan mTLS.

Trajectory backend mengelompokkan event hanya ketika host dan path sama serta ada hash continuity (strong) atau jarak waktunya maksimal 60 detik tanpa hash chain (medium). Relasi menyimpan alasan dan confidence; ini bukan kesimpulan kausal. Tab Trajectory di dashboard menampilkan event, waktu, alasan, dan confidence dari API terautentikasi. Korelasi login/actor/IP ke FIM belum tersedia.

Perintah dasar di atas menjalankan collector tanpa playbook (semua temuan hanya dicatat). Untuk menjalankan demo lengkap — data contoh, executor, persetujuan operator, tombol **Serang!**, dan trust anchor — pakai satu perintah ini:

```sh
sh lab/build.sh
```

Di Docker, agent berjalan di container terpisah dari server, jadi port tidak terbaca dan peta menampilkan satu pintu bawaan. Jalur SSH atau Web yang dipilih tetap tercatat di tab Playbook. Empat pintu dan blog WordPress hanya ada pada lab VM di `lab/vm`.

Dashboard menampilkan kesiapan worker dan tahapan setiap pemulihan. Overlay demo menahan tahap perbaikan selama 15 detik (`DEMO_REPAIR_DELAY_SECONDS`) agar isolasi terlihat. Hitung mundurnya tampil di dashboard saat server terisolasi; setelah jeda, artefak canary dikarantina, health check dijalankan, lalu Server A aktif kembali jika sehat. Jeda ini hanya untuk memperlihatkan alur demo, dan dashboard melaporkan waktu pulih tanpa jeda tersebut.

Dashboard memiliki tab **Patrol**. Peta Canvas 2D menyusun file dari snapshot hash agent ke ruang per server, menampilkan agent patroli, aktor berdasarkan IP, event akses, severity, dan detail hash. Snapshot hanya mengirim path relatif dan SHA-256, bukan isi file. Agent memakai `WATCH_ROOT` sebagai konfigurasi folder yang dipantau.

- Snapshot patrol: `GET /api/patrol/state`
- Event live: `GET /api/patrol/stream` (SSE)
- Ingest event akses: `POST /api/patrol/events`
- Snapshot hash agent: `POST /v1/patrol/snapshot`

### Animasi insiden (tab Patrol)

Tab Patrol sekarang memainkan cerita insiden dengan karakter game:

1. **Maling masuk.** Event simulasi (request ke app atau event FIM) memunculkan maling yang berjalan lewat jalan, masuk pintu server, lalu beraksi di file: mengintip (read), membawa kabur (download), merusak (modify), menghapus (delete), atau menanam file baru. Agent menandai event berdasarkan aturan; ini bukan AI analis.
2. **Isolasi.** Saat playbook masuk `ISOLATING`, gerbang server turun dan kabel ke HAProxy putus (percikan + label PUTUS). Maling terjebak di dalam. Status HAProxy `MAINT` tanpa playbook juga ditampilkan sebagai server terisolasi.
3. **Maintenance (`REPAIRING`).** Satpam menempelkan badge dan masuk, maling mencoba kabur, polisi menembak sampai maling KO. Satpam lalu memperbaiki file dengan bar progres yang mengikuti hitung mundur jeda demo (15 detik di konfigurasi VM dan canary).
4. **Verifikasi dan rejoin.** Satpam memeriksa file satu per satu (tanda centang), kabel tersambung kembali, gerbang dibuka, server kembali ONLINE, dan maling diamankan.

Urutan visual mengikuti tahap asli dari `/v1/dashboard`; tiap tahap punya durasi tayang minimum agar tahap singkat tetap terlihat. Membuka dashboard di tengah insiden langsung menampilkan keadaan terakhir.

Tombol **Serang!** mewakili permintaan operator, bukan eksekusi otomatis: `POST /v1/lab/attack/<host>` (butuh sesi operator + header CSRF) membuat persetujuan `SIMULATE_LAB_ATTACK` yang langsung disetujui oleh operator yang memintanya, lalu executor mengirim `POST /lab/attack` ke worker host target untuk menambah satu baris penanda ke `etc/kunci1.dat`. Agent mendeteksi perubahan itu, Policy Gate menulis persetujuan baru, dan playbook respons hanya berjalan setelah operator menyetujuinya di panel Persetujuan: server dikeluarkan dari HAProxy (`disable server`), file dikarantina, dipulihkan dari salinan master yang cocok manifes, dan server masuk kembali setelah health check lolos. Status di dashboard dibaca dari HAProxy; `MAINT` ditampilkan sebagai `DOWN`. Pilihan **SSH / Web** di sebelahnya menentukan pintu yang dilewati intruder di peta (`?vector=ssh` atau `?vector=web`); jalur masuknya simulasi, tidak ada serangan nyata ke SSH atau WordPress. Tombol ini butuh `LAB_ATTACK_SIMULATION=true` di remediator dan ditolak bila server lain tidak `UP` atau kunci belum pulih. Server yang tersangkut terisolasi dipulihkan operator dengan **Persetujuan → Rejoin backend** (atau `POST /v1/lab/recover/<host>`, juga butuh sesi operator).

Jumlah pintu tiap server mengikuti port TCP yang terbuka. Agent membaca `/proc/net/tcp` dan melaporkannya lewat heartbeat, jadi port yang hanya di loopback (misalnya MariaDB) tidak menjadi pintu, dan peta menampilkan paling banyak 6 pintu. Bila `AUTH_LOG` dan `WEB_LOG` diisi, agent juga membaca log login: login SSH berhasil dan login `wp-login.php` berhasil membuat intruder masuk lewat pintu port itu, sedangkan login gagal berhenti di pintu dengan tanda DENIED. Login SSH memakai kunci dianggap admin dan tidak ditampilkan; atur lewat `TRUSTED_SSH_METHODS`. Pasang di VM dengan `lab/vm/deploy-port-doors.sh`.

Pilih **Patrol → Mulai demo** untuk menghasilkan dua aktor sintetis dengan aksi berbeda. Simulator ini hanya berjalan pada browser dan tidak menulis file atau mengirim event palsu ke database. Event live berasal dari request ke app (`/` atau `/files/<path>`) serta event integritas agent. App hanya menyajikan file relatif yang terdaftar di `PATROL_PUBLIC_FILES` (default `index.txt`); file lain, file sensitif, dan metode tulis ditolak serta dicatat sebagai event. `WATCH_ROOT` pada tiap agent menentukan folder yang dipatroli. Analisis severity tetap berbasis aturan, bukan model AI terlatih.

## Simulasi containment yang aman

Dua playbook tersedia setelah overlay canary aktif; keduanya kini menunggu persetujuan operator sebelum dieksekusi:

1. **Mode canary** — agent menandai `DEFNETT-LAB-CANARY.txt` dari Insight isi; Policy Gate membuat persetujuan, playbook mengisolasi host, mengkarantina canary, dan mengaktifkan kembali host.
2. **Mode kunci** — FIM melihat isi `etc/kunci1.dat`/`etc/kunci2.dat` berubah (dicuri/diubah); persetujuan dibuat, playbook mengisolasi host, worker mengkarantina kunci tampered sebagai bukti ke `/quarantine`, memulihkan **kedua** kunci byte-per-byte dari salinan master di volume `/master` yang wajib cocok manifes (`/manifest/keys.json`, diisi `build.sh` atau `provision_master.py` — worker tidak lagi menyalin sendiri), lalu host kembali aktif. Kunci yang masih asli tidak disentuh, dan bila kedua kunci sudah asli permintaan ditolak dengan `keys_already_pristine`. Pemicu kunci hanya `file_modified`, dan pemulihan yang sama hash-nya dengan catatan diakui sebagai konfirmasi, bukan insiden baru.

```sh
sh lab/test-containment.sh server-a canary   # default
sh lab/test-containment.sh server-a kunci    # Playbook kunci
```

Keduanya menunggu status `REPAIRED`, menguji trafik sebelum/selama/sesudah, dan memastikan konstruk kembali sehat.

Playbook memilih host dari event. Setiap server memiliki worker dan volume karantina sendiri. Untuk event Server A, hanya worker A yang dapat menulis volume A; Server B hanya bertugas menjaga layanan tetap tersedia. Aturan yang sama berlaku sebaliknya untuk event Server B. Sekarang ada dua marker: string `DEFNETT-LAB-MALWARE-CANARY` di `/data/DEFNETT-LAB-CANARY.txt`, atau isi kunci `etc/kunci1.dat`/`etc/kunci2.dat` yang berubah. Playbook kemudian:

1. Memastikan backend survivor sehat.
2. Mengeluarkan hanya host target dari rotasi HAProxy.
3. Dashboard menampilkan jeda demo saat host tetap terisolasi. Setelah jeda, worker host target mengarantina file canary terverifikasi ke volume terpisah.
4. HAProxy menjalankan health check dan mengaktifkan kembali hanya host target jika sehat.

Script default menguji Server A. Untuk menguji Server B sebagai host target:

```sh
sh lab/test-containment.sh server-b
```

Script menunggu status `REPAIRED`, memeriksa file sudah hilang dari `/data`, memastikan request kembali mencapai Server A dan B, dan memastikan ID container kedua server tidak berubah. Jika worker, karantina, atau health check gagal, sistem menjaga host target tetap diisolasi dan dashboard mencatat penyebabnya.

Ini hanya membersihkan satu artefak canary lab pada path tetap. Worker memeriksa tipe file, ukuran, dan isi marker sebelum memindahkannya serta memverifikasi SHA-256 salinan. Ini bukan antivirus, bukan perbaikan OS, dan tidak mendeteksi atau menghapus malware sungguhan. Tidak ada file lain yang disentuh.

Jika perlu mengaktifkan kembali backend secara manual setelah pemeriksaan operator:

```sh
curl --fail --cacert "$HOME/.config/defnett-lab/tls/ca.crt" --request POST https://127.0.0.1:8443/v1/lab/recover/server-a
# Ganti server-a dengan server-b untuk memulihkan Server B.
```

Runtime admin HAProxy terikat pada alamat statis `172.31.254.2:9999` di network Compose `response_control` yang internal. Executor adalah satu-satunya service selain HAProxy pada network tersebut. Collector masih berbagi `host_access` untuk probe HTTP biasa, tetapi tidak bergabung pada `response_control`, `repair_a`, atau `repair_b`; ia hanya mengirim permintaan yang terautentikasi ke executor pada `execution_request`. Tiap remediator hanya berada di network repair host pasangannya. Port worker tidak dipublikasikan.

VM menempatkan Collector, Approval Authority, dan Executor pada VM Collector dengan UID terpisah. Approval Authority memiliki database privat; Collector tidak mendapat akses file langsung. Jalur dashboard/agent, authority, executor, dan remediator memakai HTTPS pada konfigurasi. Cgroup systemd dan guard UID membatasi Collector dari port HAProxy runtime/remediator. Ini masih batas proses pada kernel host, bukan isolasi host terpisah, dan belum diverifikasi pada VM aktual. Lihat [SECURITY_CUTOVER_RUNBOOK.md](vm/SECURITY_CUTOVER_RUNBOOK.md) untuk cutover, sertifikat, migrasi approval tertunda, dan rollback.

Provisioning akun dan permission dilakukan pada jendela maintenance setelah layanan collector/executor dihentikan:

```sh
sudo sh /tmp/defnett-deploy/provision-service-users.sh
```

Paket deployment harus memuat unit `defnett-collector.service`, `defnett-executor.service`, `defnett-collector-network-guard`, dan skrip provisioning. Setelah update, pastikan filter systemd aktif (`systemctl show ... -p IPAddressDeny -p IPAddressAllow`), aturan UID terpasang (`sudo iptables -S OUTPUT`), dan uji konektivitas positif/negatif secara aktual. Bila kernel/systemd tidak dapat menerapkan filter atau guard gagal, collector harus tetap gagal start; jangan menghapus direktif untuk memaksa layanan hidup.

## Trafik sebelum, selama, setelah containment

Collector menjalankan probe kecil: satu `GET /healthz` per detik lewat HAProxy (`http://haproxy:8080/healthz`), lalu mencatat sukses/gagal dan backend yang menjawab (header `X-DEFNETT-Host`). Probe memakai `/healthz`, jadi tidak membuat event patrol atau aktor di peta. Hitungan dibagi tiga fase mengikuti playbook:

- **Sebelum:** sejak collector hidup (atau sejak pemulihan sebelumnya) sampai playbook mulai (`EXECUTING`).
- **Selama:** dari playbook mulai sampai `REJOINING` selesai; host target sudah keluar dari rotasi.
- **Setelah:** mulai `REPAIRED`.

Hasil ada di `/v1/dashboard` pada kunci `traffic` dan di dashboard bagian "Request lewat HAProxy". Hitungan disimpan di memori collector, jadi reset saat collector restart. Nonaktifkan dengan `TRAFFIC_PROBE_ENABLED=false`; atur `TRAFFIC_PROBE_URL` dan `TRAFFIC_PROBE_INTERVAL` bila perlu.

## Inventaris file system di dashboard

Tab **File** di sidebar menampilkan isi file system tiap server per folder, bukan hanya `/data`. Agent memindai `INVENTORY_ROOT` setiap `INVENTORY_SECONDS` (default 300 detik) dan mengirim nama, jenis, ukuran, dan waktu ubah ke `/v1/patrol/inventory`. Dashboard membaca satu folder per klik lewat `/api/patrol/fs?host=server-a&path=/etc`.

- Inventaris hanya berisi metadata, tanpa hash dan tanpa isi file.
- Deteksi perubahan, alert, dan hewan patroli di kanvas tetap memakai `WATCH_ROOT`, yaitu `/data`.
- `/proc`, `/sys`, `/dev`, dan `/run` tampil sebagai virtual dan tidak dipindai.
- Di VM, `INVENTORY_ROOT=/`. Bila tidak diatur, nilainya mengikuti `WATCH_ROOT`, sehingga lab Docker hanya menampilkan `/watched`.
- Pasang di VM dengan `lab/vm/deploy-inventory.sh`, yang menyimpan file lama sebagai `*.bak-<waktu>`.

## Struktur /data: pohon ala Linux

Isi `/data` tiap server tidak flat. Script `lab/seed-fs.sh` menata ±22 direktori dan 56 file per host menyerupai pohon Linux (`bin`, `boot/grub`, `etc`, `home/kartika/notes`, `home/dima`, `opt/defnett`, `root`, `srv`, `usr`, `var/log`, `var/lib/defnett`). Jalankan dari root repo:

```sh
docker exec -i lab-server-a-1 sh -s server-a < lab/seed-fs.sh
docker exec -i lab-server-b-1 sh -s server-b < lab/seed-fs.sh
docker compose -f lab/compose.yaml -f lab/compose.canary.yaml restart agent-a agent-b
```

Aturan yang tetap berlaku:

- `index.txt` tetap di akar karena app menyajikan `/` ke file itu.
- Hanya path yang terdaftar di `PATROL_PUBLIC_FILES` (index, beberapa config distro, dan catatan di `home/kartika/...`) yang bisa dibaca lewat HAProxy; sisanya ditolak 403 dan dicatat sebagai event denied.
- `etc/kunci1.dat` dan `etc/kunci2.dat` adalah kunci rahasia: sengaja tidak didaftarkan sehingga selalu ditolak (di peta muncul sebagai ikon kunci emas dan menjadi target animasi "Serang!").
- `DEFNETT-LAB-CANARY.txt` harus tetap di akar `/data` karena playbook canary dan worker memakai jalur tetap itu. Restart agent setelah seed ulang agar baseline FIM segar tanpa event palsu.

## Demo perubahan file

```sh
sh lab/demo.sh
```

Agent akan mendeteksi perubahan `etc/new-config.txt` pada Server A dan mengirim event ke collector. Event hanya dicatat (bukan canary/kunci); endpoint layanan tetap berjalan melalui HAProxy.

## Waktu respons, jalur masuk, dan rantai bukti

Tab **Playbook** menampilkan tiga angka yang dihitung dari stempel waktu insiden: waktu deteksi, waktu isolasi, dan waktu pulih tanpa jeda demo. Bila ada login berhasil di host yang sama dalam 10 menit terakhir, insiden mencatat IP dan port masuknya.

`GET /v1/evidence/verify` memeriksa seluruh rantai event, dan hasilnya tampil sebagai lencana **Bukti utuh**. Hash mendeteksi perubahan pada baris yang tersimpan, tapi rantai ini belum ditanam ke sistem eksternal, sehingga penyerang yang menguasai database masih bisa menulis ulang seluruh rantai.

## Autentikasi antarkomponen

Bila `LAB_API_TOKEN` diisi, collector dan remediator menolak permintaan mesin tanpa token yang cocok; executor punya token m2m sendiri (`EXECUTOR_API_TOKEN`) dan menolak hidup tanpanya. Token dibaca dari env masing-masing layanan dan tidak disimpan di repo. Selain itu dashboard memiliki login operator (PBKDF2 + cookie + CSRF) dan setiap eksekusi menunggu persetujuan.

### Batas keamanan sesi dan trust anchor

- Dashboard Docker dan Collector VM dikonfigurasi HTTPS. Cookie sesi memakai `Secure`, `HttpOnly`, dan `SameSite=Strict`; tindakan POST operator membutuhkan CSRF. CA/certificate disiapkan untuk lab, bukan PKI produksi. Runtime browser dan VM belum diuji. Frontend demo app HTTP :8080 hanya untuk loopback/host-only lab dan bukan endpoint operator.
- Hash akun baru memakai PBKDF2-HMAC-SHA256 600.000 iterasi. Rekaman lama tetap diverifikasi memakai jumlah iterasinya dan dinaikkan setelah login sukses; kegagalan menulis rehash tidak menolak login.
- Master dan manifest Compose dipasang read-only pada remediator. `build.sh` tidak lagi menurunkan master dari `/data`; sediakan baseline tepercaya di luar target sebelum menjalankan provisioning. VM memakai `/master` dan manifest `/etc/defnett/master-manifest.json`; provisioning juga harus memakai baseline eksternal, bukan `/data`.
- Untuk Compose, siapkan folder baseline offline berisi `kunci1.dat` dan `kunci2.dat` untuk tiap host, lalu jalankan provisioning eksplisit (contoh Server A): `docker run --rm --user root -v defnett-lab_master_a_data:/master -v defnett-lab_manifest_a_data:/manifest -v /path/ke/baseline/server-a:/src:ro defnett-lab:local python /opt/defnett/provision_master.py --master /master --source /src --manifest /manifest/keys.json`. Ulangi dengan volume `_b_data` dan folder baseline Server B. Tanpa langkah ini, pemulihan sengaja gagal tertutup.
- Manifest lokal melindungi dari perubahan master yang tidak disertai perubahan manifest. Administrator host yang sudah menguasai root dapat mengubah keduanya, binary, volume, atau database; jaminan trust anchor tidak bertahan terhadap host yang telah dikompromikan.
- AI Patroli belum diimplementasikan. Agent saat ini adalah pemantau deterministik. Jika AI kelak ditempatkan dalam proses collector, ia mewarisi token dan akses jaringan proses itu; pemisahan proses diperlukan sebelum AI dapat disebut read-only secara struktural.

## Pengujian otomatis

```sh
python3 -m unittest discover -s lab/tests
```

## Skrip utilitas

| Skrip | Fungsi |
|---|---|
| `sh lab/build.sh` | Bangun image, hidupkan lab lengkap, buat token m2m, siapkan akun operator pertama, isi data contoh, dan siapkan salinan master + manifes dalam satu perintah. |
| `sh lab/demo.sh` | Simulasi operator: ubah `etc/new-config.txt`, lalu lihat event/hash chain di collector. |
| `sh lab/attack.sh` | Simulasi pencuri lewat HAProxy: mengintip file publik, menebak nama sensitif, lalu mencoba `etc/kunci1.dat`/`etc/kunci2.dat` termasuk `?download=1` — setiap percobaan ditolak 403 dan muncul sebagai event denied (animasi pencuri di Patrol bergolak). |
| `sh lab/test-containment.sh` | Uji playbook penuh lewat login operator: dapatkan persetujuan, setujui, tunggu isolasi → karantina → verifikasi → rejoin + asersi trafik sebelum/selama/sesudah. |
| `sh lab/seed-fs.sh` (via `docker exec -i`) | Seed ulang pohon `/data` ala Linux; lihat bagian "Struktur /data" di atas. |

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

Dashboard menampilkan heartbeat agent, status tiap worker, server yang menjadi target perbaikan, server survivor yang tetap berjalan, daftar event dan hash, serta tahapan `deteksi → persetujuan → isolasi → karantina → verifikasi → rejoin` plus panel Persetujuan. Worker hanya dapat menulis volume host pasangannya. Peta node adalah visualisasi alur layanan, bukan representasi neuron atau model AI sungguhan. Analisis yang berjalan adalah FIM dan aturan canary deterministik.

- Pemantauan polling membaca file di `/data`; belum menggunakan Wazuh agent atau memantau file sistem host.
- SQLite dan hash chain membantu demonstrasi audit, tetapi bukan penyimpanan bukti tahan manipulasi produksi.
- Collector menggabungkan ingestion, normalisasi minimal, penyimpanan, trajectory, scoring, dan policy dalam satu proses agar irisan end-to-end mudah dijalankan.
- Belum ada model ML, classifier terkalibrasi, atau isolasi jaringan container penuh. Isolasi lab mengeluarkan backend dari rotasi HAProxy.
- Pemulihan yang dapat dijalankan terbatas pada file canary dan dua file kunci lab pada host yang terdeteksi, dan hanya setelah persetujuan operator. Kasus selain itu gagal tertutup dan perlu pemeriksaan operator.
- Network Compose untuk layanan, telemetri, kontrol HAProxy, dan remediation dibuat terpisah/internal. HAProxy dan collector saja yang mempublikasikan port ke `127.0.0.1`.

## OT Modbus lab (instrumented gateway)

Compose menambahkan layanan `ot-gateway` pada jaringan internal `ot_lab` tanpa port host yang dipublikasikan. Layanan ini merupakan endpoint Modbus TCP aktif yang memvalidasi dan menegakkan policy lab; ia **bukan** passive IDS atau packet-capture sensor. Lingkup protokol saat ini hanya FC03 Read Holding Registers dan FC06 Write Single Register.

Policy di `lab/ot-policy.json` menentukan identitas device, unit ID, sumber jaringan, rentang register read, register write yang diizinkan, nilai awal, dan dampak aset. Jangan menghubungkan gateway ke PLC produksi. Jaringan Compose internal dan token khusus OT membatasi pengiriman event kepada collector; event diteruskan melalui HTTPS dan CA verification.

Setelah build/stack berjalan dengan `DEFNETT_OT_API_TOKEN` tersedia, kirim transaksi nyata dari dalam container gateway:

```sh
docker compose -f lab/compose.yaml exec -T ot-gateway \
  python /opt/defnett/modbus_lab.py --client --function 3 --address 100 --value 2
docker compose -f lab/compose.yaml exec -T ot-gateway \
  python /opt/defnett/modbus_lab.py --client --function 6 --address 120 --value 7
docker compose -f lab/compose.yaml exec -T ot-gateway \
  python /opt/defnett/modbus_lab.py --client --function 6 --address 121 --value 7
```

Output `LIVE_LAB_TELEMETRY` berarti respons berasal dari transaksi TCP ke simulator yang berjalan. Keputusan `DENY` dan exception code tetap merupakan hasil transaksi yang diamati. Collector menerima event melalui endpoint token khusus, menghapus duplikasi berdasarkan hash request, memasukkan event ke evidence chain, dan menyimpan assessment risiko ordinal (bukan probabilitas). Denial menghasilkan temuan operator-review; tidak ada tindakan containment otomatis.

Uji cepat lokal termasuk dalam `python3 -m unittest discover -s lab/tests`: test membuka TCP gateway dan handler Collector pada loopback, menjalankan FC03/FC06, denial source/unit/function/register, malformed MBAP, duplicate delivery, dan pemeriksaan ledger. Itu adalah integration test loopback; bukan bukti Docker runtime atau konektivitas VM. Di deployment Docker, `ot-gateway` tidak dapat mengakses network executor, HAProxy, maupun remediator. Approval state dimiliki database service `approval-authority`, terpisah dari database evidence; Compose config dan process/API test mendukung boundary ini, tetapi runtime Docker/VM belum diuji.

Skenario unknown device/source, telemetry malformed, dan simulator unavailable menghasilkan denial, event rejection, atau kegagalan koneksi sesuai kasus. Kondisi sensor tidak tersedia tidak boleh dibaca sebagai kondisi OT aman. Tidak ada integrasi PLC produksi yang diuji.
