# Dokumentasi Teknis DEFNETT

DEFNETT adalah purwarupa respons insiden otomatis untuk layanan dua server di balik load balancer. Saat file penting berubah, server target dikeluarkan dari rotasi, file dipulihkan, lalu server dimasukkan kembali setelah health check lolos. Selama itu server lain tetap melayani pengguna.

## Komponen

| Komponen | Berkas | Tugas |
|---|---|---|
| Agent | `lab/agent.py` | Memantau hash `/data`, port terbuka, log login, dan inventaris file system |
| Collector | `lab/collector.py` | Menerima event, menilai risiko, menyimpan rantai hash, membuat persetujuan, melayani dashboard |
| Policy Gate | `lab/policy_gate.py` | Menentukan kategori keputusan (informasi, penyelidikan, peringatan, menunggu persetujuan) — murni analisis, tidak pernah mengeksekusi |
| Approval Authority | `lab/approval_authority.py` | Pemilik tunggal database persetujuan; autentikasi operator, role, CSRF, expiry, klaim atomik, audit |
| Authority client | `lab/authority_client.py` | API HTTPS bertoken untuk Collector dan Executor dengan verifikasi CA |
| Trajectory grouping | `lab/trajectory.py` | Menghubungkan event host/path yang sama dengan kesinambungan hash atau jendela waktu sempit; menyimpan alasan dan confidence, bukan klaim kausal |
| Otentikasi operator | `lab/operator_auth.py` | Login PBKDF2 dari berkas 0600, sesi memori, header CSRF |
| Executor | `lab/executor.py` | Satu-satunya proses yang memegang akses HAProxy runtime dan remediator; mengklaim persetujuan lalu menjalankan playbook |
| Remediator | `lab/remediator.py` | Mengarantina file dan memulihkan kunci pada host-nya sendiri, selalu sesuai manifes kepercayaan |
| Provisioning | `lab/provision_operators.py`, `lab/provision_master.py` | CLI operator-manage akun, salinan master kunci, dan manifes sha256 |
| Dashboard | `lab/dashboard` | Overview, Patrol, tab File, Playbook, Trafik, modal login, panel persetujuan |
| Gateway | HAProxy | Membagi trafik dan menjalankan perintah isolasi |

Kode buatan tim hanya memakai pustaka standar Python, sehingga dapat dipasang di jaringan tertutup tanpa mengunduh dependensi Python.

## Alur insiden

1. Agent melihat hash `etc/kunci1.dat` atau `etc/kunci2.dat` berubah, atau canary lab muncul.
2. Collector mencatat event ke rantai hash; Policy Gate menetapkan `PENDING_APPROVAL`. Collector meminta Authority membuat approval melalui API bertoken; database approval tidak dipasang pada Collector atau Executor.
3. Operator yang sudah login menekan **Setujui** di panel persetujuan dashboard. Eksekusi hanya bisa bermula dari persetujuan yang klaimnya atomik, satu kali, dan tidak kedaluwarsa.
4. Executor memastikan server lain sehat. Bila tidak, playbook berhenti dan server target tidak diubah.
5. Executor memerintahkan HAProxy mengeluarkan server target, lalu menunggu konfirmasi.
6. Remediator mengarantina file yang berubah dan memulihkan kunci dari salinan `/master` yang isi wajib cocok dengan manifes. Bila master tidak cocok manifes, pemulihan ditolak (`master_untrusted`) dan target tetap terisolasi.
7. Hash hasil pemulihan diverifikasi, lalu HAProxy memeriksa kesehatan server.
8. Server kembali ke rotasi. Bila health check gagal, server tetap terisolasi. Kegagalan tahap mana pun dicatat `EXECUTION_FAILED`, tidak pernah dilaporkan sukses.

## API utama

| Metode dan jalur | Fungsi | Akses |
|---|---|---|
| `POST /v1/events` | Event integritas dari agent | Token `LAB_API_TOKEN` dari agent bila diaktifkan |
| `POST /v1/agent/heartbeat` | Heartbeat dan daftar port | Sama |
| `POST /api/patrol/events` | Event akses dan login | Sama |
| `POST /v1/patrol/snapshot`, `/v1/patrol/inventory` | Daftar file dan inventaris | Sama |
| `POST /v1/operator/login,logout,whoami` | Sesi operator | Wajib punya file akun; terkunci sementara setelah 5 kegagalan |
| `GET /v1/*` (dashboard, approvals, events, fsmap, patrol) | Pembacaan collector | Cookie sesi (viewer+) |
| `GET /v1/trajectories` | Rangkaian event dan relasi bukti yang terukur | Cookie sesi (viewer+) |
| `POST /v1/approvals/<id>/<approve\|reject\|execute>` | Siklus persetujuan | Sesi operator + header CSRF |
| `POST /v1/lab/attack/<host>?vector=ssh\|web` | Minta simulasi serangan lab | Sesi operator + CSRF; dibuat sebagai persetujuan |
| `POST /v1/lab/recover/<host>` | Minta rejoin backend | Sesi operator + CSRF; dibuat sebagai persetujuan |
| `POST /v1/execute` | Eskalasi persetujuan ke executor (m2m) | Token khusus executor |
| `POST /v1/repair`, `POST /v1/lab/attack` (remediator) | Karantina/pemulihan di satu host | Token; host tujuan wajib sama |
| `GET /v1/haproxy-states` | Status backend untuk dashboard | Token executor |

## Keamanan dan validasi saat ini

- **Approval boundary:** hanya Approval Authority memiliki database approval. Collector dan Executor memakai API internal terbatas dengan token berbeda; UI approval memerlukan role operator, sesi, dan CSRF yang diverifikasi Authority.
- **Token antarkomponen:** agent–collector memakai `LAB_API_TOKEN`, collector–executor memakai `EXECUTOR_API_TOKEN` (executor menolak hidup tanpa token ini), executor–remediator memakai `LAB_API_TOKEN`. Token disimpan di env layanan, bukan di repo.
- **Otentikasi operator:** hash baru PBKDF2-SHA256 600.000 iterasi; hash lama yang memenuhi batas minimum tetap diverifikasi dan dinaikkan setelah login valid. Dashboard/Authority dikonfigurasi TLS; cookie Secure, HttpOnly, SameSite=Strict. Header CSRF wajib untuk POST operator.
- **Semua tindakan operator tercatat:** tabel `operator_audit` mencatat siapa yang menyetujui, menolak, atau menandai persetujuan.
- **Trust anchor:** salinan master kunci ditulis CLI `provision_master.py` sekali per host beserta manifes sha256; master dan manifes di-mount read-only. Pemulihan menolak penyalah gunaan: `master_untrusted:<nama>` dan target tetap terisolasi.
- **Pemisahan peran:** executor tidak pernah menulis tabel `events`; remediator tiap host hanya menerima permintaan untuk host itu sendiri; remediator tidak lagi mengisi `/master` sendiri.
- **Docker:** HAProxy admin menggunakan Unix socket mode 0660 pada volume yang hanya dipasang ke HAProxy dan executor. Collector dapat memakai frontend HTTP biasa untuk probe, tetapi tidak memiliki socket dan tidak bergabung pada `response_control` atau jaringan remediator.
- **VM:** Collector, Approval Authority, dan Executor berada pada VM Collector dengan UID berbeda. Database authority privat; Collector tidak memiliki group akses ke database atau file kredensial operator. HTTPS, systemd IP filters, dan guard UID diprovisi, tetapi VM belum diuji aktual sehingga belum E2E PASS.

## Batasan

- Skor risiko berbasis aturan, belum model ML.
- Trajectory saat ini hanya korelasi host/path dan hash continuity; belum menghubungkan login, actor, IP, event type lain, atau tampilan timeline khusus. MEDIUM correlation bukan causal claim.
- CA lab bukan PKI produksi dan jalur service memakai bearer token melalui TLS, bukan mTLS. Demo app :8080 tetap HTTP pada loopback/host-only lab. Browser/Docker/VM runtime belum divalidasi pada deployment.
- Collector adalah satu titik kegagalan. Bila mati, pemantauan berhenti, tapi layanan tetap berjalan.
- Rantai hash mendeteksi perubahan baris, tapi belum ditanam ke sistem eksternal.
- Cakupan yang diuji adalah sistem IT berbasis Linux. Sistem OT belum diuji.

## Pemasangan

- **Docker:** `sh lab/build.sh` menyiapkan token, CA lab, akun operator, dan trust anchor dari baseline tepercaya; buka `https://127.0.0.1:8443/` setelah browser mempercayai CA lab.
- **VM:** ikuti [TLS dan Approval Authority cutover](../lab/vm/SECURITY_CUTOVER_RUNBOOK.md). Backup dan selesaikan approval lama sebelum cutover; konektivitas dan isolasi VM tetap harus diuji aktual.
- **Operator:** akun dibuat CLI `provision_operators.py --add <nama> --role viewer|operator` (kata sandi minimal 12 karakter); tidak ada akun bawaan.
- **Pengujian otomatis:** `python3 -m unittest discover -s lab/tests`.

Hasil pengujian di lab ada di [HASIL_UJI.md](HASIL_UJI.md).
