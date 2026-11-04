# Hasil Uji DEFNETT

## Uji VM dengan persetujuan operator — 3 November 2026

Diuji di empat VM VirtualBox setelah cutover ke TLS dan Approval Authority. Rincian dan bukti: `DEFNETT-artifacts/BLUESECC-DEPLOYMENT-VALIDATION/`.

| Ukuran | Hasil |
|---|---|
| Insiden disetujui, diisolasi, dan pulih | 6 dari 6 (3 di Server A, 3 di Server B, SSH dan Web) |
| Permintaan blog lewat load balancer | 506, semuanya HTTP 200 (Server A 255, Server B 251) |
| Deteksi | 0,39 sampai 2,76 detik, median 1,06 |
| Persetujuan muncul setelah Serang | 6,0 sampai 8,3 detik |
| Isolasi setelah disetujui | 0,05 sampai 0,34 detik |
| Pulih tanpa jeda demo 15 detik | 0,53 sampai 2,04 detik, median 1,29 |
| Rantai bukti | Utuh, 3.132 event |
| Uji TLS, token, dan isolasi dari host | 30 dari 30 setelah satu aturan firewall lama ditutup |
| Uji isolasi per UID, viewer, dan Authority mati | 28 lulus, 1 tidak terverifikasi karena bug skrip uji |

| Dashboard lewat browser (Safari, HTTPS) | Login, Serang, Setujui, Tolak, dan logout lulus setelah enam bug dashboard diperbaiki |

Docker dan gateway OT Modbus belum diuji di laptop ini.

## Status pemeriksaan lokal terbaru

Pemeriksaan 4 November 2026 di macOS: 94 test, 93 lulus dan 1 dilewati, tanpa `ResourceWarning`. Test yang dilewati (`test_unknown_source_is_denied_and_recorded`) memerlukan alamat sumber `127.0.0.2`, yang hanya tersedia di loopback Linux.

Pemeriksaan lokal 3 November 2026 setelah authority/TLS closure: 89/89 unit test lulus dengan `ResourceWarning` diaktifkan dan tanpa warning. Compose base dan canary lulus `docker compose config --quiet`. Approval Authority HTTPS diuji sebagai proses terpisah di loopback. Docker runtime/browser dan VM E2E `NOT_RUN`; VM BlueSecc berada di laptop lain. Unit systemd valid pada temporary-copy tanpa host-only guard; unit terpasang dan runtime VM tetap belum diverifikasi.

Data angka di bawah merupakan catatan historis dari lingkungan pengujian sebelumnya. Angka tersebut belum direproduksi pada pemeriksaan lokal terbaru dan tidak boleh dipakai sebagai bukti release saat ini.

Diuji pada 2 November 2026 di empat VM VirtualBox dengan HAProxy asli. Setiap uji memicu insiden sungguhan: file kunci diubah, server keluar dari rotasi HAProxy, file dipulihkan, lalu server kembali setelah health check.

## Ringkasan

| Ukuran | Hasil |
|---|---|
| Insiden pulih sampai tuntas | 6 dari 6 |
| Permintaan blog lewat load balancer | 400, semuanya HTTP 200 |
| Dijawab Server A / Server B | 185 / 215 |
| Waktu deteksi | 0,29 sampai 3,02 detik, median 1,69 detik |
| Waktu isolasi setelah deteksi | 0,01 sampai 0,02 detik |
| Waktu pulih tanpa jeda demo | 0,53 sampai 1,55 detik, median 1,04 detik |
| Waktu pulih dengan jeda demo 15 detik | 15,53 sampai 16,55 detik |
| Verifikasi rantai bukti | Utuh, 3.103 event |

Enam insiden terdiri dari tiga di Server A dan tiga di Server B, memakai jalur SSH dan Web bergantian. Permintaan dikirim terus-menerus ke blog, sekitar tiga kali per detik.

## Cara membaca angka

- **Deteksi** dihitung dari waktu file berubah sampai agent melihatnya. Agent memeriksa tiap 3 detik, jadi batas atasnya sekitar 3 detik.
- **Isolasi** dihitung dari insiden tercatat sampai HAProxy mengonfirmasi server keluar rotasi.
- **Pulih** dihitung dari insiden tercatat sampai HAProxy melaporkan server `UP` penuh. Jeda demo 15 detik sengaja dipasang agar isolasi terlihat, dan tidak termasuk kerja sistem.
- Jalur masuk SSH atau Web pada uji ini adalah simulasi. Perubahan file, deteksi, isolasi, dan pemulihan berjalan sungguhan.

## Pemeriksaan lain

| Pemeriksaan | Hasil |
|---|---|
| Heartbeat ke collector tanpa token | Ditolak 401 |
| Perintah perbaikan ke remediator tanpa token | Ditolak 401 |
| Login SSH dengan password | Tertangkap sebagai event port 22 |
| Login SSH salah password | Tertangkap sebagai event ditolak |
| Port dilaporkan agent | 22, 80, 8080, 8091, sesuai yang terbuka dari luar |
| Pengujian otomatis (`lab/tests`) | 10 lolos pada versi saat itu (tahap 0) |

Pengujian otomatis mencakup pembacaan log login, rotasi log, deteksi manipulasi bukti, event bersamaan, perhitungan waktu, dan penolakan token.

## Temuan saat pengujian

Pengujian mengungkap dua masalah yang sudah diperbaiki sebelum angka di atas diambil:

- Server sempat dianggap sehat saat HAProxy masih berstatus `UP 1/2`. Sekarang hanya status `UP` penuh yang lolos.
- Rantai hash berisiko bercabang saat dua agent mengirim event bersamaan. Sekarang penulisan event dikunci.

## Uji jalur Docker

Jalur `sh lab/build.sh` diuji dari instalasi bersih, memakai project Docker dan volume baru, di satu komputer. Langkah ini sama dengan yang dijalankan pembaca repo.

| Ukuran | Hasil |
|---|---|
| Build dan seed data | Berhasil, mode `ACTIVE_LAB`, Server A dan B `UP` |
| Insiden lewat API | 2 dari 2 pulih, 149 permintaan semuanya HTTP 200 |
| Dijawab Server A / Server B | 73 / 76 |
| Tombol **Serang!** di browser | Server keluar rotasi, load balancer `1/2`, lalu kembali `UP` |
| Waktu pulih tanpa jeda demo | 0,53 sampai 1,55 detik |
| Error JavaScript di dashboard | 0 |
| Verifikasi rantai bukti | Utuh, 117 event, semuanya terverifikasi penuh |

Docker berjalan dengan aplikasi demo, bukan WordPress, dan peta hanya menampilkan satu pintu. Jalur masuk yang dipilih tetap tercatat di tab Playbook.

## Validasi authority dan TLS lokal — 3 November 2026

| Pemeriksaan | Status | Hasil |
|---|---|---|
| Full unit suite | PASS | 89/89; tidak ada ResourceWarning |
| Authority TLS valid | PASS | HTTPS process/API loopback dengan CA lab |
| CA tak dikenal dan HTTP authority | PASS | Ditolak pada test process-level |
| Collector service token | PASS | Tidak dapat approve atau claim approval |
| Viewer/session/CSRF/expiry/one-use/replay | PASS | Ditolak/diterima sesuai role dan status yang diuji |
| Cookie login authority | PASS | `Secure`, `HttpOnly`, `SameSite=Strict` |
| SAN dan hostname verification | PASS | SAN sertifikat VM diperiksa; koneksi ke hostname IP yang tidak cocok ditolak |
| Compose config | PASS (statis) | `docker compose -f lab/compose.yaml config --quiet` |
| Python/shell syntax | PASS | Modul dan skrip terkait berhasil diperiksa |
| Unit systemd VM | PASS (syntax only) | Temporary copies valid; runtime guard harus terpasang dan diuji pada VM |
| Expired certificate handshake | NOT_RUN | Belum dibuat test certificate kedaluwarsa |
| mTLS client identity | NOT_IMPLEMENTED | Jalur memakai TLS server verification dan token service, bukan client certificate |
| Docker E2E/browser | NOT_RUN | Docker runtime tidak dijalankan |
| VM connectivity/E2E | NOT_RUN | Empat VM tidak tersedia di laptop ini |

Approval lama dalam database evidence tidak diimpor otomatis ke authority baru. Sebelum cutover VM, backup kedua database dan minta operator menuntaskan atau menolak approval tertunda.

## Belum diuji

- Login web `wp-login.php` sungguhan.
- Sistem OT dan beban trafik tinggi.
- 3.080 event lama di lab VM hanya terverifikasi tautan rantainya, karena isi lengkap baru disimpan setelah fitur ini ada. Event yang lebih baru terverifikasi penuh.

## Uji tahap 1 (pengaman dan persetujuan)

Tahap 1 mengubah cara sistem bekerja: eksekusi tidak lagi dipicu otomatis oleh collector. Setiap temuan canary/kunci kini menulis baris persetujuan yang harus disetujui operator yang login, dan eksekusi hanya dilakukan executor yang terpisah, dengan salinan master kunci diverifikasi manifes sha256. Sebagian besar perubahan diuji dengan uji otomatis; uji lomba (scripts) dari tahap 0 belum diulang untuk semua perubahan ini.

| Pemeriksaan | Hasil |
|---|---|
| Pengujian otomatis seluruh `lab/tests` | 89 test; 88 lulus dan 1 dilewati di macOS (4 November 2026) |
| Ingestion tanpa eksekusi: canary dan kunci hanya membuat persetujuan `PENDING` | Lolos |
| Event dengan skor/ML palsu di payload diabaikan, risiko tetap dari aturan | Lolos |
| Policy Gate: canary/kunci → persetujuan; event umum → catatan saja | Lolos |
| Konfirmasi pemulihan: hash sama dengan catatan tidak lagi dianggap insiden | Lolos |
| Siklus persetujuan: setujui/tolak/klaim satu kali/kedaluwarsa | Lolos |
| Login operator: PBKDF2, cookie, CSRF wajib, kunci setelah 5 kegagalan | Lolos |
| Matriks hak: viewer tidak bisa menyetujui; tanpa sesi → 401; tanpa CSRF → 403 | Lolos |
| Playbook executor (HAProxy + remediator palsu): pulih, master_untrusted, repair gagal, isolasi gagal, server pasangan mati | Lolos |
| Executor m2m: token salah 401, klaim dua kali 409 | Lolos |
| Trust anchor: provision → verifikasi; master diubah/tanpa manifes → ditolak `master_untrusted`, target tidak disentuh | Lolos |
| E2E Docker (`lab/build.sh` + `lab/test-containment.sh`) | NOT_RUN pada pemeriksaan lokal terbaru: Docker daemon tidak aktif |
| E2E VM VirtualBox (empat VM) | NOT_RUN pada pemeriksaan lokal terbaru: VM tidak tersedia di laptop ini; kernel module host tidak aktif |

Uji otomatis baru ada di `lab/tests/test_tahap1.py`. Ia berdiri sendiri: setiap test memasang pangkalan data bukti, berkas operator, HAProxy palsu, dan remediator palsu di folder sementara, tanpa jaringan keluar.

Angka lama (waktu deteksi/isolasi/pulih) di atas masih milik arus tahap 0; arus baru menambah satu langkah manual: operator menyetujui playbook setelah peringatan muncul, sebelum eksekusi dimulai. Perubahan waktu total insiden akan diukur ulang di uji E2E yang menunggu Docker aktif.
