# Source Transfer Audit

## Sumber yang diterima

Arsip `lomba-kartika.zip` (via WhatsApp) berisi `DEFNETT/` (working directory git) dan `DEFNETT-artifacts/`.

| Item | Laptop pengembangan (zip) | Laptop BlueSecc (repo ini) |
|---|---|---|
| Branch | `tahap-1-policy-gate` | `main` |
| HEAD | `5f4f7dc` | `5f4f7dc` |
| Perubahan tracked belum di-commit | 30 file | sama, disalin dari zip |
| File untracked yang dibutuhkan | 26 file (modul tahap 1, unit, runbook) | sama, disalin dari zip |
| Dataset | `datasets/` 898 MB | **tidak disalin**, dimasukkan `.gitignore` |

Branch berbeda tetapi HEAD sama. Tidak ada checkout, reset, atau clean. Repo lokal sebelum penyalinan bersih (hanya `NASKAH_VIDEO.md` untracked), jadi penyalinan `rsync` (tanpa `--delete`) setara menerapkan diff tim. Hasil diverifikasi dengan `diff -rq`: tidak ada perbedaan selain file yang sengaja dikecualikan.

Rekomendasi: buat branch `tahap-1-policy-gate` dari keadaan ini sebelum commit, agar sama dengan laptop pengembangan.

## Perubahan setelah transfer (perbaikan yang ditemukan saat deployment)

| File | Masalah | Perbaikan |
|---|---|---|
| `lab/vm/server-a/server-a.env`, `server-b.env` | URL heartbeat/snapshot/inventory tanpa `/v1`, ditolak 404 | Ditambah `/v1` |
| `lab/vm/collector/provision-service-users.sh` | Mewajibkan kunci TLS remediator di Collector (bertentangan dengan runbook) | Hanya kunci Collector, Executor, Authority |
| `lab/vm/deploy-update.sh` | `risk_engine.py` tidak disalin, Collector gagal impor | Ditambahkan |
| `lab/provision_master.py` | CLI mengirim `str`, `provision()` butuh `Path` → crash | Dibungkus `Path`; test CLI baru |
| `lab/collector.py` | `EXECUTOR_API_TOKEN` tidak terdefinisi saat start → crash loop | Memakai `EXECUTOR_TOKEN` |
| `lab/authority_client.py` | Balasan dipotong 16 KB → JSON rusak → dashboard crash setelah beberapa insiden | Batas 1 MB, balasan terlalu besar ditolak eksplisit |
| `lab/collector.py` | `restored-hashes` dipanggil GET, Authority hanya POST → 404 | Memakai POST; `list_approvals` gagal tertutup bila balasan tidak valid |
| `lab/provision_operators.py` | Kata sandi hanya diminta sekali (salah ketik tidak terdeteksi) | Konfirmasi dua kali |
| `lab/tests/test_tahap1.py` | Test memakai `127.0.0.2` (tidak ada di macOS) | Dilewati dengan alasan bila alamat tidak tersedia |
| `lab/tests/test_approval_authority_process.py` | — | Test baru: daftar >16 KB dan `restored-hashes` lewat proses Authority asli |
| `lab/dashboard/dashboard.js` | Modal login merebut fokus tiap 2,5 dtk; pesan "Collector tidak dapat dijangkau" saat belum login | Fokus hanya saat dibuka; status "Belum masuk" |
| `lab/dashboard/dashboard.css` | Popup login tidak bisa disembunyikan | `.op-modal[hidden] { display: none; }` |
| `lab/collector.py` | `GET /v1/operator/whoami` 404; logout body kosong 400; Tolak tidak menutup insiden | Rute GET, baca body hanya bila >0, `close_rejected_run`; 3 test baru |
| `lab/dashboard/patrol.js` | Insiden ditolak tidak pernah berakhir di peta | Tahap `REJECTED` mengakhiri adegan |
| `lab/dashboard/index.html`, `dashboard.js` | Logout tersembunyi di balik tombol nama operator | Tombol **Keluar** tersendiri, tampil hanya saat login |

Skrip baru: `lab/vm/restore-kunci.sh`, `lab/vm/cutover-stage.sh`, `lab/vm/cutover-vm.sh`, `lab/vm/e2e-approval.py`, `lab/vm/vm-checks-host.py`, `lab/vm/vm-checks-root.sh`.

Unit test setelah semua perubahan: 94 test, 93 PASS, 1 skipped (macOS), 0 FAIL.

## Secret audit

| Pemeriksaan | Hasil |
|---|---|
| trufflehog filesystem (`lab`, `docs`, README, naskah) | 0 temuan |
| trufflehog riwayat git | 0 temuan |
| Pola private key PEM di repo | tidak ada |
| Token di compose | dari variabel lingkungan, dibuat acak oleh `build.sh` (`secrets.token_urlsafe`) |
| Env VM di repo | hanya placeholder `GANTI-TOKEN-*`; cutover menolak lanjut bila placeholder tersisa |
| CA dan kunci lab | dibuat di `~/.config/defnett-vm-lab/` (di luar repo, mode 0700/0600) |
| Token layanan VM | dibuat acak (`openssl rand -hex 32`) di `~/.config/defnett-vm-lab/tokens.env` (0600); salinan di `/tmp` VM dihapus setelah cutover |
