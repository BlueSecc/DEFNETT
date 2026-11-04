# DEFNETT VM TLS dan Approval Authority Cutover

Status dokumen: prosedur disiapkan; runtime VM belum dijalankan pada laptop ini.

## Batas pemisahan

- `defnett-approval-authority` adalah satu-satunya service yang membaca/menulis `/var/lib/defnett-approval/approvals.sqlite3`.
- Approval API hanya bind ke `127.0.0.1:8093`; Collector dan Executor memakai HTTPS dengan token service yang berbeda.
- Collector dan Executor punya UID serta primary group terpisah. Keduanya tetap menjadi anggota group bukti bersama untuk kebutuhan event/remediation lama; itu tidak memberi akses ke direktori approval.
- Berkas kredensial operator hanya dapat dibaca oleh group authority. Collector tidak mendapat group tersebut.
- Executor tetap berjalan pada VM Collector yang sama. UID dan systemd IP filter memberi pemisahan proses, tetapi ini bukan isolasi host/VM penuh dan belum runtime-verified.
- Collector menerima TLS pada 8443. Agent mengirim event melalui HTTPS. Executor menghubungi remediator melalui HTTPS. HAProxy runtime dan remediator tetap hanya mengizinkan host Collector pada firewall; rule `defnett-collector-network-guard` menolak port admin dari UID Collector selain Executor.

Ini konfigurasi lab. Token bearer internal bukan mTLS. Operator browser mempercayai CA lab secara eksplisit. Jangan gunakan CA lab ini untuk produksi.

## Sebelum cutover

1. Jadwalkan maintenance window dan hentikan Collector, Executor, serta Authority.
2. Amankan backup database bukti dan file operator yang sudah ada. Jangan hapus volume atau database.
3. Periksa approval yang masih `PENDING`, `APPROVED`, atau `CLAIMED`. Selesaikan atau tolak secara operator sebelum layanan baru aktif. Tidak ada migrasi otomatis dari tabel approval lama di database evidence; approval lama tidak boleh dieksekusi setelah cutover.
4. Simpan backup file konfigurasi dan catat timestamp serta pemiliknya.
5. Siapkan paket deployment berisi Python modules, unit systemd, script guard, dan file dashboard. Jangan masukkan private key atau token ke paket yang dilacak Git.

## CA dan certificate lab

Di workstation administrasi yang dipercaya, jalankan:

```sh
umask 077
sh lab/provision-lab-tls.sh "$HOME/.config/defnett-vm-lab/tls"
```

Skrip menghasilkan CA privat serta certificate berikut: `collector-vm`, `executor-vm`, `approval-authority`, `remediator-a-vm`, dan `remediator-b-vm`. Certificate VM mencakup alamat host-only yang dikonfigurasi pada `lab/vm/*/01-lab.yaml`. Jangan menyalin `ca.key` ke VM.

Salin `ca.crt` ke setiap VM sebagai `/etc/defnett/tls/ca.crt`. Salin hanya pasangan yang dibutuhkan setiap host:

| Host | Certificate dan private key |
|---|---|
| Collector | `collector-vm.crt`, `collector-vm.key`, `executor-vm.crt`, `executor-vm.key`, `approval-authority.crt`, `approval-authority.key` |
| Server A | `remediator-a-vm.crt`, `remediator-a-vm.key` |
| Server B | `remediator-b-vm.crt`, `remediator-b-vm.key` |

Atur pemilik certificate root dan mode 0644. Atur key root-owned, mode 0640, dengan group masing-masing service (`defnett-collector`, `defnett-executor`, `defnett-approval`, `defnett`). Jalankan `provision-service-users.sh` di Collector setelah file ada; script memeriksa file biasa, mode, dan kepemilikan. Gunakan transfer yang terlindungi dan hapus staging copy secara manual setelah verifikasi. Private key CA hanya untuk issuance lab; rotasi dilakukan dengan CA/folder baru dan penggantian terkoordinasi seluruh leaf/trust store. Tidak ada CRL/OCSP pada lab ini.

## Token dan konfigurasi authority

Buat dua secret acak yang berbeda menggunakan sumber randomness yang disetujui tim. Set nilai yang sama untuk token Collector pada `collector.env` dan `approval-authority.env`; lakukan hal serupa secara terpisah untuk token Executor. Jangan gunakan `EXECUTOR_API_TOKEN` sebagai token authority. File di `/etc/defnett/approval-authority.env` harus root-owned dan hanya dapat dibaca oleh `defnett-approval`; `executor.env` root-only; `collector.env` root-owned dan hanya dapat dibaca Collector.

Operator auth file berada di `/etc/defnett/operator_auth.json`, owner root, group `defnett-approval-auth`, mode 0640. Jalankan `provision-service-users.sh` sebagai root setelah persiapan; ia menolak jika service berjalan atau TLS/config penting tidak ada. Script hanya mengubah metadata akses pada database yang sudah ada; tidak menghapus konten.

## Instalasi dan startup

1. Pasang source dan unit memakai prosedur deployment tim. Pastikan `/opt/defnett/approval_authority.py`, `authority_client.py`, `tls_support.py`, `approvals.py`, `db.py`, dan `operator_auth.py` tersedia.
2. Pasang tiga unit dari `lab/vm/collector/defnett-units/` ke `/etc/systemd/system/`.
3. Validasi konfigurasi sebelum restart: `systemd-analyze verify defnett-approval-authority.service defnett-executor.service defnett-collector.service`.
4. Jalankan provisioning permission; kemudian `systemctl daemon-reload`.
5. Enable/start berurutan: Approval Authority, Executor, Collector. Verifikasi masing-masing `systemctl is-active` dan log tanpa token/secret.
6. Uji `https://192.168.56.20:8443/healthz` dari host admin dengan CA lab, dan tolak koneksi ketika CA tidak diberikan atau host tidak cocok.
7. Impor `ca.crt` sebagai trust anchor pada browser khusus lab, lalu akses dashboard HTTPS. Cookie harus memuat `Secure`, `HttpOnly`, dan `SameSite=Strict`.
8. Uji event dari Agent A/B, authority login/approval, Executor, containment, recovery, hash, health check, dan rejoin. Uji juga koneksi negatif sesuai checklist deployment.

Jangan membuka firewall ke jaringan lain untuk mengatasi kegagalan TLS atau connectivity. Rollback berarti stop service baru dan pulihkan file konfigurasi/unit dari backup; jangan menghapus database authority atau database evidence. Approval lama tidak dipindahkan otomatis.

## Hasil yang wajib dicatat saat uji

Catat command, timestamp UTC, hostname/UID, target dan source, hasil aktual, sertifikat/CA yang diuji, serta log aktual. Koneksi positif dan negatif harus diuji dari Collector sebagai UID `defnett-collector`, Executor sebagai UID `defnett-executor`, browser host, dan VM lain yang tidak berwenang. Sampai pengujian itu dijalankan, VM isolation, HTTPS browser, dan VM E2E berstatus `NOT_RUN`.
