# Panduan Instalasi DEFNETT

Ada dua cara memasang DEFNETT. Pilih salah satu:

| Cara | Cocok untuk | Waktu | Fitur |
|---|---|---|---|
| [A. Docker](#a-instalasi-dengan-docker) | Mencoba cepat di satu komputer | ±15 menit | Dashboard, Patrol (satu pintu), persetujuan operator, SERANG!. Tanpa WordPress dan tanpa tab Terminal |
| [B. Empat VM VirtualBox](#b-instalasi-di-empat-vm-virtualbox) | Demo lengkap seperti di video | ±2–3 jam | Semua fitur: blog WordPress di dua server, pintu per port, isolasi HAProxy sungguhan, tab Terminal |

Semua perintah di bawah dijalankan dari folder repositori, kecuali disebut lain. Baris yang diawali `<...>` harus diganti dengan nilai Anda sendiri.

---

## A. Instalasi dengan Docker

### A1. Yang dibutuhkan

- Docker Desktop (macOS/Windows) atau Docker Engine (Linux) dengan **Docker Compose v2** (`docker compose version` harus berhasil).
- `git`, `python3`, dan `openssl`.
- RAM bebas sekitar 4 GB.

### A2. Unduh repositori

```bash
git clone https://github.com/BlueSecc/DEFNETT.git
```

```bash
cd DEFNETT
```

### A3. Jalankan skrip pemasangan

Pastikan Docker sudah berjalan, lalu:

```bash
sh lab/build.sh
```

Skrip ini:

1. membuat CA dan sertifikat lab di `~/.config/defnett-lab/tls` (di luar repositori);
2. membuat token antarlayanan acak;
3. membangun dan menyalakan semua container;
4. membuat akun operator `admin` dan **mencetak kata sandinya sekali saja**. Catat kata sandi ini;
5. mengisi data contoh dan trust anchor (salinan master kunci).

### A4. Percayai sertifikat CA lab di browser

Dashboard memakai HTTPS dengan CA buatan sendiri, jadi browser harus mempercayainya. Lihat [Mempercayai CA lab](#mempercayai-ca-lab) dan gunakan berkas `~/.config/defnett-lab/tls/ca.crt`.

### A5. Buka dashboard

Buka `https://127.0.0.1:8443/`, klik **Masuk operator**, lalu masuk dengan `admin` dan kata sandi dari langkah A3. Lanjutkan ke [Petunjuk penggunaan](../README.md#petunjuk-penggunaan).

### A6. Menghentikan dan menyalakan lagi

Menghentikan lab (data tetap tersimpan):

```bash
docker compose -f lab/compose.yaml -f lab/compose.canary.yaml down
```

Menyalakan lagi:

```bash
sh lab/build.sh
```

Akun operator yang sudah ada tidak dibuat ulang. Untuk menghapus seluruh data dan memulai dari nol, tambahkan `-v` pada perintah `down`. Ini menghapus database bukti dan akun operator secara permanen.

---

## B. Instalasi di empat VM VirtualBox

Hasil akhirnya:

| VM | Hostname | IP host-only | Isi |
|---|---|---|---|
| Gateway | `gateway` | `192.168.56.10` | HAProxy, situs di port 8080 |
| Server A | `server-a` | `192.168.56.11` | Blog WordPress, app, agent, remediator |
| Server B | `server-b` | `192.168.56.12` | Blog WordPress, app, agent, remediator |
| Collector | `collector` | `192.168.56.20` | Dashboard HTTPS 8443, Approval Authority, Executor |
| Laptop (host) | – | `192.168.56.1` | Browser operator dan tempat menjalankan skrip deploy |

Urutan kerjanya:

1. siapkan laptop;
2. buat jaringan dan empat VM;
3. siapkan dasar tiap VM;
4. pasang Gateway, Server A/B, dan Collector;
5. jalankan *cutover* (TLS, token, akun operator);
6. verifikasi.

### B1. Yang dibutuhkan

- VirtualBox 7.x.
- RAM laptop minimal 8 GB. Keempat VM memakai sekitar 6 GB.
- ISO **Ubuntu Server**: ARM64 untuk Mac Apple Silicon, AMD64 untuk laptop Intel/AMD. Lab ini diuji dengan Ubuntu 26.10 ARM64.
- Di laptop: `git`, `python3`, `openssl`, `ssh`, dan `scp`.
- Koneksi internet untuk VM (lewat adapter NAT) selama instalasi paket.

### B2. Siapkan laptop

Unduh repositori:

```bash
git clone https://github.com/BlueSecc/DEFNETT.git
```

```bash
cd DEFNETT
```

Buat CA dan sertifikat lab untuk VM. Folder ini berisi kunci privat, jadi jangan pernah di-commit:

```bash
sh lab/provision-lab-tls.sh "$HOME/.config/defnett-vm-lab/tls"
```

Buat tiga token antarlayanan untuk Collector:

```bash
python3 -c 'import secrets; [print(f"{k}={secrets.token_urlsafe(32)}") for k in ("EXECUTOR_API_TOKEN","APPROVAL_COLLECTOR_TOKEN","APPROVAL_EXECUTOR_TOKEN")]' > "$HOME/.config/defnett-vm-lab/tokens.env"
```

Buat satu token lagi, `LAB_API_TOKEN`, yang dipakai bersama oleh agent, remediator, dan Collector. Tampilkan, lalu simpan nilainya karena akan diisikan ke tiga VM:

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
```

### B3. Buat jaringan host-only

Di VirtualBox, buka **File → Tools → Network Manager → Host-only Networks → Create**, lalu isi:

- Nama: `defnett`
- Alamat host / lower bound: `192.168.56.1`, netmask `255.255.255.0`
- DHCP: **mati** (IP VM diatur statis)

Pastikan laptop mendapat alamat `192.168.56.1` di jaringan itu.

### B4. Buat empat VM

Buat empat VM dengan nama Gateway, Server A, Server B, dan Collector. Setelan tiap VM:

| Setelan | Nilai |
|---|---|
| CPU / RAM / Disk | 1 vCPU, 1,5 GB, 10 GB |
| Adapter 1 | NAT (untuk internet saat instalasi) |
| Adapter 2 | Host-only, jaringan `defnett` |

Pasang Ubuntu Server di tiap VM dengan pilihan **Install OpenSSH server**. Pakai username yang sama di keempat VM. Skrip repo memakai `malas` sebagai bawaan; bila berbeda, tambahkan `VM_USER=<username>` saat menjalankan `cutover-stage.sh`, dan sesuaikan alamat `malas@...` di skrip deploy.

### B5. Persiapan dasar di setiap VM

Lakukan langkah ini di keempat VM. Login ke konsol VM, lalu set `ROLE` sesuai VM: `gateway`, `server-a`, `server-b`, atau `collector`.

```bash
ROLE=server-a
```

Pasang alat dasar dan unduh repositori:

```bash
sudo apt update && sudo apt install -y git python3 ufw
```

```bash
git clone https://github.com/BlueSecc/DEFNETT.git ~/DEFNETT && cd ~/DEFNETT
```

Set hostname dan daftar host:

```bash
sudo hostnamectl set-hostname "$ROLE"
```

```bash
sudo cp "lab/vm/$ROLE/hosts" /etc/hosts
```

Atur IP statis host-only. Lihat dulu nama interface dengan `ip link`. Adapter 2 biasanya interface kedua, misalnya `enp0s8` atau `enp0s9`. Salin berkas netplan, lalu sesuaikan nama interface di dalamnya bila berbeda:

```bash
sudo cp "lab/vm/$ROLE/01-lab.yaml" /etc/netplan/01-lab.yaml && sudo chmod 600 /etc/netplan/01-lab.yaml
```

```bash
sudo nano /etc/netplan/01-lab.yaml
```

```bash
sudo netplan apply
```

Cek bahwa IP sudah benar, misalnya `192.168.56.11` untuk Server A:

```bash
ip -br addr
```

Sejak titik ini, VM bisa diakses dari laptop dengan `ssh <username>@<IP>`, dan sisa langkah boleh dijalankan lewat SSH.

### B6. Gateway (`192.168.56.10`)

```bash
sudo apt install -y haproxy
```

```bash
sudo cp lab/vm/gateway/haproxy.cfg /etc/haproxy/haproxy.cfg
```

```bash
sudo mkdir -p /etc/systemd/system/haproxy.service.d && sudo cp lab/vm/gateway/haproxy.service.d/override.conf /etc/systemd/system/haproxy.service.d/
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now haproxy && sudo systemctl restart haproxy
```

Pasang firewall:

```bash
sudo bash lab/vm/gateway/ufw.sh
```

### B7. Server A dan Server B (`192.168.56.11`, `192.168.56.12`)

Jalankan di kedua server dengan `ROLE=server-a` atau `ROLE=server-b`.

**1. Paket web dan database**

```bash
sudo apt install -y apache2 mariadb-server php libapache2-mod-php php-mysql wget
```

**2. Blog WordPress 5.0**

Versi lama ini dipakai dengan sengaja sebagai target lab. Unduh dan pasang:

```bash
cd /tmp && wget https://wordpress.org/wordpress-5.0.tar.gz && tar xzf wordpress-5.0.tar.gz
```

```bash
sudo rm -f /var/www/html/index.html && sudo cp -r /tmp/wordpress/* /var/www/html/ && sudo chown -R www-data:www-data /var/www/html
```

Buat database WordPress. Ganti `<sandi-db>` dengan kata sandi Anda:

```bash
sudo mysql -e "CREATE DATABASE wordpress; CREATE USER 'wp'@'localhost' IDENTIFIED BY '<sandi-db>'; GRANT ALL ON wordpress.* TO 'wp'@'localhost'; FLUSH PRIVILEGES;"
```

Dari browser laptop, buka `http://192.168.56.11/` (atau `.12`) dan selesaikan wizard WordPress:

- database `wordpress`, user `wp`, sandi `<sandi-db>`, host `localhost`;
- isi **Site Title** dengan `SERVER A` atau `SERVER B`, supaya terlihat server mana yang menjawab.

Kembali ke VM, lalu perbaiki beranda WordPress 5.0 yang rusak di PHP 8:

```bash
cd ~/DEFNETT && sudo sh lab/vm/fix-wp-php8-home.sh
```

Buat halaman health check yang dipakai HAProxy:

```bash
echo ok | sudo tee /var/www/html/healthz
```

**3. Akun dan folder DEFNETT**

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin defnett
```

```bash
sudo install -d -o root -g defnett -m 0755 /opt/defnett /etc/defnett && sudo install -d -o defnett -g defnett /data /state "/quarantine/$ROLE"
```

**4. Data contoh (termasuk file kunci)**

```bash
sudo sh lab/seed-fs.sh "$ROLE" && sudo chown -R defnett:defnett /data
```

**5. Program, konfigurasi, dan layanan**

```bash
sudo cp lab/agent.py lab/app.py lab/remediator.py lab/tls_support.py lab/provision_master.py /opt/defnett/
```

```bash
sudo cp "lab/vm/$ROLE/$ROLE.env" "/etc/defnett/$ROLE.env"
```

Tambahkan `LAB_API_TOKEN` dari langkah B2. Nilainya harus sama di Server A, Server B, dan Collector:

```bash
echo 'LAB_API_TOKEN=<token-dari-B2>' | sudo tee -a "/etc/defnett/$ROLE.env"
```

```bash
sudo cp lab/vm/$ROLE/defnett-units/*.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable defnett-agent defnett-app defnett-remediator
```

Layanan baru dinyalakan oleh *cutover* di langkah B9, setelah sertifikat terpasang.

**6. Firewall**

```bash
sudo bash "lab/vm/$ROLE/ufw.sh"
```

### B8. Collector (`192.168.56.20`)

```bash
sudo apt install -y openssh-client util-linux
```

```bash
sudo install -d -m 0755 /opt/defnett /opt/defnett/dashboard /etc/defnett && sudo install -d -m 2770 /evidence
```

Isi `LAB_API_TOKEN` yang sama dengan langkah B7:

```bash
echo 'LAB_API_TOKEN=<token-dari-B2>' | sudo tee /etc/defnett/collector.env
```

```bash
sudo bash lab/vm/collector/ufw.sh
```

### B9. Cutover: sertifikat, token, dan akun operator

Dari **laptop** (folder repositori), kirim paket ke ketiga VM. Ganti username bila bukan `malas`:

```bash
VM_USER=malas sh lab/vm/cutover-stage.sh
```

Lalu jalankan di tiap VM, **berurutan: Server A, Server B, baru Collector**:

```bash
sudo sh /tmp/defnett-cutover/cutover-vm.sh
```

Yang dilakukan skrip ini:

- **Cadangan:** menyimpan konfigurasi lama ke `/root/defnett-backup-<waktu>`.
- **Server A/B:** memasang sertifikat, membuat salinan master kunci beserta manifes sha256, lalu menyalakan agent, app, dan remediator.
- **Collector:**
  - memasang semua modul dan sertifikat;
  - membuat akun layanan terpisah (`defnett-collector`, `defnett-executor`, `defnett-approval`);
  - meminta Anda membuat **kata sandi akun operator `admin`** (minimal 12 karakter);
  - menyalakan Approval Authority, Executor, lalu Collector.

### B10. Percayai CA dan buka dashboard

Percayai `~/.config/defnett-vm-lab/tls/ca.crt` di laptop (lihat [Mempercayai CA lab](#mempercayai-ca-lab)), lalu buka `https://192.168.56.20:8443/` dan masuk sebagai `admin`.

### B11. Verifikasi

Jalankan dari laptop.

Collector menjawab lewat HTTPS dengan CA lab:

```bash
curl --cacert "$HOME/.config/defnett-vm-lab/tls/ca.crt" https://192.168.56.20:8443/healthz
```

Situs dilayani bergantian oleh kedua server. Jalankan beberapa kali dan lihat judulnya berganti:

```bash
curl -s http://192.168.56.10:8080/ | grep -o '<title>[^<]*'
```

Di dashboard:

1. **Overview:** semua node dan kabel hijau.
2. **Patrol:** tiap server menampilkan pintu `22`, `80`, `8080`, dan `8091`.
3. **SERANG!** ke Server A, lalu **Setujui** di **Detail → Playbook**: Server A diisolasi, pulih, dan kembali online.
4. **Terminal:** login ke Server A dengan username dan password VM.

Status layanan di VM bisa dicek dengan:

```bash
systemctl status 'defnett-*' --no-pager
```

### B12. Memperbarui setelah kode berubah

| Yang berubah | Perintah dari laptop |
|---|---|
| Hanya file `lab/dashboard/` | `sh lab/vm/deploy-dashboard.sh` |
| `collector.py`, `web_terminal.py`, atau dashboard | `SKIP_FIREWALL=1 sh lab/vm/deploy-terminal.sh` |
| Banyak modul sekaligus | Ulangi langkah B9 (`cutover-stage.sh`, lalu `cutover-vm.sh` di tiap VM) |

---

## Mempercayai CA lab

CA ini hanya untuk lab. Jangan dipakai untuk situs lain, dan hapus dari daftar tepercaya bila lab tidak dipakai lagi.

**macOS** (Safari dan Chrome). Ganti path sesuai cara instalasi (`defnett-lab` untuk Docker, `defnett-vm-lab` untuk VM):

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$HOME/.config/defnett-vm-lab/tls/ca.crt"
```

**Linux** (Chrome dan aplikasi sistem):

```bash
sudo cp "$HOME/.config/defnett-vm-lab/tls/ca.crt" /usr/local/share/ca-certificates/defnett-lab.crt && sudo update-ca-certificates
```

**Windows:** klik ganda `ca.crt` → **Install Certificate** → **Local Machine** → **Trusted Root Certification Authorities**.

**Firefox** memakai daftar sendiri: **Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import**, pilih `ca.crt`, lalu centang *Trust this CA to identify websites*.

Tutup dan buka lagi browser setelah mengimpor.

---

## Masalah saat instalasi

| Gejala | Penyebab umum | Solusi |
|---|---|---|
| `docker compose` tidak dikenal | Compose v2 belum terpasang | Pasang Docker Desktop terbaru atau plugin `docker-compose-plugin` |
| Browser: "Your connection is not private" | CA lab belum dipercaya | Lihat [Mempercayai CA lab](#mempercayai-ca-lab) |
| VM tidak bisa di-ping dari laptop | Adapter 2 bukan host-only `defnett`, atau nama interface di netplan salah | Cek setelan VM dan `ip link`, perbaiki `/etc/netplan/01-lab.yaml`, jalankan `sudo netplan apply` |
| HAProxy menandai server DOWN | `/healthz` tidak ada atau port 80 diblok | Ulangi `echo ok \| sudo tee /var/www/html/healthz` dan `sudo bash lab/vm/<role>/ufw.sh` |
| `cutover-stage.sh`: "token belum ada" | `tokens.env` belum dibuat | Ulangi langkah B2 |
| `cutover-vm.sh`: "LAB_API_TOKEN hilang/tidak ada" | Token belum diisi di env | Ulangi pengisian `LAB_API_TOKEN` di langkah B7/B8 |
| Agent tidak mengirim event | `LAB_API_TOKEN` berbeda antar VM | Samakan nilainya di ketiga VM, lalu `sudo systemctl restart defnett-agent` |
| Lupa kata sandi operator | – | Lihat [Mengganti kata sandi operator](#mengganti-kata-sandi-operator-vm) |

### Mengganti kata sandi operator (VM)

Jalankan di Collector. Layanan harus dihentikan dulu, karena skrip izin menolak berjalan saat layanan aktif:

```bash
sudo systemctl stop defnett-collector defnett-executor defnett-approval-authority
```

Buat ulang akun `admin` dengan kata sandi baru (minimal 12 karakter):

```bash
sudo python3 /opt/defnett/provision_operators.py --file /etc/defnett/operator_auth.json --add admin --role operator --force
```

Kembalikan izin berkas, lalu nyalakan lagi berurutan:

```bash
sudo /usr/local/sbin/defnett-provision-service-users
```

```bash
sudo systemctl start defnett-approval-authority defnett-executor defnett-collector
```

Untuk masalah saat lab sudah berjalan, lihat [Pemecahan masalah](../README.md#pemecahan-masalah) di README.
