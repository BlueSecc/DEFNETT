# Deployment Checklist — VM lab

| Langkah | Perintah | Status 3 Nov 2026 |
|---|---|---|
| CA dan sertifikat lab (Mac) | `sh lab/provision-lab-tls.sh ~/.config/defnett-vm-lab/tls` | selesai |
| Token layanan (Mac) | tiga token acak di `~/.config/defnett-vm-lab/tokens.env` (0600) | selesai |
| Muat SSH key | `ssh-add ~/.ssh/id_ed25519` | tiap sesi |
| Kirim paket | `sh lab/vm/cutover-stage.sh` | selesai |
| Cutover Server A, Server B, Collector (urut) | `ssh -t malas@<ip> 'sudo sh /tmp/defnett-cutover/cutover-vm.sh'` | selesai |
| Pemeriksaan root tiap VM | `ssh -t malas@<ip> 'sudo sh /tmp/defnett-checks.sh'` | selesai |
| Uji dari Mac | `python3 lab/vm/vm-checks-host.py --out <file>` | selesai |
| Uji E2E | `python3 lab/vm/e2e-approval.py --out <file>` | 6/6 PASS |
| Uji fail-safe Authority (setelah E2E) | `ssh -t malas@192.168.56.20 'sudo sh /tmp/defnett-checks.sh --failsafe'` | PASS |
| Browser HTTPS (login, Serang, Setujui, Tolak, logout lulus 3 Nov 20:07 UTC) | `security add-trusted-cert -r trustRoot -p ssl -k ~/Library/Keychains/login.keychain-db ~/.config/defnett-vm-lab/tls/ca.crt`, buka `https://192.168.56.20:8443/`; cabut setelah demo dengan `security remove-trusted-cert ~/.config/defnett-vm-lab/tls/ca.crt` | halaman trusted PASS; login browser belum |
| Snapshot VM (saat mati) | `sudo poweroff`, lalu `VBoxManage snapshot <vm> take demo-siap-2026-11-03`, lalu `VBoxManage startvm <vm> --type headless` | selesai, keempat VM |

## Reset demo

- Kembali ke titik siap demo: matikan VM, `VBoxManage snapshot <vm> restore demo-siap-2026-11-03`, nyalakan lagi. Urutan nyala: Gateway, Server A, Server B, Collector.
- Snapshot live tidak dipakai: dengan empat VM menyala, RAM Mac penuh dan snapshot live berjalan sekitar 3 MB per menit.
- Tombol power ACPI tidak mematikan VM ini; pakai `sudo poweroff` dari dalam VM.

- Setelah Tolak, kunci tetap berubah dan Serang ditolak `key_not_pristine`: `scp lab/vm/restore-kunci.sh malas@<ip>:/tmp/` lalu `ssh -t malas@<ip> 'sudo sh /tmp/restore-kunci.sh'`.
- Server terisolasi tidak kembali: tekan **Jalankan** pada persetujuan yang APPROVED, atau ajukan Rejoin dari dashboard.
- Sesi hilang setelah Authority restart: login ulang.
- Rollback cutover: salin balik `/root/defnett-backup-<waktu>` lalu restart layanan.
