# Environment Inventory — laptop BlueSecc

Diambil 3 November 2026 (UTC). Tanpa kredensial.

## Host

| Item | Nilai |
|---|---|
| Perangkat | MacBookPro17,1, Apple M1, 8 core, RAM 8 GB |
| OS | macOS 26.6.1 (25G76), Darwin 25.6.0 arm64 |
| Repo | `/Volumes/BLUE/KARTIKA CEYBER` (drive eksternal BLUE, 347 GB bebas) |
| Python host | 3.15.0 |
| OpenSSL host | 3.6.4 |
| Docker CLI | 29.7.2; **daemon tidak berjalan** (socket `~/.docker/run/docker.sock` tidak ada) |
| VirtualBox | 7.2.22r175245 |
| Interface lab | `bridge100` 192.168.56.1/24 |
| Jaringan host-only | `defnett` (`hostonly-defnett`), 192.168.56.0/24, rentang .1–.199 |

## Topologi VM aktual

Keempat VM: Ubuntu 26.10, kernel 7.3.0-10-generic, ARM64, 1 vCPU, RAM 1.527 MB, NIC1 NAT (10.0.2.15), NIC2 host-only `defnett`. **Tidak ada snapshot** di keempat VM.

| VM | Hostname | IP lab | Peran aktual | Layanan aktif | Port mendengar |
|---|---|---|---|---|---|
| Gateway | gateway | 192.168.56.10 | Load balancer | haproxy | 22, 8080, 192.168.56.10:9999 |
| Server A | server-a | 192.168.56.11 | Backend blog | apache2, mariadb, defnett-agent, defnett-app, defnett-remediator | 22, 80, 8080, 8091, 127.0.0.1:3306 |
| Server B | server-b | 192.168.56.12 | Backend blog | apache2, mariadb, defnett-agent, defnett-app, defnett-remediator | 22, 80, 8080, 8091, 127.0.0.1:3306 |
| Collector | collector | 192.168.56.20 | Kontrol | defnett-approval-authority, defnett-executor, defnett-collector | 22, 8443, 127.0.0.1:8092, 127.0.0.1:8093 |

Peta ini sesuai `lab/vm/*/01-lab.yaml` dan runbook. Tidak ada IP atau adapter yang diubah.

## Kapasitas

Empat VM memakai sekitar 6,1 GB dari 8 GB RAM host. Ini batas utama yang menghalangi menjalankan Docker Desktop bersamaan (lihat `DOCKER_DEPLOYMENT_REPORT.md`). Detail beban per VM ada di `test-results/resources-vm.txt`.
