# Docker Deployment Report

**Status: BLOCKED. Tidak dijalankan.**

| Test ID | Test | Expected | Actual | Status | Evidence |
|---|---|---|---|---|---|
| DK-01 | Docker CLI tersedia | ada | 29.7.2 | PASS | `ENVIRONMENT_INVENTORY.md` |
| DK-02 | Docker daemon | berjalan | socket tidak ada, daemon mati | BLOCKED | `docker info` |
| DK-03 | Build dan startup | PASS | tidak dijalankan | NOT_RUN | — |
| DK-04 | Health dan isolasi Compose runtime | PASS | tidak dijalankan | NOT_RUN | — |
| DK-05 | OT, approval, containment, recovery di Docker | PASS | tidak dijalankan | NOT_RUN | — |

## Alasan

Empat VM sudah memakai sekitar 6,1 GB dari 8 GB RAM host. Menyalakan Docker Desktop bersamaan berisiko membuat host dan VM kehabisan memori di tengah uji VM. Izin Docker socket tidak diubah.

## Langkah untuk membuka blocker

1. Matikan keempat VM dengan rapi (`VBoxManage controlvm <nama> acpipowerbutton`), atau jalankan uji Docker di laptop lain.
2. Nyalakan Docker Desktop.
3. `sh lab/build.sh`, lalu `sh lab/test-containment.sh`.
4. Catat hasilnya terpisah dari hasil VM.

Konfigurasi Compose base dan canary hanya divalidasi statis oleh tim pengembang (`docker compose config --quiet`). Itu bukan bukti runtime.
