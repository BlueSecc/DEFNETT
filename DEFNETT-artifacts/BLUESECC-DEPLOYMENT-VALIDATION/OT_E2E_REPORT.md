# OT E2E Report

**Status: BLOCKED pada laptop ini.**

Gateway Modbus (`lab/modbus_lab.py`) hanya dipasang di jalur Docker Compose. Keempat VM tidak menjalankan gateway OT, dan Docker tidak bisa dijalankan bersamaan dengan empat VM (RAM 8 GB).

| Test ID | Test | Expected | Actual | Status |
|---|---|---|---|---|
| OT-01 | FC03 read diizinkan | ALLOW, event masuk | tidak dijalankan | NOT_RUN |
| OT-02 | FC06 write diizinkan | ALLOW | tidak dijalankan | NOT_RUN |
| OT-03 | FC06 write tidak diizinkan | DENY, register tetap | tidak dijalankan | NOT_RUN |
| OT-04 | Frame rusak / fungsi tidak didukung | ditolak aman | tidak dijalankan | NOT_RUN |
| OT-05 | Sumber tidak di allowlist | ditolak | dilewati di unit test macOS (butuh 127.0.0.2) | NOT_RUN |

Unit test OT di loopback (FC03/FC06, duplikat, frame rusak, fungsi tidak didukung) PASS di macOS, kecuali uji sumber tidak dikenal yang dilewati. Itu bukan bukti runtime deployment.

Yang tidak boleh diklaim: integrasi PLC produksi, gateway sebagai passive IDS, atau telemetri OT live.

Untuk membuka blocker: jalankan Docker (lihat `DOCKER_DEPLOYMENT_REPORT.md`), atau pasang `modbus_lab.py` sebagai unit di salah satu VM.
