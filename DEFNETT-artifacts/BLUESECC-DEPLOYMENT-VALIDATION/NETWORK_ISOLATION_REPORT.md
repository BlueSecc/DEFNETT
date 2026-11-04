# Network Isolation Report (VM)

Positif dan negatif diuji dengan koneksi TCP ke port aplikasi, bukan ping. Uji per UID memakai `sudo -u` di Collector, sehingga menguji guard iptables owner-match (`defnett-collector-network-guard`), bukan filter IP systemd milik unit.

| Test ID | Dari | Ke | Expected | Actual | Status |
|---|---|---|---|---|---|
| NET-01 | Host .1 | Authority :8093 | tertutup | timeout (difilter) | PASS |
| NET-02 | Host .1 | Executor :8092 | tertutup | timeout | PASS |
| NET-03 | Host .1 | HAProxy runtime :9999 | tertutup | timeout | PASS |
| NET-04 | Host .1 | Remediator A :8091 | tertutup | **terbuka** (aturan ufw lama), lalu timeout setelah perbaikan | PASS setelah perbaikan |
| NET-05 | Host .1 | Remediator B :8091 | tertutup | **terbuka**, lalu timeout setelah perbaikan | PASS setelah perbaikan |
| NET-06 | Host .1 | Blog HAProxy :8080 | terbuka | terbuka | PASS |
| ISO-01..03 | Collector, user biasa | HAProxy :9999, Remediator A/B :8091 | ditolak | refused (iptables REJECT) | PASS |
| UID-01..03 | Collector, UID `defnett-collector` | HAProxy :9999, Remediator A/B :8091 | ditolak | ditolak | PASS |
| UID-04..06 | Collector, UID `defnett-executor` | HAProxy :9999, Remediator A/B :8091 | terbuka | terbuka | PASS |
| UID-07 | Collector, UID `defnett-collector` | Authority :8093 | terbuka | terbuka | PASS |
| ISO-04, ISO-06 | Server A ↔ Server B | Remediator :8091 (lateral) | tertutup | timeout | PASS |
| ISO-05 | Server A | HAProxy :9999 | tertutup | timeout | PASS |
| ISO-07 | Server A | Authority :8093 | tertutup | timeout | PASS |
| ISO-08 | Server A | Collector :8443 (telemetri) | terbuka | terbuka | PASS |
| GW-01, GW-02 | ufw Gateway | :9999 | hanya .20 | hanya .20 | PASS |
| FW-01 | ufw Server A/B | :8091 dari .1 | tidak ada | dihapus | PASS |

Evidence: `test-results/vm-checks-host.json`, `test-results/vm-checks-root-*.txt`.

## Temuan dan perbaikan

Kedua server masih punya aturan ufw `allow from 192.168.56.1 to any port 8091` dari tahap 0, padahal repo sudah menghapusnya. Remediator tetap menolak tanpa token (401), tetapi port kontrol tidak seharusnya terbuka ke host admin. Aturan dihapus dengan `ufw delete`; tidak ada aturan lain yang diubah.

## Belum diuji

- Filter `IPAddressDeny`/`IPAddressAllow` systemd per unit tidak diuji langsung (uji `sudo -u` berjalan di luar cgroup unit).
- Dashboard 8443 terbuka untuk .1, .11, .12. Server A/B bisa membuka halaman login dashboard; itu konsekuensi telemetri lewat port yang sama.
- Port 80 dan 8080 server (HTTP) terbuka untuk jaringan lab sesuai desain demo.
