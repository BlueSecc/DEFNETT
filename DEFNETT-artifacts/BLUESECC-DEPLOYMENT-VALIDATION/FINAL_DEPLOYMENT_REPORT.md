# Final Deployment Report — DEFNETT di laptop BlueSecc

Tanggal uji: 3 November 2026 (UTC). Keputusan di bawah adalah status validasi deployment lab, bukan `FINAL_RELEASE_READY` dan bukan klaim siap produksi.

## Keputusan

| Jalur | Keputusan |
|---|---|
| **VM (empat VirtualBox)** | **PARTIALLY_VALIDATED**: approval, TLS antarlayanan, isolasi, containment, recovery, dan alur browser lulus di runtime; OT belum |
| **Docker** | **DEPLOYMENT_BLOCKED**: daemon tidak berjalan, RAM host tidak cukup untuk Docker bersama empat VM |
| **Keseluruhan** | **PARTIALLY_VALIDATED** |

## Jawaban 20 pertanyaan

1. **Source sesuai pengembangan terbaru?** Ya. HEAD sama (`5f4f7dc`), seluruh perubahan tracked dan untracked dari zip disalin dan dicek `diff -rq`. Branch berbeda (`main` di sini, `tahap-1-policy-gate` di zip). Dataset 898 MB tidak disalin.
2. **Docker berhasil?** Tidak dijalankan (BLOCKED).
3. **Empat VM berjalan?** Ya, keempatnya aktif dengan versi persetujuan operator setelah cutover.
4. **HTTPS bekerja?** Ya, untuk Agent → Collector, Collector/Executor → Authority, Executor → Remediator, dan dashboard dari Mac (klien skrip). Browser belum diuji.
5. **Sertifikat tervalidasi?** Ya: CA lab diterima; CA tak dikenal, hostname salah, dan sertifikat kedaluwarsa (uji khusus) ditolak.
6. **Authority terpisah?** Ya: UID, database, token, dan port loopback sendiri.
7. **Collector tidak bisa menulis approval?** Ya untuk database Authority (baca dan tulis ditolak per UID). Catatan: Collector masih bisa menulis tabel lama `operator_approvals` di database bukti, tetapi Executor terbukti mengabaikannya.
8. **Executor memvalidasi approval?** Ya: klaim lewat Authority, satu kali, 6/6; tidak ada eksekusi saat Authority mati.
9. **OT gateway bekerja di deployment?** Tidak diuji (BLOCKED, gateway hanya ada di Docker).
10. **Event masuk ke Collector?** Ya: heartbeat, snapshot, dan event FIM dari kedua server (202), memicu persetujuan 6/6.
11. **Bukti terverifikasi?** Ya: rantai `ok`, 3.132 event.
12. **Trajectory dan risk bekerja?** Tidak diverifikasi di runtime VM. Unit test PASS.
13. **Dashboard browser bekerja?** Ya, setelah enam bug dashboard/collector diperbaiki: HTTPS trusted tanpa peringatan, login, Serang, Setujui, Tolak, dan logout lewat Safari lulus (lihat `TLS_VALIDATION_REPORT.md`).
14. **Containment berhasil?** Ya, 6/6: target keluar HAProxy 0,05–0,34 s setelah persetujuan, survivor tetap melayani.
15. **Recovery dan rejoin berhasil?** Ya, 6/6: kunci dipulihkan dari master yang cocok manifes, server kembali UP.
16. **Isolasi jaringan terbukti?** Sebagian besar ya, dengan uji positif dan negatif per port dan per UID. Satu celah ditemukan (aturan ufw lama ke :8091) dan sudah ditutup. Filter IP systemd per unit belum diuji langsung.
17. **Apa yang gagal?** Selama deployment: 7 bug kode/konfigurasi (lihat `SOURCE_TRANSFER_AUDIT.md`), 1 aturan firewall lama, 2 uji E2E awal (restart Authority, bug 16 KB). Semua diperbaiki dan diuji ulang.
18. **Apa yang belum diuji?** Docker seluruhnya, OT, browser HTTPS dan screenshot, trajectory/risk di runtime, approval kedaluwarsa/replay/target berubah di runtime, `master_untrusted` dan survivor tidak sehat di runtime, filter IP systemd, mTLS (tidak diimplementasikan), AI Patroli (tidak diimplementasikan).
19. **Demo kompetisi siap?** Alur VM (Serang → Setujui → isolasi → pulih) siap dan dapat diulang. Sebelum merekam, impor `ca.crt` ke browser dan uji dashboard secara manual. Jangan tampilkan OT atau AI Patroli.
20. **Risiko tersisa?** Lihat di bawah.

## Ringkasan hasil

| Area | Status | Laporan |
|---|---|---|
| Inventaris | PASS | `ENVIRONMENT_INVENTORY.md` |
| Source transfer dan secret | PASS | `SOURCE_TRANSFER_AUDIT.md` |
| Docker | BLOCKED | `DOCKER_DEPLOYMENT_REPORT.md` |
| VM cutover dan layanan | PASS | `VM_DEPLOYMENT_REPORT.md` |
| TLS dan browser | PASS (browser setelah 6 perbaikan) | `TLS_VALIDATION_REPORT.md` |
| Approval Authority | PASS (17), NOT_VERIFIED (1), NOT_RUN (3) | `APPROVAL_AUTHORITY_REPORT.md` |
| Isolasi jaringan | PASS setelah 1 perbaikan | `NETWORK_ISOLATION_REPORT.md` |
| OT | BLOCKED | `OT_E2E_REPORT.md` |
| Containment dan recovery | PASS 6/6, 506/506 HTTP 200 | `RECOVERY_E2E_REPORT.md` |
| Performa | diukur sebagian | `PERFORMANCE_REPORT.md` |
| Unit test | 94 test: 93 PASS, 1 skipped (macOS) | — |

## Risiko tersisa

- Server yang diserang tetap melayani sampai operator menyetujui (sekitar 6 detik + waktu operator). Ini pilihan desain human-in-the-loop.
- Sesi operator hilang setiap kali Authority restart, dan kunci login (5 kali gagal) dihitung bersama untuk semua operator.
- Tabel `operator_approvals` lama masih ada di database bukti dan bisa ditulis Collector.
- Collector dan Executor masih berbagi database bukti yang bisa ditulis keduanya.
- CA lab tanpa CRL/OCSP, sertifikat 90 hari, token bearer (bukan mTLS).
- Snapshot `demo-siap-2026-11-03` (VM mati, disk saja) tersedia di keempat VM. Backup konfigurasi juga ada di `/root/defnett-backup-*` tiap VM.
- Akun `uji-viewer` tertinggal di `operator_auth.json`.
- Setelah Tolak, server tetap melayani dengan kunci berubah dan tidak ada tombol untuk meminta pemulihan lagi; perlu `lab/vm/restore-kunci.sh` manual.

## Rekomendasi berikutnya

1. Ambil screenshot baru dari dashboard (CA harus dipercaya selama rekaman), lalu cabut kepercayaan CA.
2. Snapshot `demo-siap-2026-11-03` sudah dibuat di keempat VM; uji ulang dari Mac setelah reboot 30/30 PASS (`test-results/vm-checks-host-after-reboot.json`).
3. Uji Docker dan OT di laptop lain, atau setelah VM dimatikan.
4. Commit perubahan ke branch `tahap-1-policy-gate` setelah ditinjau.
