#!/bin/sh
# DEFNETT lab - uji isolasi per UID layanan dan perbaikan firewall kecil. Jalankan sebagai root.
# Peran dibaca dari hostname. Tidak mencetak token, kata sandi, atau isi kunci.
# Hasil ditulis ke /tmp/defnett-checks-<host>.txt (dapat dibaca user SSH untuk diarsipkan).
# Collector: python3 tersedia; opsi --pasang memasang collector.py dan authority_client.py
#            dari /tmp/defnett-cutover lalu me-restart executor dan collector (bukan authority).
# Collector: opsi --failsafe menghentikan Approval Authority sebentar untuk uji fail-safe,
#            lalu menyalakannya lagi. Semua sesi login hilang; jalankan setelah uji E2E.
set -u

ROLE="$(hostname)"
OUT="/tmp/defnett-checks-$ROLE.txt"
PASS=0
FAIL=0
: > "$OUT"
chmod 0644 "$OUT"

log() { printf '%s\n' "$*" | tee -a "$OUT"; }

check() {
  # check ID "nama" expected actual
  if [ "$3" = "$4" ]; then _st=PASS; PASS=$((PASS + 1)); else _st=FAIL; FAIL=$((FAIL + 1)); fi
  log "$1 $_st  $2 | expected=$3 actual=$4"
}

as_uid_connect() {
  sudo -u "$1" python3 -c '
import socket, sys
try:
    socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=3).close(); print("TERHUBUNG")
except socket.timeout: print("TIMEOUT")
except ConnectionRefusedError: print("DITOLAK")
except OSError as e: print(type(e).__name__)' "$2" "$3"
}

as_uid_read() {
  if sudo -u "$1" head -c 1 "$2" >/dev/null 2>&1; then echo BISA; else echo DITOLAK; fi
}

as_uid_write_dir() {
  if sudo -u "$1" sh -c "touch '$2/.defnett-uji-tulis' 2>/dev/null"; then rm -f "$2/.defnett-uji-tulis"; echo BISA; else echo DITOLAK; fi
}

log "== $ROLE $(date -u +%Y-%m-%dT%H:%M:%SZ)"

case "$ROLE" in
  collector)
    if [ "${1:-}" = "--pasang" ]; then
      install -m 0644 -o root -g root /tmp/defnett-cutover/collector.py /tmp/defnett-cutover/authority_client.py /opt/defnett/
      systemctl restart defnett-executor defnett-collector
      sleep 3
      log "pasang perbaikan: executor=$(systemctl is-active defnett-executor) collector=$(systemctl is-active defnett-collector)"
    fi

    if [ "${1:-}" = "--failsafe" ]; then
      systemctl stop defnett-approval-authority
      sleep 1
      code=$(curl -s --resolve collector:8443:127.0.0.1 -o /dev/null -w '%{http_code}' --cacert /etc/defnett/tls/ca.crt \
        -H 'Content-Type: application/json' -d '{"username":"admin","password":"bukan-kata-sandi-asli"}' \
        https://collector:8443/v1/operator/login)
      check FS-01 "Login saat Authority mati (fail-closed)" 503 "$code"
      code=$(curl -s --resolve collector:8443:127.0.0.1 -o /dev/null -w '%{http_code}' --cacert /etc/defnett/tls/ca.crt -X POST \
        https://collector:8443/v1/lab/attack/server-a?vector=ssh)
      check FS-02 "Serang saat Authority mati" 401 "$code"
      sleep 3
      executor_log=$(journalctl -u defnett-executor --since "-10s" --no-pager | grep -ciE 'error|unavailable|refused|failed')
      log "FS-03 INFO  Executor mencatat $executor_log baris galat klaim saat Authority mati (tidak ada eksekusi)"
      systemctl start defnett-approval-authority
      sleep 2
      check FS-04 "Authority menyala kembali" active "$(systemctl is-active defnett-approval-authority)"
      log "== selesai: PASS=$PASS FAIL=$FAIL, hasil di $OUT"
      exit 0
    fi

    for unit in defnett-approval-authority defnett-executor defnett-collector; do
      log "UNIT $unit user=$(systemctl show -p User --value $unit) group=$(systemctl show -p Group --value $unit) aktif=$(systemctl is-active $unit) enabled=$(systemctl is-enabled $unit)"
    done
    systemd-analyze verify defnett-approval-authority.service defnett-executor.service defnett-collector.service \
      >/tmp/defnett-verify.txt 2>&1
    check SYS-01 "systemd-analyze verify tiga unit Collector" 0 "$?"

    check UID-01 "defnett-collector -> HAProxy runtime :9999" DITOLAK "$(as_uid_connect defnett-collector 192.168.56.10 9999)"
    check UID-02 "defnett-collector -> Remediator A :8091" DITOLAK "$(as_uid_connect defnett-collector 192.168.56.11 8091)"
    check UID-03 "defnett-collector -> Remediator B :8091" DITOLAK "$(as_uid_connect defnett-collector 192.168.56.12 8091)"
    check UID-04 "defnett-executor -> HAProxy runtime :9999" TERHUBUNG "$(as_uid_connect defnett-executor 192.168.56.10 9999)"
    check UID-05 "defnett-executor -> Remediator A :8091" TERHUBUNG "$(as_uid_connect defnett-executor 192.168.56.11 8091)"
    check UID-06 "defnett-executor -> Remediator B :8091" TERHUBUNG "$(as_uid_connect defnett-executor 192.168.56.12 8091)"
    check UID-07 "defnett-collector -> Approval Authority :8093" TERHUBUNG "$(as_uid_connect defnett-collector 127.0.0.1 8093)"
    check UID-08 "defnett-collector baca database Authority" DITOLAK "$(as_uid_read defnett-collector /var/lib/defnett-approval/approvals.sqlite3)"
    check UID-09 "defnett-collector tulis direktori database Authority" DITOLAK "$(as_uid_write_dir defnett-collector /var/lib/defnett-approval)"
    check UID-10 "defnett-executor baca database Authority" DITOLAK "$(as_uid_read defnett-executor /var/lib/defnett-approval/approvals.sqlite3)"
    check UID-11 "defnett-collector baca akun operator" DITOLAK "$(as_uid_read defnett-collector /etc/defnett/operator_auth.json)"
    check UID-12 "defnett-collector baca executor.env" DITOLAK "$(as_uid_read defnett-collector /etc/defnett/executor.env)"
    check UID-13 "defnett-collector baca approval-authority.env" DITOLAK "$(as_uid_read defnett-collector /etc/defnett/approval-authority.env)"
    check UID-14 "defnett-collector baca kunci TLS Authority" DITOLAK "$(as_uid_read defnett-collector /etc/defnett/tls/approval-authority.key)"
    check UID-15 "defnett-approval baca kunci TLS Collector" DITOLAK "$(as_uid_read defnett-approval /etc/defnett/tls/collector-vm.key)"
    check UID-16 "defnett-approval baca akun operator" BISA "$(as_uid_read defnett-approval /etc/defnett/operator_auth.json)"
    tables=$(python3 -c 'import sqlite3; c=sqlite3.connect("file:/evidence/events.sqlite3?mode=ro", uri=True); print(",".join(r[0] for r in c.execute("select name from sqlite_master where type=\"table\"")))')
    log "INFO  tabel di database bukti (dipakai Collector dan Executor): $tables"
    log "INFO  aturan guard UID: $(iptables -S OUTPUT | grep -c 'owner') baris owner-match di OUTPUT"
    ufw status | sed 's/^/UFW /' | tee -a "$OUT" >/dev/null

    # Akun viewer uji dengan kata sandi acak yang tidak pernah ditampilkan.
    VIEWER_PASS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
    printf '%s\n' "$VIEWER_PASS" | python3 /opt/defnett/provision_operators.py --file /etc/defnett/operator_auth.json \
      --add uji-viewer --role viewer --force --password-stdin >/dev/null
    chown root:defnett-approval-auth /etc/defnett/operator_auth.json
    chmod 0640 /etc/defnett/operator_auth.json
    JAR="$(mktemp)"
    BODY="$(mktemp)"
    printf '{"username":"uji-viewer","password":"%s"}' "$VIEWER_PASS" > "$BODY"
    unset VIEWER_PASS
    code=$(curl -s --resolve collector:8443:127.0.0.1 -o /tmp/defnett-viewer-login.json -w '%{http_code}' -c "$JAR" --cacert /etc/defnett/tls/ca.crt \
      -H 'Content-Type: application/json' --data-binary "@$BODY" https://collector:8443/v1/operator/login)
    rm -f "$BODY"
    check VW-01 "Login viewer" 200 "$code"
    CSRF="$(python3 -c 'import json; print(json.load(open("/tmp/defnett-viewer-login.json")).get("csrf", ""))' 2>/dev/null)"
    rm -f /tmp/defnett-viewer-login.json
    code=$(curl -s --resolve collector:8443:127.0.0.1 -o /dev/null -w '%{http_code}' -b "$JAR" --cacert /etc/defnett/tls/ca.crt https://collector:8443/v1/dashboard)
    check VW-02 "Viewer membaca dashboard" 200 "$code"
    code=$(curl -s --resolve collector:8443:127.0.0.1 -o /dev/null -w '%{http_code}' -b "$JAR" --cacert /etc/defnett/tls/ca.crt -X POST \
      -H "X-DEFNETT-CSRF: $CSRF" "https://collector:8443/v1/lab/attack/server-a?vector=ssh")
    check VW-03 "Viewer menekan Serang" 401 "$code"
    code=$(curl -s --resolve collector:8443:127.0.0.1 -o /dev/null -w '%{http_code}' -b "$JAR" --cacert /etc/defnett/tls/ca.crt -X POST \
      -H "X-DEFNETT-CSRF: $CSRF" https://collector:8443/v1/approvals/00000000-0000-0000-0000-000000000000/approve)
    check VW-04 "Viewer menyetujui approval" 401 "$code"
    rm -f "$JAR"
    unset CSRF

    # Baris APPROVED palsu di tabel lama database bukti tidak boleh dieksekusi Executor.
    FAKE="uji-legacy-$(date +%s)"
    before=$(journalctl -u defnett-executor --no-pager -q | grep -c "$FAKE")
    sudo -u defnett-collector python3 - "$FAKE" <<'PYX'
import sqlite3, sys
c = sqlite3.connect("/evidence/events.sqlite3")
c.execute("""INSERT INTO operator_approvals (id, created_at, created_by, action, host_id, path, parameters_json,
             reason, event_id, approval_status, expires_at, execution_status)
             VALUES (?, datetime('now'), 'uji-isolasi', 'RESTORE_KEYS', 'server-a', 'etc/kunci1.dat', '{}',
             'uji tabel lama', NULL, 'APPROVED', '2099-01-01T00:00:00+00:00', 'NONE')""", (sys.argv[1],))
c.commit()
PYX
    check LEG-01 "Collector menulis baris APPROVED palsu ke tabel lama" 0 "$?"
    sleep 8
    after=$(journalctl -u defnett-executor --no-pager -q | grep -c "$FAKE")
    status=$(python3 -c 'import sqlite3,sys; c=sqlite3.connect("file:/evidence/events.sqlite3?mode=ro",uri=True); print(c.execute("select execution_status from operator_approvals where id=?",(sys.argv[1],)).fetchone()[0])' "$FAKE")
    check LEG-02 "Executor tidak menyentuh baris palsu (log)" "$before" "$after"
    check LEG-03 "Status eksekusi baris palsu tetap NONE" NONE "$status"
    sudo -u defnett-collector python3 -c 'import sqlite3,sys; c=sqlite3.connect("/evidence/events.sqlite3"); c.execute("delete from operator_approvals where id=?",(sys.argv[1],)); c.commit()' "$FAKE"
    log "INFO  baris uji $FAKE dihapus lagi dari tabel lama"
    ;;

  server-a|server-b)
    if ufw status | grep -qE '^8091/tcp +ALLOW +192\.168\.56\.1( |$)'; then
      ufw delete allow from 192.168.56.1 to any port 8091 proto tcp >/dev/null
      log "PERBAIKAN  aturan lama 192.168.56.1 -> 8091 (remediator admin) dihapus"
    fi
    check FW-01 "Host admin tidak lagi diizinkan ke remediator :8091" 0 "$(ufw status | grep -cE '^8091/tcp +ALLOW +192\.168\.56\.1( |$)')"
    for unit in defnett-agent defnett-remediator defnett-app; do
      log "UNIT $unit user=$(systemctl show -p User --value $unit) aktif=$(systemctl is-active $unit)"
    done
    check SRV-01 "Agent (defnett) menulis /master" DITOLAK "$(as_uid_write_dir defnett /master)"
    check SRV-02 "Remediator (defnett) membaca master" BISA "$(as_uid_read defnett /master/kunci1.dat)"
    check SRV-03 "Remediator (defnett) mengubah manifes" DITOLAK "$(if sudo -u defnett sh -c ': >> /etc/defnett/master-manifest.json' 2>/dev/null; then echo BISA; else echo DITOLAK; fi)"
    check SRV-04 "Manifes cocok dengan master" OK "$(python3 -c '
import hashlib, json
m = json.load(open("/etc/defnett/master-manifest.json"))["files"]
ok = all(hashlib.sha256(open("/master/" + n, "rb").read()).hexdigest() == e["sha256"] for n, e in m.items())
print("OK" if ok else "BEDA")')"
    ufw status | sed 's/^/UFW /' | tee -a "$OUT" >/dev/null
    ;;

  gateway)
    log "UNIT haproxy aktif=$(systemctl is-active haproxy)"
    check GW-01 "Runtime HAProxy hanya diizinkan dari Collector" 1 "$(ufw status | grep -cE '^9999/tcp +ALLOW +192\.168\.56\.20( |$)')"
    check GW-02 "Tidak ada aturan 9999 untuk alamat lain" 0 "$(ufw status | grep -E '^9999' | grep -vcE '192\.168\.56\.20( |$)')"
    ufw status | sed 's/^/UFW /' | tee -a "$OUT" >/dev/null
    ;;

  *)
    log "hostname tidak dikenal: $ROLE"
    exit 2
    ;;
esac

log "== selesai: PASS=$PASS FAIL=$FAIL, hasil di $OUT"
