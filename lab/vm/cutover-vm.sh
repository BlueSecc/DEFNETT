#!/bin/sh
# DEFNETT lab - cutover satu VM ke alur persetujuan operator + TLS.
# Jalankan sebagai root; peran dibaca dari hostname. Urutan: server-a, server-b, collector.
# Paket disiapkan dari Mac dengan lab/vm/cutover-stage.sh ke /tmp/defnett-cutover.
# Backup /etc/defnett, /opt/defnett, unit, dan database bukti disimpan di /root/defnett-backup-<waktu>.
# Database tidak pernah dihapus. Rollback: salin balik isi backup, lalu restart layanan lama.
set -eu

ROLE="$(hostname)"
PKG="${1:-/tmp/defnett-cutover}"
STAMP="$(date +%Y%m%d%H%M%S)"
BACKUP="/root/defnett-backup-$STAMP"

[ -d "$PKG" ] || { echo "paket tidak ditemukan di $PKG, tidak ada yang diubah" >&2; exit 1; }

put() {
  install -D -m "$3" -o root -g "$4" "$1" "$2"
}

# Gabungkan tiap KEY=VALUE dari template ke file env yang ada; kunci lain dibiarkan.
merge_env() {
  template="$1"
  target="$2"
  touch "$target"
  grep -E '^[A-Z_][A-Z0-9_]*=' "$template" | while IFS= read -r line; do
    key="${line%%=*}"
    if grep -q "^$key=" "$target"; then
      python3 - "$target" "$key" "$line" <<'PY'
import sys
path, key, line = sys.argv[1:]
rows = open(path, encoding="utf-8").read().splitlines()
rows = [line if row.startswith(key + "=") else row for row in rows]
open(path, "w", encoding="utf-8").write("\n".join(rows) + "\n")
PY
    else
      printf '%s\n' "$line" >> "$target"
    fi
  done
}

envval() {
  sed -n "s/^$2=//p" "$1" | tail -n 1
}

fill_tokens() {
  sed -i \
    -e "s|GANTI-TOKEN-EXECUTOR-AUTHORITY|$APPROVAL_EXECUTOR_TOKEN|" \
    -e "s|GANTI-TOKEN-COLLECTOR-AUTHORITY|$APPROVAL_COLLECTOR_TOKEN|" \
    -e "s|GANTI-TOKEN-EXECUTOR|$EXECUTOR_API_TOKEN|" \
    "$1"
  if grep -q GANTI-TOKEN "$1"; then
    echo "token belum terisi di $1" >&2
    exit 1
  fi
}

install_tls() {
  install -d -m 0755 -o root -g root /etc/defnett/tls
  put "$PKG/tls/ca.crt" /etc/defnett/tls/ca.crt 0644 root
  for name in "$@"; do
    put "$PKG/tls/$name.crt" "/etc/defnett/tls/$name.crt" 0644 root
    put "$PKG/tls/$name.key" "/etc/defnett/tls/$name.key" 0600 root
  done
}

mkdir -p "$BACKUP"
chmod 0700 "$BACKUP"
cp -a /etc/defnett "$BACKUP/etc-defnett"
cp -a /opt/defnett "$BACKUP/opt-defnett"
cp -a /etc/systemd/system/defnett-*.service "$BACKUP/" 2>/dev/null || true
echo "backup: $BACKUP"

case "$ROLE" in
  server-a|server-b)
    ENV_FILE="/etc/defnett/$ROLE.env"
    systemctl stop defnett-agent defnett-remediator
    install_tls "remediator-${ROLE#server-}-vm"
    chown root:defnett "/etc/defnett/tls/remediator-${ROLE#server-}-vm.key"
    chmod 0640 "/etc/defnett/tls/remediator-${ROLE#server-}-vm.key"
    merge_env "$PKG/$ROLE.env" "$ENV_FILE"
    grep -q '^LAB_API_TOKEN=.' "$ENV_FILE" || { echo "LAB_API_TOKEN hilang dari $ENV_FILE" >&2; exit 1; }
    put "$PKG/agent.py" /opt/defnett/agent.py 0640 defnett
    put "$PKG/app.py" /opt/defnett/app.py 0644 root
    put "$PKG/remediator.py" /opt/defnett/remediator.py 0644 root
    put "$PKG/tls_support.py" /opt/defnett/tls_support.py 0644 root
    put "$PKG/provision_master.py" /opt/defnett/provision_master.py 0644 root
    put "$PKG/defnett-remediator.service" /etc/systemd/system/defnett-remediator.service 0644 root

    # Trust anchor: kunci bersih dibuat ulang dari template seed di repo, bukan dari /data.
    BASE=/root/defnett-trusted-baseline
    install -d -m 0700 "$BASE/etc"
    printf 'SECRET kunci1 — jangan dibagikan (%s)\nLabel: DEFNETT-LAB-KEY-1\n' "$ROLE" > "$BASE/etc/kunci1.dat"
    printf 'SECRET kunci2 — jangan dibagikan (%s)\nLabel: DEFNETT-LAB-KEY-2\n' "$ROLE" > "$BASE/etc/kunci2.dat"
    mkdir -p /master
    python3 /opt/defnett/provision_master.py --source "$BASE" --master /master \
      --manifest /etc/defnett/master-manifest.json --force
    chown -R root:defnett /master
    chmod 0750 /master
    chmod 0640 /master/* /etc/defnett/master-manifest.json
    chown root:defnett /etc/defnett/master-manifest.json

    systemctl daemon-reload
    systemctl restart defnett-remediator defnett-agent defnett-app
    sleep 2
    systemctl is-active defnett-remediator defnett-agent defnett-app
    ;;

  collector)
    [ -s "$PKG/tokens.env" ] || { echo "tokens.env tidak ada di paket" >&2; exit 1; }
    . "$PKG/tokens.env"
    LAB_API_TOKEN="$(envval /etc/defnett/collector.env LAB_API_TOKEN)"
    [ -n "$LAB_API_TOKEN" ] || { echo "LAB_API_TOKEN tidak ada di collector.env lama; tidak ada yang diubah" >&2; exit 1; }
    for unit in defnett-collector defnett-executor defnett-approval-authority; do
      systemctl stop "$unit" 2>/dev/null || true
    done
    [ ! -f /evidence/events.sqlite3 ] || cp -p /evidence/events.sqlite3 "$BACKUP/events.sqlite3"

    for name in collector db policy_gate approvals operator_auth trajectory risk_engine executor \
        approval_authority authority_client tls_support provision_operators; do
      put "$PKG/$name.py" "/opt/defnett/$name.py" 0644 root
    done
    for name in index.html dashboard.css dashboard.js patrol.css patrol.js; do
      put "$PKG/dashboard/$name" "/opt/defnett/dashboard/$name" 0644 root
    done
    put "$PKG/defnett-collector-network-guard" /usr/local/libexec/defnett-collector-network-guard 0750 root
    put "$PKG/provision-service-users.sh" /usr/local/sbin/defnett-provision-service-users 0750 root
    for unit in defnett-collector defnett-executor defnett-approval-authority; do
      put "$PKG/$unit.service" "/etc/systemd/system/$unit.service" 0644 root
    done

    install_tls collector-vm executor-vm approval-authority

    merge_env "$PKG/collector.env" /etc/defnett/collector.env
    sed -i '/^ENABLE_LAB_AUTOREPAIR=/d' /etc/defnett/collector.env
    fill_tokens /etc/defnett/collector.env
    [ -s /etc/defnett/executor.env ] || cp "$PKG/executor.env" /etc/defnett/executor.env
    merge_env "$PKG/executor.env" /etc/defnett/executor.env
    grep -q '^LAB_API_TOKEN=' /etc/defnett/executor.env \
      || printf 'LAB_API_TOKEN=%s\n' "$LAB_API_TOKEN" >> /etc/defnett/executor.env
    fill_tokens /etc/defnett/executor.env
    [ -s /etc/defnett/approval-authority.env ] || cp "$PKG/approval-authority.env" /etc/defnett/approval-authority.env
    merge_env "$PKG/approval-authority.env" /etc/defnett/approval-authority.env
    fill_tokens /etc/defnett/approval-authority.env

    if [ ! -s /etc/defnett/operator_auth.json ]; then
      OPERATOR="${OPERATOR_USER:-admin}"
      echo "buat akun operator '$OPERATOR' (kata sandi minimal 12 karakter):"
      python3 /opt/defnett/provision_operators.py --file /etc/defnett/operator_auth.json \
        --add "$OPERATOR" --role operator
    fi

    ufw allow from 192.168.56.1  to any port 8443 proto tcp comment "dashboard/API HTTPS admin"
    ufw allow from 192.168.56.11 to any port 8443 proto tcp comment "HTTPS telemetry server-a"
    ufw allow from 192.168.56.12 to any port 8443 proto tcp comment "HTTPS telemetry server-b"

    /usr/local/sbin/defnett-provision-service-users
    systemctl daemon-reload
    systemd-analyze verify defnett-approval-authority.service defnett-executor.service defnett-collector.service \
      || echo "peringatan: systemd-analyze verify melaporkan masalah di atas" >&2
    systemctl enable defnett-approval-authority.service defnett-executor.service defnett-collector.service
    for unit in defnett-approval-authority defnett-executor defnett-collector; do
      systemctl restart "$unit"
      sleep 2
      systemctl is-active "$unit" || { journalctl -u "$unit" -n 30 --no-pager; exit 1; }
    done
    ;;

  *)
    echo "hostname tidak dikenal: $ROLE" >&2
    exit 2
    ;;
esac

rm -f "$PKG/tokens.env"
echo "selesai: $ROLE; backup di $BACKUP"
