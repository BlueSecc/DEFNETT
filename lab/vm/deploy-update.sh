#!/bin/sh
# DEFNETT lab - pasang pembaruan di satu VM. Jalankan sebagai root; peran dibaca dari hostname.
# Urutan: server-a, server-b, lalu collector, agar token aktif setelah pengirimnya siap.
# File lama disalin ke <nama>.bak-<waktu>. Paket sumber dipertahankan untuk rollback.
set -eu

ROLE="$(hostname)"
SOURCE="${1:-/tmp/defnett-deploy}"
STAMP="$(date +%Y%m%d%H%M%S)"

put() {
  [ ! -e "$2" ] || cp -p "$2" "$2.bak-$STAMP"
  install -m "$3" -o root -g "$4" "$1" "$2"
}

setenv() {
  if grep -q "^$2=" "$1"; then
    sed -i "s|^$2=.*|$2=$3|" "$1"
  else
    printf '%s=%s\n' "$2" "$3" >> "$1"
  fi
}

[ -d "$SOURCE" ] || { echo "paket tidak ditemukan di $SOURCE, tidak ada yang diubah" >&2; exit 1; }
TOKEN=""
[ ! -s "$SOURCE/token" ] || TOKEN="$(cat "$SOURCE/token")"

case "$ROLE" in
  server-a|server-b)
    ENV_FILE="/etc/defnett/$ROLE.env"
    cp -p "$ENV_FILE" "$ENV_FILE.bak-$STAMP"
    put "$SOURCE/agent.py" /opt/defnett/agent.py 640 defnett
    put "$SOURCE/app.py" /opt/defnett/app.py 644 root
    put "$SOURCE/remediator.py" /opt/defnett/remediator.py 644 root
    put "$SOURCE/tls_support.py" /opt/defnett/tls_support.py 644 root
    [ -z "$TOKEN" ] || setenv "$ENV_FILE" LAB_API_TOKEN "$TOKEN"
    systemctl restart defnett-remediator defnett-agent defnett-app
    systemctl is-active defnett-remediator defnett-agent defnett-app
    ;;
  collector)
    ENV_FILE=/etc/defnett/collector.env
    cp -p "$ENV_FILE" "$ENV_FILE.bak-$STAMP"
    put "$SOURCE/collector.py" /opt/defnett/collector.py 644 root
    put "$SOURCE/db.py" /opt/defnett/db.py 644 root
    put "$SOURCE/policy_gate.py" /opt/defnett/policy_gate.py 644 root
    put "$SOURCE/approvals.py" /opt/defnett/approvals.py 644 root
    put "$SOURCE/operator_auth.py" /opt/defnett/operator_auth.py 644 root
    put "$SOURCE/trajectory.py" /opt/defnett/trajectory.py 644 root
    put "$SOURCE/risk_engine.py" /opt/defnett/risk_engine.py 644 root
    put "$SOURCE/executor.py" /opt/defnett/executor.py 644 root
    put "$SOURCE/approval_authority.py" /opt/defnett/approval_authority.py 644 root
    put "$SOURCE/authority_client.py" /opt/defnett/authority_client.py 644 root
    put "$SOURCE/tls_support.py" /opt/defnett/tls_support.py 644 root
    put "$SOURCE/web_terminal.py" /opt/defnett/web_terminal.py 644 root
    put "$SOURCE/defnett-collector-network-guard" /usr/local/libexec/defnett-collector-network-guard 750 root
    put "$SOURCE/provision-service-users.sh" /usr/local/sbin/defnett-provision-service-users 750 root
    put "$SOURCE/defnett-collector.service" /etc/systemd/system/defnett-collector.service 644 root
    put "$SOURCE/defnett-executor.service" /etc/systemd/system/defnett-executor.service 644 root
    put "$SOURCE/defnett-approval-authority.service" /etc/systemd/system/defnett-approval-authority.service 644 root
    for name in index.html dashboard.css dashboard.js patrol.css patrol.js terminal.js; do
      put "$SOURCE/dashboard/$name" "/opt/defnett/dashboard/$name" 644 root
    done
    [ -z "$TOKEN" ] || setenv "$ENV_FILE" LAB_API_TOKEN "$TOKEN"
    [ -s /etc/defnett/executor.env ] || {
      echo "executor.env belum ada di /etc/defnett; isi EXECUTOR_API_TOKEN dulu" >&2
      exit 1
    }
    [ -s /etc/defnett/approval-authority.env ] || {
      echo "approval-authority.env belum diprovision dengan token terpisah" >&2
      exit 1
    }
    [ -z "$TOKEN" ] || setenv /etc/defnett/executor.env LAB_API_TOKEN "$TOKEN"
    id defnett-collector >/dev/null 2>&1 || {
      echo "jalankan provision-service-users.sh saat maintenance sebelum deploy ulang" >&2
      exit 1
    }
    id defnett-executor >/dev/null 2>&1 || {
      echo "jalankan provision-service-users.sh saat maintenance sebelum deploy ulang" >&2
      exit 1
    }
    id defnett-approval >/dev/null 2>&1 || {
      echo "jalankan provision-service-users.sh saat maintenance sebelum deploy ulang" >&2
      exit 1
    }
    systemctl daemon-reload
    systemctl enable defnett-approval-authority.service defnett-executor.service defnett-collector.service
    systemctl restart defnett-approval-authority.service
    systemctl is-active defnett-approval-authority.service
    systemctl restart defnett-executor.service
    systemctl is-active defnett-executor.service
    systemctl restart defnett-collector
    systemctl is-active defnett-collector.service
    ;;
  *)
    echo "hostname tidak dikenal: $ROLE" >&2
    exit 2
    ;;
esac

echo "selesai: $ROLE; paket sumber dipertahankan di $SOURCE"
