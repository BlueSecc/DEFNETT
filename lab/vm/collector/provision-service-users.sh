#!/bin/sh
# Run as root on the Collector VM during a maintenance window.
# This changes ownership/mode metadata only; it never alters database contents.
set -eu

for unit in defnett-approval-authority.service defnett-collector.service defnett-executor.service; do
  if systemctl is-active --quiet "$unit"; then
    echo "stop $unit before provisioning; refusing to change a live SQLite directory" >&2
    exit 1
  fi
done

ensure_group() {
  getent group "$1" >/dev/null || groupadd --system "$1"
}

ensure_user() {
  if ! id "$1" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin --gid "$2" "$1"
  else
    usermod --gid "$2" --shell /usr/sbin/nologin "$1"
  fi
}

ensure_group defnett-evidence
ensure_group defnett-approval-auth
ensure_group defnett-collector
ensure_group defnett-executor
ensure_group defnett-approval
ensure_user defnett-collector defnett-collector
ensure_user defnett-executor defnett-executor
ensure_user defnett-approval defnett-approval
usermod --lock defnett-collector
usermod --lock defnett-executor
usermod --lock defnett-approval
usermod --append --groups defnett-evidence defnett-collector
usermod --append --groups defnett-evidence defnett-executor
usermod --append --groups defnett-approval-auth defnett-approval

if [ ! -d /evidence ] || [ -L /evidence ]; then
  echo "/evidence does not exist; preserve deployment state and provision it first" >&2
  exit 1
fi
chgrp defnett-evidence /evidence
chmod 2770 /evidence
for file in /evidence/events.sqlite3 /evidence/events.sqlite3-wal /evidence/events.sqlite3-shm; do
  if [ -e "$file" ]; then
    if [ -L "$file" ] || [ ! -f "$file" ]; then
      echo "refusing non-regular SQLite path: $file" >&2
      exit 1
    fi
    chgrp defnett-evidence "$file"
    chmod 0660 "$file"
  fi
done

if [ ! -f /etc/defnett/operator_auth.json ] || [ -L /etc/defnett/operator_auth.json ] \
   || [ ! -r /etc/defnett/operator_auth.json ]; then
  echo "operator auth file missing/unreadable; refusing to start approval authority" >&2
  exit 1
fi
chown root:defnett-approval-auth /etc/defnett/operator_auth.json
chmod 0640 /etc/defnett/operator_auth.json

if [ ! -s /etc/defnett/collector.env ] || [ ! -s /etc/defnett/executor.env ] \
   || [ ! -s /etc/defnett/approval-authority.env ]; then
  echo "service environment file missing; refusing to change service access" >&2
  exit 1
fi
chown root:defnett-collector /etc/defnett/collector.env
chmod 0640 /etc/defnett/collector.env
chown root:root /etc/defnett/executor.env
chmod 0600 /etc/defnett/executor.env
chown root:defnett-approval /etc/defnett/approval-authority.env
chmod 0640 /etc/defnett/approval-authority.env

if [ -L /var/lib/defnett-approval ] || { [ -e /var/lib/defnett-approval ] && [ ! -d /var/lib/defnett-approval ]; }; then
  echo "unsafe approval state path; refusing" >&2
  exit 1
fi
install -d -o defnett-approval -g defnett-approval -m 0700 /var/lib/defnett-approval
for file in approvals.sqlite3 approvals.sqlite3-wal approvals.sqlite3-shm; do
  path="/var/lib/defnett-approval/$file"
  if [ -e "$path" ]; then
    [ -f "$path" ] && [ ! -L "$path" ] || { echo "unsafe SQLite path: $path" >&2; exit 1; }
    chown defnett-approval:defnett-approval "$path"
    chmod 0600 "$path"
  fi
done

if [ -d /etc/defnett/tls ] && [ ! -L /etc/defnett/tls ]; then
  chown root:root /etc/defnett/tls
  chmod 0755 /etc/defnett/tls
  # Kunci remediator hanya dipasang di server-a/server-b, tidak di Collector.
  for name in collector-vm executor-vm approval-authority; do
    cert="/etc/defnett/tls/$name.crt"
    key="/etc/defnett/tls/$name.key"
    [ -f "$cert" ] && [ ! -L "$cert" ] || { echo "TLS certificate missing or unsafe: $cert" >&2; exit 1; }
    [ -f "$key" ] && [ ! -L "$key" ] || { echo "TLS key missing or unsafe: $key" >&2; exit 1; }
    chmod 0644 "$cert"
    chmod 0600 "$key"
    case "$name" in
      collector-vm) chown root:defnett-collector "$key"; chmod 0640 "$key" ;;
      executor-vm) chown root:defnett-executor "$key"; chmod 0640 "$key" ;;
      approval-authority) chown root:defnett-approval "$key"; chmod 0640 "$key" ;;
    esac
  done
  [ -f /etc/defnett/tls/ca.crt ] && [ ! -L /etc/defnett/tls/ca.crt ] || {
    echo "lab CA missing or unsafe" >&2; exit 1;
  }
  chown root:root /etc/defnett/tls/ca.crt
  chmod 0644 /etc/defnett/tls/ca.crt
else
  echo "TLS directory missing or unsafe; services will not start until provisioned" >&2
  exit 1
fi

echo "service identities and least-privilege file permissions provisioned"
