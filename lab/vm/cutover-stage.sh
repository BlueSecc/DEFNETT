#!/bin/sh
# DEFNETT lab - kirim paket cutover dari Mac ke /tmp/defnett-cutover di tiap VM (tanpa sudo).
# Sertifikat dan token dibaca dari ~/.config/defnett-vm-lab (dibuat provision-lab-tls.sh).
# Tiap VM hanya menerima sertifikat miliknya; token layanan hanya dikirim ke Collector.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
LAB="$(cd "$HERE/.." && pwd)"
CONF="${DEFNETT_LAB_CONF:-$HOME/.config/defnett-vm-lab}"
TLS="$CONF/tls"
USER_VM="${VM_USER:-malas}"
[ -f "$TLS/ca.crt" ] || { echo "jalankan dulu: sh lab/provision-lab-tls.sh $TLS" >&2; exit 1; }
[ -s "$CONF/tokens.env" ] || { echo "token belum ada di $CONF/tokens.env" >&2; exit 1; }

send() {
  ip="$1"
  shift
  ssh "$USER_VM@$ip" 'rm -rf /tmp/defnett-cutover && mkdir -m 700 /tmp/defnett-cutover /tmp/defnett-cutover/tls /tmp/defnett-cutover/dashboard'
  scp -q "$@" "$USER_VM@$ip:/tmp/defnett-cutover/"
}

for role in server-a server-b; do
  case "$role" in server-a) ip=192.168.56.11; tag=a ;; server-b) ip=192.168.56.12; tag=b ;; esac
  send "$ip" "$HERE/cutover-vm.sh" "$HERE/$role/$role.env" "$HERE/$role/defnett-units/defnett-remediator.service" \
    "$LAB/agent.py" "$LAB/app.py" "$LAB/remediator.py" "$LAB/tls_support.py" "$LAB/provision_master.py"
  scp -q "$TLS/ca.crt" "$TLS/remediator-$tag-vm.crt" "$TLS/remediator-$tag-vm.key" "$USER_VM@$ip:/tmp/defnett-cutover/tls/"
  echo "paket $role terkirim"
done

ip=192.168.56.20
send "$ip" "$HERE/cutover-vm.sh" "$HERE/collector/collector.env" "$HERE/collector/executor.env" \
  "$HERE/collector/approval-authority.env" "$HERE/collector/defnett-collector-network-guard" \
  "$HERE/collector/provision-service-users.sh" "$HERE"/collector/defnett-units/*.service \
  "$LAB/collector.py" "$LAB/db.py" "$LAB/policy_gate.py" "$LAB/approvals.py" "$LAB/operator_auth.py" \
  "$LAB/trajectory.py" "$LAB/risk_engine.py" "$LAB/executor.py" "$LAB/approval_authority.py" \
  "$LAB/authority_client.py" "$LAB/tls_support.py" "$LAB/provision_operators.py" "$CONF/tokens.env"
scp -q "$LAB"/dashboard/index.html "$LAB"/dashboard/*.css "$LAB"/dashboard/*.js "$USER_VM@$ip:/tmp/defnett-cutover/dashboard/"
scp -q "$TLS/ca.crt" "$TLS"/collector-vm.* "$TLS"/executor-vm.* "$TLS"/approval-authority.* "$USER_VM@$ip:/tmp/defnett-cutover/tls/"
echo "paket collector terkirim"
