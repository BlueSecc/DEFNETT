#!/bin/sh
# DEFNETT lab - pasang tombol Serang! demo: serangan lab asli di VM.
# Jalankan sebagai root di tiap VM, urutan server-a, server-b dulu, collector terakhir.
# Pemakaian: sh deploy-real-attack.sh server-a|server-b|collector [folder-sumber]
# Deploy komponen inti (collector, executor, modul tahap 1, dashboard) dikerjakan
# deploy-update.sh; skrip ini hanya menyetel lingkungan khusus demo serangan.
# Tombol Serang! sejak tahap 1 membuat persetujuan operator, bukan eksekusi langsung.
set -eu

ROLE="${1:-}"
SOURCE="${2:-/tmp/defnett-deploy}"
HERE="$(cd "$(dirname "$0")" && pwd)"

setenv() {
  if grep -q "^$2=" "$1"; then
    sed -i "s|^$2=.*|$2=$3|" "$1"
  else
    printf '%s=%s\n' "$2" "$3" >> "$1"
  fi
}

case "$ROLE" in
  server-a|server-b)
    sh "$HERE/deploy-update.sh" "$SOURCE"
    setenv "/etc/defnett/$ROLE.env" LAB_ATTACK_SIMULATION true
    systemctl restart defnett-remediator
    systemctl is-active defnett-remediator
    ;;
  collector)
    sh "$HERE/deploy-update.sh" "$SOURCE"
    setenv /etc/defnett/collector.env DEMO_REPAIR_HOST all
    setenv /etc/defnett/collector.env DEMO_REPAIR_DELAY_SECONDS 15
    systemctl restart defnett-collector
    systemctl is-active defnett-collector
    ;;
  *)
    echo "pemakaian: sh deploy-real-attack.sh server-a|server-b|collector [folder-sumber]" >&2
    exit 2
    ;;
esac
