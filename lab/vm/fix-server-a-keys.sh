#!/bin/sh
# DEFNETT lab - pulihkan kunci Server A yang tertinggal rusak (approval RESTORE_KEYS kedaluwarsa),
# supaya SERANG! ke Server A bisa jalan lagi dan Playbook kembali menampilkan Setujui/Tolak.
# 1) tampilkan alasan gagal serangan terakhir dari collector (baca-saja)
# 2) bila disetujui, jalankan restore-kunci.sh di Server A (master diverifikasi, file lama dikarantina)
set -eu
COLLECTOR="${1:-malas@192.168.56.20}"
SERVER_A="${2:-malas@192.168.56.11}"
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

echo "== alasan gagal SIMULATE_LAB_ATTACK server-a (5 terakhir) =="
ssh -t "$COLLECTOR" 'sudo python3 -c "
import sqlite3
db = sqlite3.connect(\"file:/var/lib/defnett-approval/approvals.sqlite3?mode=ro\", uri=True)
for r in db.execute(\"SELECT created_at, execution_status, execution_detail FROM operator_approvals WHERE host_id=? AND action=? ORDER BY created_at DESC LIMIT 5\", (\"server-a\", \"SIMULATE_LAB_ATTACK\")):
    print(*r, sep=\"  |  \")
"'

printf '\nPulihkan kunci Server A dari /master sekarang? [y/N] '
read -r answer
[ "$answer" = "y" ] || { echo "dibatalkan, tidak ada yang diubah"; exit 0; }

SOCK="${TMPDIR:-/tmp}/defnett-ssh-a-$$"
SSH="ssh -o ControlMaster=auto -o ControlPath=$SOCK -o ControlPersist=120"
$SSH "$SERVER_A" 'cat > /tmp/restore-kunci.sh' < "$HERE/restore-kunci.sh"
$SSH -t "$SERVER_A" '[ "$(hostname)" = server-a ] || { echo bukan server-a; exit 2; }; sudo sh /tmp/restore-kunci.sh'
$SSH -O exit "$SERVER_A" 2>/dev/null || true
echo "selesai. Tunggu ~10 detik lalu coba SERANG! ke Server A lagi."
