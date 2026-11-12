#!/bin/sh
# DEFNETT lab - kirim file dashboard (Overview + Patrol) ke VM collector dari laptop.
# Pemakaian: sh lab/vm/deploy-dashboard.sh [user@host]   (default malas@192.168.56.20)
# Password SSH dan sudo diketik sendiri; koneksi dipakai ulang sehingga password SSH cukup sekali.
# File lama disalin ke <nama>.bak-<waktu>. Collector membaca file per request, tidak perlu restart.
set -eu

TARGET="${1:-malas@192.168.56.20}"
DIR="$(CDPATH= cd -- "$(dirname -- "$0")/../dashboard" && pwd)"
SOCK="${TMPDIR:-/tmp}/defnett-ssh-$$"
SSH="ssh -o ControlMaster=auto -o ControlPath=$SOCK -o ControlPersist=120"
FILES="index.html dashboard.css dashboard.js patrol.css patrol.js terminal.js"

$SSH "$TARGET" 'rm -rf /tmp/defnett-dash && mkdir -p /tmp/defnett-dash'
(cd "$DIR" && COPYFILE_DISABLE=1 tar --no-xattrs -cf - $FILES) | $SSH "$TARGET" 'tar xf - -C /tmp/defnett-dash'
$SSH -t "$TARGET" 'sudo sh -c "
  set -e; [ \"\$(hostname)\" = collector ] || { echo bukan VM collector; exit 2; }
  STAMP=\$(date +%Y%m%d%H%M%S)
  for n in '"$FILES"'; do
    [ ! -e /opt/defnett/dashboard/\$n ] || cp -p /opt/defnett/dashboard/\$n /opt/defnett/dashboard/\$n.bak-\$STAMP
    install -m 644 -o root -g root /tmp/defnett-dash/\$n /opt/defnett/dashboard/\$n
  done
  sha256sum /opt/defnett/dashboard/patrol.js /opt/defnett/dashboard/patrol.css
  echo selesai: dashboard diperbarui, cadangan .bak-\$STAMP
"'
$SSH -O exit "$TARGET" 2>/dev/null || true
