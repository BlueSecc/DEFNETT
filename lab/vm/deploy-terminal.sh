#!/bin/sh
# DEFNETT lab - pasang tab Terminal (shell SSH ke server-a/server-b lewat collector).
# Pemakaian dari laptop: sh lab/vm/deploy-terminal.sh
#  1) collector: collector.py + web_terminal.py + file dashboard, lalu restart defnett-collector
#  2) server-a & server-b: ufw izinkan SSH (22) dari collector 192.168.56.20
# Password SSH dan sudo diketik sendiri. File lama disalin ke <nama>.bak-<waktu>.
set -eu

COLLECTOR="${COLLECTOR:-malas@192.168.56.20}"
SERVERS="${SERVERS:-malas@192.168.56.11 malas@192.168.56.12}"
LAB="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
SOCK="${TMPDIR:-/tmp}/defnett-ssh-term-$$"
SSH="ssh -o ControlMaster=auto -o ControlPath=$SOCK -o ControlPersist=120"
DASH="index.html dashboard.css dashboard.js patrol.css patrol.js terminal.js"
# sha256 collector.py versi repo sebelum fitur terminal (commit 3b14242); VM lain tidak ditimpa diam-diam
BASE_SHA="2ef009c38e0c01bb18ac69e08ba9371c03cd32139a9bf39ec97b66616c0abef1"

echo "== 1/2 collector ($COLLECTOR)"
$SSH "$COLLECTOR" 'rm -rf /tmp/defnett-term && mkdir -p /tmp/defnett-term/dashboard'
(cd "$LAB" && COPYFILE_DISABLE=1 tar --no-xattrs -cf - collector.py web_terminal.py $(for n in $DASH; do printf 'dashboard/%s ' "$n"; done)) \
  | $SSH "$COLLECTOR" 'tar xf - -C /tmp/defnett-term'
$SSH -t "$COLLECTOR" 'sudo sh -c "
  set -e; [ \"\$(hostname)\" = collector ] || { echo bukan VM collector; exit 2; }
  command -v ssh >/dev/null || { echo klien ssh belum terpasang: apt install openssh-client; exit 3; }
  command -v setsid >/dev/null || { echo setsid tidak ada: apt install util-linux; exit 3; }
  CUR=\$(sha256sum /opt/defnett/collector.py | cut -d\" \" -f1)
  if [ \"\$CUR\" != '"$BASE_SHA"' ] && [ \"\$CUR\" != \$(sha256sum /tmp/defnett-term/collector.py | cut -d\" \" -f1) ] && [ '"${FORCE:-0}"' != 1 ]; then
    echo collector.py di VM berbeda dari versi repo, tidak ditimpa. Jalankan ulang dengan FORCE=1 bila yakin.; exit 4
  fi
  STAMP=\$(date +%Y%m%d%H%M%S)
  put() { [ ! -e \"\$2\" ] || cp -p \"\$2\" \"\$2.bak-\$STAMP\"; install -m 644 -o root -g root \"\$1\" \"\$2\"; }
  put /tmp/defnett-term/collector.py /opt/defnett/collector.py
  put /tmp/defnett-term/web_terminal.py /opt/defnett/web_terminal.py
  for n in '"$DASH"'; do put /tmp/defnett-term/dashboard/\$n /opt/defnett/dashboard/\$n; done
  systemctl restart defnett-collector
  sleep 2
  systemctl is-active defnett-collector
  echo collector selesai, cadangan .bak-\$STAMP
"'
$SSH -O exit "$COLLECTOR" 2>/dev/null || true

echo "== 2/2 firewall server: izinkan SSH dari collector"
for target in $SERVERS; do
  echo "-- $target"
  ssh -t "$target" 'case "$(hostname)" in server-a|server-b) ;; *) echo "hostname tak dikenal"; exit 2;; esac
    sudo ufw allow from 192.168.56.20 to any port 22 proto tcp comment "terminal web collector"
    sudo ufw status | grep -E "^22/tcp"'
done
echo "selesai. Muat ulang dashboard, masuk operator, buka tab Terminal."
