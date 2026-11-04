#!/bin/sh
# DEFNETT lab - mengisi salinan master kunci + manifes sha256 di VM server (sekali).
# Jalankan sebagai root dengan baseline tepercaya eksternal; jangan gunakan /data.
# Pemakaian: sh provision-master.sh           (di server-a atau server-b)
#   atau:    sh provision-master.sh --force   (kunci baru yang sah diputih)
set -eu
ROLE="$(hostname)"
case "$ROLE" in
  server-a|server-b) ;;
  *) echo "jalankan di server-a atau server-b, bukan $ROLE" >&2; exit 2 ;;
esac
MASTER=/master
MANIFEST=/etc/defnett/master-manifest.json
SOURCE="${DEFNETT_TRUSTED_SOURCE:-/root/defnett-trusted-baseline}"
if [ ! -d "$SOURCE" ]; then
  echo "baseline tepercaya tidak ditemukan: $SOURCE (siapkan terpisah dari /data)" >&2
  exit 2
fi
SOURCE_REAL="$(realpath "$SOURCE")"
case "$SOURCE_REAL/" in
  /data/*|/data/) echo "baseline tidak boleh berasal dari /data" >&2; exit 2 ;;
esac
if [ -s "$MANIFEST" ] && [ "$#" -eq 0 ]; then
  echo "manifes $MANIFEST sudah ada; tidak disentuh (provision-master.sh --force untuk mengganti)" >&2
  exit 0
fi
mkdir -p "$MASTER"
python3 /opt/defnett/provision_master.py \
  --source "$SOURCE_REAL" \
  --master "$MASTER" \
  --manifest "$MANIFEST" \
  "$@"
chown -R root:defnett "$MASTER"
chmod 0750 "$MASTER"
chmod 0640 "$MASTER"/* "$MANIFEST"
echo "trust anchor siap: $MASTER + $MANIFEST"
