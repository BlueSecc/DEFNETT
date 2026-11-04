#!/bin/sh
# Pulihkan manual kunci server ini dari /master setelah playbook ditolak operator.
# Master diverifikasi dengan manifes dulu; file yang berubah disalin ke karantina sebagai bukti.
set -eu
HOST="$(hostname)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
python3 - <<'PY'
import hashlib, json, sys
m = json.load(open("/etc/defnett/master-manifest.json"))["files"]
for name, entry in m.items():
    if hashlib.sha256(open("/master/" + name, "rb").read()).hexdigest() != entry["sha256"]:
        sys.exit(f"master {name} tidak cocok manifes; pemulihan dibatalkan")
print("master cocok manifes")
PY
for name in kunci1.dat kunci2.dat; do
  if ! cmp -s "/master/$name" "/data/etc/$name"; then
    cp -p "/data/etc/$name" "/quarantine/$HOST/manual-$STAMP-$name"
    install -m 0644 -o defnett -g defnett "/master/$name" "/data/etc/$name"
    echo "$name dipulihkan; salinan bukti: /quarantine/$HOST/manual-$STAMP-$name"
  else
    echo "$name sudah sama dengan master"
  fi
done
