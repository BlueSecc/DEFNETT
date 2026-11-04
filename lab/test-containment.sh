#!/bin/sh
# test-containment.sh — uji end-to-end: insiden -> approval operator -> executor.
# Pemakaian (dari root repo): sh lab/test-containment.sh [server-a|server-b] [canary|kunci]
# Operator login: DEFNETT_OPERATOR_USER / DEFNETT_OPERATOR_PASSWORD (wajib diisi).
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
compose_file="$root_dir/lab/compose.yaml"
canary_file="$root_dir/lab/compose.canary.yaml"
target_host=${1:-server-a}
mode=${2:-canary}
user=${DEFNETT_OPERATOR_USER:-admin}
pass=${DEFNETT_OPERATOR_PASSWORD:?set DEFNETT_OPERATOR_PASSWORD untuk login operator}
export user pass
case "$target_host" in
    server-a) survivor_host=server-b ;;
    server-b) survivor_host=server-a ;;
    *) printf '%s\n' 'Target harus server-a atau server-b.' >&2; exit 2 ;;
esac
case "$mode" in
    canary) artifact_label='canary' ;;
    kunci) artifact_label='kunci' ;;
    *) printf '%s\n' 'Mode harus canary atau kunci.' >&2; exit 2 ;;
esac

[ -n "$(docker compose -f "$compose_file" -f "$canary_file" ps -q "$target_host")" ] || {
    printf '%s\n' 'Jalankan lab dengan build.sh terlebih dahulu, target tidak hidup.' >&2
    exit 1
}
[ -n "$(docker compose -f "$compose_file" -f "$canary_file" ps -q "$survivor_host")" ] || {
    printf '%s\n' 'Kontainer lab survivor tidak hidup.' >&2
    exit 1
}

tmp_cookie=$(mktemp)
tmp_login=$(mktemp)
trap 'rm -f "$tmp_cookie" "$tmp_login"' EXIT
base_url="http://127.0.0.1:8090"

printf '%s\n' 'Login operator...'
curl --fail --silent --show-error \
    --cookie-jar "$tmp_cookie" \
    -H 'Content-Type: application/json' \
    --data "$(
        DEFNETT_OPERATOR_USER=$user DEFNETT_OPERATOR_PASSWORD=$pass python3 -c \
        'import json,os; print(json.dumps({"username": os.environ["DEFNETT_OPERATOR_USER"], "password": os.environ["DEFNETT_OPERATOR_PASSWORD"]}))'
    )" \
    --request POST \
    "$base_url/v1/operator/login" > "$tmp_login"
csrf=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["csrf"])' < "$tmp_login")
case "$csrf" in
    ""|[!w-]*) printf '%s\n' 'Login sukses tapi CSRF tidak terbaca.' >&2; exit 1 ;;
esac

# Dashboard dan evidence harus bisa dibaca dengan sesi ini (kerahasiaan GET).
curl --fail --silent --cookie "$tmp_cookie" "$base_url/v1/dashboard" > "$tmp_login" 2>/dev/null || {
    printf '%s\n' 'Dashboard tidak terbaca dengan sesi operator.' >&2
    exit 1
}

previous_run_id=$(python3 -c 'import json,sys; d=json.load(sys.stdin); print((d.get("remediation") or {}).get("event_id") or "")' < "$tmp_login" 2>/dev/null || true)

if [ "$mode" = "kunci" ]; then
    printf 'Mengisengi kunci rahasia di %s (dicuri adalah seluruh isi file).\n' "$target_host"
    docker compose -f "$compose_file" -f "$canary_file" exec -T "$target_host" \
        python -c "from pathlib import Path; import time; Path('/data/etc/kunci1.dat').write_text('DEFNETT-LAB-THIEF-GRABBED ' + str(time.time()) + chr(10), encoding='utf-8')"
else
    printf 'Menaruh canary teks aman di %s.\n' "$target_host"
    docker compose -f "$compose_file" -f "$canary_file" exec -T "$target_host" \
        python -c "from pathlib import Path; import time; Path('/data/DEFNETT-LAB-CANARY.txt').write_text('DEFNETT-LAB-MALWARE-CANARY ' + str(time.time()) + chr(10), encoding='utf-8')"
fi

printf '%s\n' 'Menunggu Policy Gate membuat persetujuan (PENDING_APPROVAL)...'
approval_id=""
attempt=0
while [ "$attempt" -lt 60 ]; do
    approval_id=$(curl --fail --silent --cookie "$tmp_cookie" "$base_url/v1/approvals" | \
      DEFNETT_TARGET_HOST=$target_host DEFNETT_MODE=$mode python3 -c '
import json, os, sys
mode = os.environ["DEFNETT_MODE"]
target = os.environ["DEFNETT_TARGET_HOST"]
want_action = {"canary": "CONTAIN_CANARY", "kunci": "RESTORE_KEYS"}[mode]
for approval in json.load(sys.stdin).get("approvals", []):
    if approval.get("approval_status") == "PENDING" \
       and approval.get("host_id") == target \
       and approval.get("action") == want_action:
        print(approval["id"])
        break
')
    [ -n "$approval_id" ] && break
    attempt=$((attempt + 1))
    sleep 1
done
if [ -z "$approval_id" ]; then
    printf '%s\n' 'Approval PENDING tidak muncul sebelum batas waktu.' >&2
    exit 1
fi
printf 'Approval ditemukan: %s\n' "$approval_id"

printf '%s\n' 'Menyetujui (Approve) lalu menunggu playbook executor...'
curl --fail --silent --show-error --request POST \
    --cookie "$tmp_cookie" \
    -H "X-DEFNETT-CSRF: $csrf" \
    "$base_url/v1/approvals/$approval_id/approve" > "$tmp_login"
printf 'Approval di-setujui; eksekusi diklaim executor.\n'

delay_seconds=$(curl --fail --silent --cookie "$tmp_cookie" "$base_url/v1/dashboard" | \
  python3 -c 'import json,sys; print(int((json.load(sys.stdin).get("analysis") or {}).get("demo_repair_delay_seconds") or 0))')
deadline=$((delay_seconds + 90))
printf '%s\n' 'Menunggu isolasi, karantina, health check, dan rejoin:'
attempt=0
while [ "$attempt" -lt "$deadline" ]; do
    run_json=$(curl --fail --silent --cookie "$tmp_cookie" "$base_url/v1/dashboard" | \
      PREVIOUS=$previous_run_id python3 -c '
import json, os, sys
d = json.load(sys.stdin)
run = d.get("remediation") or {}
if run.get("event_id") and run.get("event_id") != os.environ["PREVIOUS"]:
    print(json.dumps(run, ensure_ascii=False))
')
    if [ -n "$run_json" ]; then
        status=$(printf '%s' "$run_json" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status"))')
        if [ "$status" = "REPAIRED" ]; then
            printf '%s\n' "$run_json"
            break
        fi
        if [ "$status" = "EXECUTION_FAILED" ]; then
            printf '%s\n' "$run_json" >&2
            printf '%s\n' 'Playbook executor mencatat EXECUTION_FAILED.' >&2
            exit 1
        fi
    fi
    attempt=$((attempt + 1))
    sleep 1
done
if [ "$attempt" -ge "$deadline" ]; then
    printf '%s\n' 'Playbook tidak selesai dalam batas waktu.' >&2
    exit 1
fi

if [ "$mode" = "kunci" ]; then
    worker="remediator-$(printf '%s' "$target_host" | sed 's/^server-//')"
    docker compose -f "$compose_file" -f "$canary_file" exec -T "$worker" \
        sh -c 'cmp -s /target/etc/kunci1.dat /master/kunci1.dat && cmp -s /target/etc/kunci2.dat /master/kunci2.dat && test -f /manifest/keys.json'
    docker compose -f "$compose_file" -f "$canary_file" exec -T "$target_host" \
        sh -c 'grep -q "SECRET kunci1" /data/etc/kunci1.dat && grep -q "SECRET kunci2" /data/etc/kunci2.dat'
    printf 'Kunci dipulihkan byte-per-byte dari master (manifes kepercayaan tervalidasi).\n'
else
    docker compose -f "$compose_file" -f "$canary_file" exec -T "$target_host" \
        python -c "from pathlib import Path; assert not Path('/data/DEFNETT-LAB-CANARY.txt').exists(), 'canary masih ada di /data'"
fi

target_id=$(docker compose -f "$compose_file" -f "$canary_file" ps -q "$target_host")
survivor_id=$(docker compose -f "$compose_file" -f "$canary_file" ps -q "$survivor_host")
[ -n "$target_id" ] || { printf 'Kontainer target hilang saat playbook.\n' >&2; exit 1; }

printf '\n%s\n' 'Memastikan Server A dan Server B kembali melayani trafik:'
seen_a=0
seen_b=0
for i in 1 2 3 4; do
    response=$(curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8080/)
    printf 'Request %s: %s\n' "$i" "$(printf '%s' "$response" | head -n 1)"
    case "$response" in
        *"response from server-a"*) seen_a=1 ;;
        *"response from server-b"*) seen_b=1 ;;
        *) printf '%s\n' 'Request tidak cocok dengan backend yang diharapkan.' >&2; exit 1 ;;
    esac
done
[ "$seen_a" -eq 1 ] && [ "$seen_b" -eq 1 ] || {
    printf '%s\n' 'Rejoin check gagal: kedua backend belum terlihat.' >&2
    exit 1
}
[ "$target_id" = "$(docker compose -f "$compose_file" -f "$canary_file" ps -q "$target_host")" ] || {
    printf 'Container %s berubah saat playbook; hasil uji tidak valid.\n' "$target_host" >&2
    exit 1
}
[ "$survivor_id" = "$(docker compose -f "$compose_file" -f "$canary_file" ps -q "$survivor_host")" ] || {
    printf '%s\n' 'Container server survivor berubah; host yang tidak diserang ikut tersentuh.' >&2
    exit 1
}

printf '\n%s\n' 'Memeriksa trafik sebelum, selama, dan setelah containment:'
TARGET_HOST="$target_host" SURVIVOR_HOST="$survivor_host" curl --fail --silent --cookie "$tmp_cookie" "$base_url/v1/dashboard" > "$tmp_login" || {
    printf '%s\n' 'Dashboard trafik tidak terbaca.' >&2
    exit 1
}
TARGET_HOST="$target_host" SURVIVOR_HOST="$survivor_host" python3 - <<'PY' < "$tmp_login"
import json, os, sys
traffic = (json.load(sys.stdin).get("traffic") or {})
if not traffic.get("enabled"):
    raise SystemExit("Probe trafik nonaktif; set TRAFFIC_PROBE_ENABLED=true untuk pemeriksaan ini.")
windows = traffic["windows"]
for phase in ("before", "during", "after"):
    w = windows[phase]
    print(f"{phase:>6}: ok={w['ok']} fail={w['fail']} by_host={w['by_host']}")
target, survivor = os.environ["TARGET_HOST"], os.environ["SURVIVOR_HOST"]
if any(windows[phase]["fail"] for phase in windows):
    raise SystemExit("Ada request gagal selama containment; layanan tidak tetap tersedia.")
during = windows["during"]["by_host"]
if not during.get(survivor, 0) > during.get(target, 0):
    raise SystemExit("Selama containment, survivor harus menjawab lebih banyak daripada host target.")
PY

printf '\n%s\n' "Selesai: hanya $target_host yang dipulihkan; $survivor_host tidak diperbaiki dan kedua container tidak direstart."
