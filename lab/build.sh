#!/bin/sh
# build.sh — bangun lab DEFNETT dan siapkan demo dengan satu perintah.
#
# Tahap "security boundary":
#   1. Token service dibuat lokal dan diberikan hanya ke pasangan pemakainya.
#   2. Approval Authority memiliki database dan file operator tersendiri.
#   3. Trust anchor tidak pernah dibuat dari /data aktif. Provision secara
#      eksplisit dari baseline tepercaya yang disediakan terpisah.
#
# Pemakaian (dari root repo):  sh lab/build.sh
set -eu

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
compose() { docker compose -f lab/compose.yaml -f lab/compose.canary.yaml "$@"; }
project=defnett-lab
DEFNETT_TLS_DIR=${DEFNETT_TLS_DIR:-${HOME}/.config/defnett-lab/tls}
export DEFNETT_TLS_DIR
sh "$root_dir/lab/provision-lab-tls.sh" "$DEFNETT_TLS_DIR"

printf '%s\n' '[1/5] Menyiapkan token service lokal...'
DEFNETT_EXECUTOR_TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
DEFNETT_LAB_API_TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
DEFNETT_OT_API_TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
DEFNETT_APPROVAL_COLLECTOR_TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
DEFNETT_APPROVAL_EXECUTOR_TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
export DEFNETT_EXECUTOR_TOKEN DEFNETT_LAB_API_TOKEN DEFNETT_OT_API_TOKEN
export DEFNETT_APPROVAL_COLLECTOR_TOKEN DEFNETT_APPROVAL_EXECUTOR_TOKEN

printf '%s\n' '[2/5] Membangun dan menghidupkan lab (compose build)...'
cd "$root_dir"
compose up -d --build --wait

printf '%s\n' '[3/5] Menyiapkan operator dan data demo...'
if ! compose run --rm -T approval-authority test -f /ops/operator_auth.json 2>/dev/null; then
    admin_password=$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')
    printf '%s\n' "$admin_password" | compose run --rm -T approval-authority python /opt/defnett/provision_operators.py \
        --file /ops/operator_auth.json --add admin --role operator --password-stdin >/dev/null
    printf '   Akun operator dashboard: admin\n'
    printf '   Kata sandi (simpan!): %s\n' "$admin_password"
else
    printf '   Akun operator sudah ada; tidak diubah (pakai provision_operators.py untuk kelola).\n'
fi
for host in server-a server-b; do
    if ! compose exec -T "$host" test -f /data/etc/kunci1.dat; then
        existing=$(compose exec -T "$host" sh -c 'find /data -mindepth 1 -print -quit')
        if [ -n "$existing" ]; then
            printf '   Data %s ada tetapi baseline seed tidak lengkap; tidak diubah.\n' "$host" >&2
            exit 1
        fi
        compose exec -T "$host" sh -s "$host" < lab/seed-fs.sh
    fi
done
compose restart remediator-a remediator-b agent-a agent-b
printf '%s\n' '   Trust anchor harus diprovisikan manual dari baseline tepercaya eksternal.'
printf '%s\n' '   build.sh tidak membaca /data untuk membuat master atau manifest.'
for host in server-a server-b; do
    suffix=${host#server-}
    if docker run --rm -v "${project}_manifest_${suffix}_data:/manifest:ro" defnett-lab:local \
        python -c "import os,sys; sys.exit(0 if os.path.exists('/manifest/keys.json') else 1)"; then
        printf '   %s: manifest tersedia, dipertahankan.\n' "$host"
    else
        printf '   %s: manifest belum ada; recovery akan menolak sampai provisioning tepercaya dilakukan.\n' "$host"
    fi
done

printf '%s\n' '[4/5] Status kontainer:'
sleep 5
compose ps --format 'table {{.Name}}\t{{.Status}}'

printf '\n%s\n' '[5/5] Siap. Dashboard: https://127.0.0.1:8443/  -  App lewat HAProxy: http://127.0.0.1:8080/'
printf '%s\n' 'Masuk sebagai operator (tombol Masuk) untuk menyetujui playbook yang tertunda.'
printf '%s\n' 'Uji containment: sh lab/test-containment.sh'
