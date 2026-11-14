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
# Image memakai ENTRYPOINT ["python"]; perintah selain python wajib --entrypoint.
if ! compose run --rm -T --no-deps --entrypoint test approval-authority -f /ops/operator_auth.json 2>/dev/null; then
    admin_password=$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')
    printf '%s\n' "$admin_password" | compose run --rm -T --no-deps approval-authority /opt/defnett/provision_operators.py \
        --file /ops/operator_auth.json --add admin --role operator --password-stdin >/dev/null
    printf '   Akun operator dashboard: admin\n'
    printf '   Kata sandi (simpan!): %s\n' "$admin_password"
else
    printf '   Akun operator sudah ada; tidak diubah (pakai provision_operators.py untuk kelola).\n'
fi
for host in server-a server-b; do
    if ! compose exec -T "$host" test -f /data/etc/kunci1.dat; then
        # app.py selalu menulis index.txt saat start; seed menimpanya.
        existing=$(compose exec -T "$host" sh -c 'find /data -mindepth 1 ! -path /data/index.txt -print -quit')
        if [ -n "$existing" ]; then
            printf '   Data %s ada tetapi baseline seed tidak lengkap; tidak diubah.\n' "$host" >&2
            exit 1
        fi
        compose exec -T "$host" sh -s "$host" < lab/seed-fs.sh
    fi
done
compose restart remediator-a remediator-b agent-a agent-b
# Trust anchor demo: baseline dibangun dari lab/seed-fs.sh di container sekali
# pakai (tanpa volume /data), lalu provision_master.py menulis master + manifest.
# build.sh tidak pernah membaca /data aktif. Matikan dengan
# DEFNETT_DEMO_TRUST_ANCHOR=0 bila memakai baseline eksternal sendiri.
demo_anchor=${DEFNETT_DEMO_TRUST_ANCHOR:-1}
for host in server-a server-b; do
    suffix=${host#server-}
    if docker run --rm --entrypoint test -v "${project}_manifest_${suffix}_data:/manifest:ro" defnett-lab:local \
        -f /manifest/keys.json; then
        printf '   %s: manifest tersedia, dipertahankan.\n' "$host"
    elif [ "$demo_anchor" = 1 ]; then
        docker run --rm --user root --entrypoint sh \
            -v "${project}_master_${suffix}_data:/master" \
            -v "${project}_manifest_${suffix}_data:/manifest" \
            -v "$root_dir/lab/seed-fs.sh:/seed-fs.sh:ro" \
            defnett-lab:local -c "sh /seed-fs.sh $host >/dev/null && python /opt/defnett/provision_master.py --source /data --master /master --manifest /manifest/keys.json >/dev/null && chown -R 10001:10001 /master /manifest"
        printf '   %s: trust anchor demo diprovisikan dari lab/seed-fs.sh (bukan dari /data aktif).\n' "$host"
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
