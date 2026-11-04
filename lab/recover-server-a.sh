#!/bin/sh
# DEFNETT lab - pinta rejoin backend lewat persetujuan operator.
# Endpoint /v1/lab/recover/<host> sejak tahap 1 butuh sesi operator + CSRF,
# jadi skrip ini login dulu, simpan cookie sementara, lalu mengirim header CSRF.
# Pemakaian: sh recover-server-a.sh [server-a|server-b]
# Kredensial dari env DEFNETT_OPERATOR_USER dan DEFNETT_OPERATOR_PASS,
# atau ditanyakan saat dijalankan. Route lain tetap tanpa nama rahasia di skrip.
set -eu

BASE="${DEFNETT_COLLECTOR:-http://127.0.0.1:8090}"
HOST_ID="${1:-server-a}"

if [ -z "${DEFNETT_OPERATOR_USER:-}" ]; then
  printf 'operator: '
  read -r DEFNETT_OPERATOR_USER
fi
if [ -z "${DEFNETT_OPERATOR_PASS:-}" ]; then
  printf 'sandi: '
  read -r DEFNETT_OPERATOR_PASS
fi

COOKIE="$(mktemp)"
trap 'rm -f "$COOKIE"' EXIT
# Catatan: kata sandi berisi " atau \ akan merusak JSON; cukup untuk akun lab.
LOGIN_JSON="$(curl --fail --silent --show-error \
  -c "$COOKIE" -H 'Content-Type: application/json' \
  -d "{\"username\": \"${DEFNETT_OPERATOR_USER}\", \"password\": \"${DEFNETT_OPERATOR_PASS}\"}" \
  "$BASE/v1/operator/login")"

CSRF="$(printf '%s' "$LOGIN_JSON" | sed -n 's/.*"csrf"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
[ -n "$CSRF" ] || { echo 'login gagal: CSRF tidak ditemukan di jawaban' >&2; exit 1; }

curl --fail --silent --show-error \
  -b "$COOKIE" -H "X-DEFNETT-CSRF: $CSRF" \
  --request POST "$BASE/v1/lab/recover/$HOST_ID"
printf '\n'
