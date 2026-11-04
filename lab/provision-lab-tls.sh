#!/bin/sh
# Provision local lab CA and per-service certificates outside the repository.
set -eu
out=${1:?usage: provision-lab-tls.sh OUTPUT_DIRECTORY}
command -v openssl >/dev/null 2>&1 || { echo "openssl is required" >&2; exit 1; }
mkdir -p "$out"
chmod 0700 "$out"
if [ -e "$out/ca.key" ]; then
    [ -f "$out/ca.crt" ] || { echo "CA key exists without CA certificate; refusing overwrite" >&2; exit 1; }
else
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$out/ca.key"
    chmod 0600 "$out/ca.key"
    openssl req -x509 -new -key "$out/ca.key" -sha256 -days 365 -subj "/CN=DEFNETT Local Lab CA" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$out/ca.crt"
fi
issue() {
    name=$1
    san=$2
    if [ -f "$out/$name.crt" ] || [ -f "$out/$name.key" ]; then
        [ -f "$out/$name.crt" ] && [ -f "$out/$name.key" ] || { echo "partial certificate for $name; refusing overwrite" >&2; exit 1; }
        openssl verify -CAfile "$out/ca.crt" "$out/$name.crt" >/dev/null || { echo "invalid existing certificate for $name" >&2; exit 1; }
        return
    fi
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$out/$name.key"
    # The enclosing directory is 0700 and bind-mounted per-service. Docker's
    # non-root UID differs from the host owner, so readable key mode is needed
    # inside the private host directory; unrelated services never mount it.
    chmod 0644 "$out/$name.key"
    openssl req -new -key "$out/$name.key" -subj "/CN=$name" -out "$out/$name.csr"
    printf '%s\n' "basicConstraints=critical,CA:FALSE" "keyUsage=critical,digitalSignature,keyEncipherment" \
        "extendedKeyUsage=serverAuth,clientAuth" "subjectAltName=$san" > "$out/$name.ext"
    openssl x509 -req -in "$out/$name.csr" -CA "$out/ca.crt" -CAkey "$out/ca.key" \
        -CAcreateserial -days 90 -sha256 -extfile "$out/$name.ext" -out "$out/$name.crt"
    rm -f "$out/$name.csr" "$out/$name.ext"
    chmod 0644 "$out/$name.crt"
}
issue collector "DNS:collector,DNS:localhost,IP:127.0.0.1"
issue executor "DNS:executor"
issue approval-authority "DNS:approval-authority,DNS:localhost,IP:127.0.0.1"
issue remediator-a "DNS:remediator-a"
issue remediator-b "DNS:remediator-b"
issue collector-vm "DNS:collector,IP:192.168.56.20"
issue executor-vm "DNS:localhost,IP:127.0.0.1"
issue remediator-a-vm "DNS:server-a,IP:192.168.56.11"
issue remediator-b-vm "DNS:server-b,IP:192.168.56.12"
chmod 0644 "$out/ca.crt"
printf 'Lab certificates provisioned in %s; CA private key stays on this host.\n' "$out"
