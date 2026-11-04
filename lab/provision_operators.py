"""CLI pemasangan akun operator. Jalankan manual oleh pemilik sistem; tidak
dipanggil otomatis oleh kode manapun. Berkas akun dienkripsi dengan PBKDF2 dan
berhak akses 0600.
"""
import argparse
import getpass
import json
import os
import secrets
import sys

import operator_auth

FILE_MODE = 0o600
VALID_ROLES = ("viewer", "operator")


def load_or_init(path):
    try:
        with open(path, "r", encoding="utf-8") as stream:
            data = json.load(stream)
        operator_auth._sanitize_users(data)
    except FileNotFoundError:
        return {"version": 1, "operators": {}}
    except (OSError, ValueError):
        raise SystemExit(f"berkas operator tidak layak: {path}; perbaiki atau hapus manual")
    return data


def write_file(path, data):
    temporary = f"{path}.tmp"
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    with open(temporary, "w", encoding="utf-8") as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, FILE_MODE)
    os.replace(temporary, path)


def add_operator(path, username, role, password, force=False):
    if role not in VALID_ROLES:
        raise SystemExit("peran harus viewer atau operator")
    if not isinstance(username, str) or not username.strip() or len(username.strip()) > 64:
        raise SystemExit("nama user tidak valid")
    if not isinstance(password, str) or len(password) < 12:
        raise SystemExit("kata sandi minimal 12 karakter")
    data = load_or_init(path)
    if username in data["operators"] and not force:
        raise SystemExit(f"akun {username} sudah ada; pakai --force untuk menimpa")
    salt = secrets.token_hex(16)
    data["operators"][username] = {
        "salt": salt,
        "hash": operator_auth.hash_password(password, salt, operator_auth.DEFAULT_ITERATIONS),
        "iterations": operator_auth.DEFAULT_ITERATIONS,
        "role": role,
    }
    write_file(path, data)
    operator_auth._file_cache.update({"mtime": None, "users": None, "failures": ""})
    return username


def main(argv=None):
    parser = argparse.ArgumentParser(description="Kelola akun operator DEFNETT")
    parser.add_argument("--file", default=os.environ.get("OPERATOR_AUTH_FILE", "/ops/operator_auth.json"))
    parser.add_argument("--add", metavar="USER", required=True)
    parser.add_argument("--role", default="operator", choices=VALID_ROLES)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--password-stdin", action="store_true", help="baca kata sandi dari stdin, bukan prompt")
    args = parser.parse_args(argv)
    password = os.environ.get("DEFNETT_OPERATOR_PASSWORD")
    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    if not password:
        password = getpass.getpass(f"Kata sandi untuk {args.add}: ")
        if getpass.getpass("Ulangi kata sandi: ") != password:
            raise SystemExit("kata sandi tidak sama; akun tidak diubah")
    add_operator(args.file, args.add, args.role, password, args.force)
    print(f"akun {args.add} ({args.role}) tersimpan di {args.file} [mode 0{FILE_MODE:o}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
