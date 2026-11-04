"""CLI sumber kepercayaan master: menyalin kunci TERVERIFIKASI ke volume /master
dan membuat manifes sha256. Tidak ada kode yang berjalan otomatis memanggil ini;
pembaruan master selalu adalah keputusan operator terpelajar.

Aturan:
- Hanya file kunci ber-marker yang sencegah dipindahkan.
- Master yang sudah ada dan beda isi ditolak tanpa --force.
- Manifes yaitu jangkar: remediator menolak pemulihan bila isi master tidak cocok.
"""
import argparse
import hashlib
import json
import os
import sys
import uuid
from pathlib import Path

KEY_NAMES = ("etc/kunci1.dat", "etc/kunci2.dat")
KEY_MARKER = b"SECRET kunci"
MAX_FILE_SIZE = 1024 * 1024


def atomic_write(path, content, mode):
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)
    if hashlib.sha256(temporary.read_bytes()).hexdigest() != hashlib.sha256(content).hexdigest():
        os.unlink(temporary)
        raise OSError("write_hash_mismatch")
    os.replace(temporary, path)


def read_source(source_root, name):
    relative = name if name in ("etc/kunci1.dat", "etc/kunci2.dat") else None
    candidates = []
    if relative:
        candidates.append(source_root / relative)
    candidates.append(source_root / os.path.basename(relative or name))
    for candidate in candidates:
        if candidate.is_file():
            metadata = candidate.stat()
            if metadata.st_size > MAX_FILE_SIZE:
                raise SystemExit(f"{candidate} terlalu besar")
            content = candidate.read_bytes()
            if KEY_MARKER not in content:
                raise SystemExit(f"{candidate} tidak memuat penanda kunci; bukan file kunci terverifikasi")
            return content
    raise SystemExit(f"sumber {name} tidak ditemukan di {source_root}")


def write_manifest(master_root, manifest_path):
    entries = {}
    for name in KEY_NAMES:
        master = master_root / os.path.basename(name)
        try:
            content = master.read_bytes()
        except FileNotFoundError as error:
            raise SystemExit(f"master {master} hilang; salin kunci dulu sebelum membuat manifes") from error
        if KEY_MARKER not in content:
            raise SystemExit(f"master {master} tidak memuat penanda; tolak membuat manifes")
        entries[os.path.basename(name)] = {"sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)}
    manifest = {"version": 1, "files": entries}
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(manifest_path, json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8"), 0o644)
    return manifest


def provision(source_root, master_root, manifest_path, force=False):
    master_root.mkdir(parents=True, exist_ok=True)
    for name in KEY_NAMES:
        content = read_source(source_root, name)
        target = master_root / os.path.basename(name)
        try:
            existing = target.read_bytes()
        except FileNotFoundError:
            existing = None
        if existing is not None and existing != content and not force:
            raise SystemExit(f"{target} beda isi; pakai --force hanya bila ini salinan kunci baru yang sah")
        if existing != content:
            atomic_write(target, content, 0o644)
    return write_manifest(master_root, manifest_path)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Kunci salinan master + manifes kepercayaan DEFNETT")
    parser.add_argument("--source", required=True, help="folder berisi kunci bersih (etc/kunci1.dat dst.)")
    parser.add_argument("--master", required=True, help="folder master, contoh /master")
    parser.add_argument("--manifest", default=os.environ.get("MANIFEST_PATH", "/manifest/keys.json"))
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    source_root = Path(os.path.realpath(args.source))
    if not source_root.is_dir():
        raise SystemExit(f"sumber {source_root} bukan folder")
    manifest = provision(source_root, Path(os.path.realpath(args.master)), Path(os.path.realpath(str(args.manifest))), args.force)
    for name, entry in manifest["files"].items():
        print(f"{name}: sha256={entry['sha256']} bytes={entry['bytes']}")
    print(f"manifes ditulis ke {os.path.realpath(str(args.manifest))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
