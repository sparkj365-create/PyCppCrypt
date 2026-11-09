"""Command-line interface for PyCppCrypt."""

from __future__ import annotations

import argparse
import base64
from getpass import getpass
import os
from pathlib import Path
import secrets
import sys
import tempfile
import time

from .file_format import NONCE_SIZE, TAG_SIZE, build_aad, pack_encrypted, parse_encrypted
from .key_manager import KeyFileError, generate_key, load_key, save_key
from .wrapper import AuthenticationError, CppCrypto, CryptoBackend, CryptoError, PythonCrypto


def _password(args: argparse.Namespace, *, confirm: bool = False) -> str:
    if args.password_env:
        value = os.environ.get(args.password_env)
        if value is None:
            raise ValueError(f"Environment variable {args.password_env!r} is not set")
        return value

    first = getpass("Key-file password: ")
    if confirm:
        second = getpass("Confirm password: ")
        if first != second:
            raise ValueError("Passwords do not match")
    return first


def _backend(args: argparse.Namespace) -> CryptoBackend:
    if args.backend == "python":
        return PythonCrypto()
    return CppCrypto(args.lib)


def _atomic_write(path: Path, data: bytes, *, force: bool) -> None:
    path = path.expanduser().resolve()
    if path.exists() and not force:
        raise FileExistsError(f"Output already exists: {path}. Use --force to overwrite.")
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def _load_user_key(args: argparse.Namespace) -> bytes:
    return load_key(args.key, _password(args))


def cmd_keygen(args: argparse.Namespace) -> int:
    key = generate_key()
    destination = save_key(key, args.out, _password(args, confirm=True))
    print(f"Key file created: {destination}")
    return 0


def cmd_encrypt_file(args: argparse.Namespace) -> int:
    source = Path(args.input)
    plaintext = source.read_bytes()
    key = _load_user_key(args)
    nonce = secrets.token_bytes(NONCE_SIZE)
    aad = build_aad(nonce, len(plaintext), TAG_SIZE)
    ciphertext, tag = _backend(args).encrypt(plaintext, key, nonce, aad)
    blob = pack_encrypted(nonce, tag, ciphertext, len(plaintext))
    _atomic_write(Path(args.output), blob, force=args.force)
    print(f"Encrypted {len(plaintext)} bytes -> {args.output}")
    return 0


def cmd_decrypt_file(args: argparse.Namespace) -> int:
    payload = parse_encrypted(Path(args.input).read_bytes())
    key = _load_user_key(args)
    plaintext = _backend(args).decrypt(
        payload.ciphertext,
        key,
        payload.nonce,
        payload.tag,
        payload.aad,
    )
    if len(plaintext) != payload.original_size:
        raise CryptoError("Decrypted size does not match authenticated metadata")
    _atomic_write(Path(args.output), plaintext, force=args.force)
    print(f"Decrypted {len(plaintext)} bytes -> {args.output}")
    return 0


def cmd_encrypt_text(args: argparse.Namespace) -> int:
    plaintext = args.text.encode("utf-8")
    key = _load_user_key(args)
    nonce = secrets.token_bytes(NONCE_SIZE)
    aad = build_aad(nonce, len(plaintext), TAG_SIZE)
    ciphertext, tag = _backend(args).encrypt(plaintext, key, nonce, aad)
    token = base64.urlsafe_b64encode(
        pack_encrypted(nonce, tag, ciphertext, len(plaintext))
    ).decode("ascii")
    print(token)
    return 0


def cmd_decrypt_text(args: argparse.Namespace) -> int:
    try:
        blob = base64.urlsafe_b64decode(args.token.encode("ascii"))
    except Exception as exc:
        raise ValueError("Invalid base64 token") from exc
    payload = parse_encrypted(blob)
    key = _load_user_key(args)
    plaintext = _backend(args).decrypt(
        payload.ciphertext,
        key,
        payload.nonce,
        payload.tag,
        payload.aad,
    )
    print(plaintext.decode("utf-8"))
    return 0


def _time_backend(name: str, backend: CryptoBackend, data: bytes, rounds: int) -> float:
    key = secrets.token_bytes(32)
    total = 0.0
    for _ in range(rounds):
        nonce = secrets.token_bytes(NONCE_SIZE)
        start = time.perf_counter()
        backend.encrypt(data, key, nonce)
        total += time.perf_counter() - start
    mib = (len(data) * rounds) / (1024 * 1024)
    speed = mib / total
    print(f"{name:14s}: {speed:10.2f} MiB/s")
    return speed


def cmd_benchmark(args: argparse.Namespace) -> int:
    if args.size_mb <= 0 or args.rounds <= 0:
        raise ValueError("--size-mb and --rounds must be positive")
    data = secrets.token_bytes(args.size_mb * 1024 * 1024)
    print(f"AES-256-GCM benchmark: {args.size_mb} MiB × {args.rounds} rounds")
    cpp_speed = _time_backend("C++ / OpenSSL", CppCrypto(args.lib), data, args.rounds)
    py_speed = _time_backend("Python / Crypto", PythonCrypto(), data, args.rounds)
    print(f"Ratio (C++/Python): {cpp_speed / py_speed:.2f}x")
    return 0


def _add_password_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--password-env",
        metavar="NAME",
        help="Read the key-file password from an environment variable instead of prompting",
    )


def _add_backend_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--fast",
        dest="backend",
        action="store_const",
        const="cpp",
        help="Use the C++/OpenSSL backend (default)",
    )
    group.add_argument(
        "--python",
        dest="backend",
        action="store_const",
        const="python",
        help="Use the PyCryptodome reference backend",
    )
    parser.set_defaults(backend="cpp")
    parser.add_argument("--lib", help="Explicit path to the compiled shared library")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pycppcrypt",
        description="AES-256-GCM file and text encryption using Python + C++/OpenSSL.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    keygen = subparsers.add_parser("keygen", help="Create a password-protected 256-bit key file")
    keygen.add_argument("--out", required=True, help="Output JSON key file")
    _add_password_option(keygen)
    keygen.set_defaults(func=cmd_keygen)

    enc_file = subparsers.add_parser("encrypt-file", help="Encrypt a file")
    enc_file.add_argument("input")
    enc_file.add_argument("output")
    enc_file.add_argument("--key", required=True, help="Password-protected key JSON")
    enc_file.add_argument("--force", action="store_true")
    _add_password_option(enc_file)
    _add_backend_options(enc_file)
    enc_file.set_defaults(func=cmd_encrypt_file)

    dec_file = subparsers.add_parser("decrypt-file", help="Decrypt and authenticate a file")
    dec_file.add_argument("input")
    dec_file.add_argument("output")
    dec_file.add_argument("--key", required=True, help="Password-protected key JSON")
    dec_file.add_argument("--force", action="store_true")
    _add_password_option(dec_file)
    _add_backend_options(dec_file)
    dec_file.set_defaults(func=cmd_decrypt_file)

    enc_text = subparsers.add_parser("encrypt-text", help="Encrypt UTF-8 text")
    enc_text.add_argument("text")
    enc_text.add_argument("--key", required=True)
    _add_password_option(enc_text)
    _add_backend_options(enc_text)
    enc_text.set_defaults(func=cmd_encrypt_text)

    dec_text = subparsers.add_parser("decrypt-text", help="Decrypt a base64 text token")
    dec_text.add_argument("token")
    dec_text.add_argument("--key", required=True)
    _add_password_option(dec_text)
    _add_backend_options(dec_text)
    dec_text.set_defaults(func=cmd_decrypt_text)

    benchmark = subparsers.add_parser("benchmark", help="Compare C++ and Python AES-GCM speed")
    benchmark.add_argument("--size-mb", type=int, default=16)
    benchmark.add_argument("--rounds", type=int, default=3)
    benchmark.add_argument("--lib", help="Explicit path to the compiled shared library")
    benchmark.set_defaults(func=cmd_benchmark)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (AuthenticationError, CryptoError, KeyFileError, FileNotFoundError,
            FileExistsError, ValueError, OSError, UnicodeDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
