"""Password-protected AES key generation and storage."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import tempfile
from typing import Any

from .wrapper import AuthenticationError, PythonCrypto

KEY_SIZE = 32
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1


class KeyFileError(ValueError):
    """Raised when a key file cannot be parsed or authenticated."""


def generate_key() -> bytes:
    """Generate a fresh 256-bit AES key."""
    return secrets.token_bytes(KEY_SIZE)


def fingerprint(key: bytes) -> str:
    """Return a non-secret SHA-256 fingerprint for key identification."""
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes")
    return "sha256:" + hashlib.sha256(key).hexdigest()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: Any, field: str) -> bytes:
    if not isinstance(value, str):
        raise KeyFileError(f"Invalid {field}")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise KeyFileError(f"Invalid base64 in {field}") from exc


def _derive_kek(password: str, salt: bytes, *, n: int = SCRYPT_N, r: int = SCRYPT_R, p: int = SCRYPT_P) -> bytes:
    if not password:
        raise ValueError("Password must not be empty")
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=KEY_SIZE,
    )


def save_key(key: bytes, path: str | os.PathLike[str], password: str) -> Path:
    """Encrypt an AES key with a password-derived key and save it atomically as JSON."""
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes")

    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    kek = _derive_kek(password, salt)
    ciphertext, tag = PythonCrypto().encrypt(key, kek, nonce)

    document = {
        "format": "pycppcrypt-key",
        "version": 1,
        "fingerprint": fingerprint(key),
        "kdf": {
            "name": "scrypt",
            "n": SCRYPT_N,
            "r": SCRYPT_R,
            "p": SCRYPT_P,
            "salt": _b64(salt),
        },
        "cipher": {
            "name": "AES-256-GCM",
            "nonce": _b64(nonce),
            "ciphertext": _b64(ciphertext),
            "tag": _b64(tag),
        },
    }

    destination = Path(path).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)

    fd, temp_name = tempfile.mkstemp(prefix=destination.name + ".", dir=destination.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temp_name, 0o600)
        except OSError:
            pass
        os.replace(temp_name, destination)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise

    return destination


def load_key(path: str | os.PathLike[str], password: str) -> bytes:
    """Load and authenticate a password-protected AES key file."""
    source = Path(path).expanduser()
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise KeyFileError(f"Could not read key file: {source}") from exc

    try:
        if document.get("format") != "pycppcrypt-key" or document.get("version") != 1:
            raise KeyFileError("Unsupported key file format")

        kdf = document["kdf"]
        cipher_data = document["cipher"]
        if kdf.get("name") != "scrypt" or cipher_data.get("name") != "AES-256-GCM":
            raise KeyFileError("Unsupported key protection settings")

        n = int(kdf["n"])
        r = int(kdf["r"])
        p = int(kdf["p"])
        if n < 2**14 or n > 2**20 or r <= 0 or p <= 0:
            raise KeyFileError("Unsafe or invalid scrypt parameters")

        salt = _unb64(kdf["salt"], "salt")
        nonce = _unb64(cipher_data["nonce"], "nonce")
        ciphertext = _unb64(cipher_data["ciphertext"], "ciphertext")
        tag = _unb64(cipher_data["tag"], "tag")
        expected_fingerprint = document["fingerprint"]
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, KeyFileError):
            raise
        raise KeyFileError("Malformed key file") from exc

    if len(salt) != SALT_SIZE or len(nonce) != NONCE_SIZE or len(tag) != TAG_SIZE:
        raise KeyFileError("Malformed key file lengths")

    kek = _derive_kek(password, salt, n=n, r=r, p=p)
    try:
        key = PythonCrypto().decrypt(ciphertext, kek, nonce, tag)
    except AuthenticationError as exc:
        raise KeyFileError("Wrong password or modified key file") from exc

    if len(key) != KEY_SIZE or not hmac.compare_digest(fingerprint(key), expected_fingerprint):
        raise KeyFileError("Key fingerprint verification failed")
    return key
