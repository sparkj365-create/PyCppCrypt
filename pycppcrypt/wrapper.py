"""ctypes bridge to the C++ OpenSSL core, plus a PyCryptodome reference backend."""

from __future__ import annotations

import ctypes
from ctypes import POINTER, c_size_t, c_ubyte
import os
from pathlib import Path
import platform
from typing import Protocol

KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16


class CryptoError(RuntimeError):
    """Base exception for cryptographic backend errors."""


class AuthenticationError(CryptoError):
    """Raised when AES-GCM authentication fails."""


class CryptoBackend(Protocol):
    def encrypt(self, plaintext: bytes, key: bytes, nonce: bytes, aad: bytes = b"") -> tuple[bytes, bytes]: ...
    def decrypt(self, ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes, aad: bytes = b"") -> bytes: ...


def _validate_inputs(key: bytes, nonce: bytes, tag: bytes | None = None) -> None:
    if len(key) != KEY_SIZE:
        raise ValueError(f"AES-256 key must be {KEY_SIZE} bytes")
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"GCM nonce must be {NONCE_SIZE} bytes")
    if tag is not None and len(tag) != TAG_SIZE:
        raise ValueError(f"GCM tag must be {TAG_SIZE} bytes")


def _library_names() -> list[str]:
    system = platform.system()
    if system == "Windows":
        return ["pycppcrypt.dll", "libpycppcrypt.dll"]
    if system == "Darwin":
        return ["libpycppcrypt.dylib", "pycppcrypt.dylib"]
    return ["libpycppcrypt.so", "pycppcrypt.so"]


def _candidate_library_paths(explicit: str | os.PathLike[str] | None = None) -> list[Path]:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit).expanduser())
    if env_path := os.environ.get("PYCPPCRYPT_LIB"):
        candidates.append(Path(env_path).expanduser())

    package_dir = Path(__file__).resolve().parent
    project_root = package_dir.parent
    search_dirs = [
        package_dir,
        project_root / "build",
        project_root / "build" / "Release",
        project_root / "build" / "Debug",
        Path.cwd() / "build",
        Path.cwd() / "build" / "Release",
        Path.cwd() / "build" / "Debug",
    ]
    for directory in search_dirs:
        for name in _library_names():
            candidates.append(directory / name)
    return candidates


def find_library(explicit: str | os.PathLike[str] | None = None) -> Path:
    checked: list[str] = []
    for candidate in _candidate_library_paths(explicit):
        resolved = candidate.resolve()
        checked.append(str(resolved))
        if resolved.is_file():
            return resolved
    raise FileNotFoundError(
        "Could not find the PyCppCrypt shared library. Build it with CMake or set "
        "PYCPPCRYPT_LIB. Checked:\n- " + "\n- ".join(checked)
    )


def _buffer(data: bytes) -> ctypes.Array[c_ubyte]:
    size = max(1, len(data))
    result = (c_ubyte * size)()
    if data:
        ctypes.memmove(result, data, len(data))
    return result


class CppCrypto:
    """AES-256-GCM backend implemented by C++ and OpenSSL."""

    def __init__(self, library_path: str | os.PathLike[str] | None = None) -> None:
        self.library_path = find_library(library_path)
        self._lib = ctypes.CDLL(str(self.library_path))
        byte_ptr = POINTER(c_ubyte)

        self._lib.pycppcrypt_encrypt.argtypes = [
            byte_ptr, c_size_t,
            byte_ptr, c_size_t,
            byte_ptr, c_size_t,
            byte_ptr, c_size_t,
            byte_ptr,
            byte_ptr, c_size_t,
        ]
        self._lib.pycppcrypt_encrypt.restype = ctypes.c_int

        self._lib.pycppcrypt_decrypt.argtypes = [
            byte_ptr, c_size_t,
            byte_ptr, c_size_t,
            byte_ptr, c_size_t,
            byte_ptr, c_size_t,
            byte_ptr, c_size_t,
            byte_ptr,
        ]
        self._lib.pycppcrypt_decrypt.restype = ctypes.c_int

    def encrypt(self, plaintext: bytes, key: bytes, nonce: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
        _validate_inputs(key, nonce)
        plain_buf = _buffer(plaintext)
        key_buf = _buffer(key)
        nonce_buf = _buffer(nonce)
        aad_buf = _buffer(aad)
        cipher_buf = _buffer(bytes(len(plaintext)))
        tag_buf = _buffer(bytes(TAG_SIZE))

        result = self._lib.pycppcrypt_encrypt(
            plain_buf, len(plaintext),
            key_buf, len(key),
            nonce_buf, len(nonce),
            aad_buf, len(aad),
            cipher_buf,
            tag_buf, TAG_SIZE,
        )
        if result != 1:
            raise CryptoError("C++ OpenSSL encryption failed")
        return bytes(cipher_buf[:len(plaintext)]), bytes(tag_buf[:TAG_SIZE])

    def decrypt(self, ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes, aad: bytes = b"") -> bytes:
        _validate_inputs(key, nonce, tag)
        cipher_buf = _buffer(ciphertext)
        key_buf = _buffer(key)
        nonce_buf = _buffer(nonce)
        aad_buf = _buffer(aad)
        tag_buf = _buffer(tag)
        plain_buf = _buffer(bytes(len(ciphertext)))

        result = self._lib.pycppcrypt_decrypt(
            cipher_buf, len(ciphertext),
            key_buf, len(key),
            nonce_buf, len(nonce),
            aad_buf, len(aad),
            tag_buf, len(tag),
            plain_buf,
        )
        if result == 0:
            raise AuthenticationError("Authentication failed: wrong key or modified data")
        if result != 1:
            raise CryptoError("C++ OpenSSL decryption failed")
        return bytes(plain_buf[:len(ciphertext)])


class PythonCrypto:
    """Reference AES-256-GCM backend. Prefers PyCryptodome, with cryptography as a fallback."""

    def __init__(self) -> None:
        self._mode: str
        try:
            from Crypto.Cipher import AES  # type: ignore
            self._aes = AES
            self._mode = "pycryptodome"
            return
        except ImportError:
            pass

        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError as exc:
            raise ImportError(
                "The Python backend requires PyCryptodome (recommended) or cryptography"
            ) from exc
        self._aesgcm = AESGCM
        self._mode = "cryptography"

    def encrypt(self, plaintext: bytes, key: bytes, nonce: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
        _validate_inputs(key, nonce)
        if self._mode == "pycryptodome":
            cipher = self._aes.new(key, self._aes.MODE_GCM, nonce=nonce, mac_len=TAG_SIZE)
            if aad:
                cipher.update(aad)
            return cipher.encrypt_and_digest(plaintext)

        combined = self._aesgcm(key).encrypt(nonce, plaintext, aad or None)
        return combined[:-TAG_SIZE], combined[-TAG_SIZE:]

    def decrypt(self, ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes, aad: bytes = b"") -> bytes:
        _validate_inputs(key, nonce, tag)
        if self._mode == "pycryptodome":
            cipher = self._aes.new(key, self._aes.MODE_GCM, nonce=nonce, mac_len=TAG_SIZE)
            if aad:
                cipher.update(aad)
            try:
                return cipher.decrypt_and_verify(ciphertext, tag)
            except ValueError as exc:
                raise AuthenticationError("Authentication failed: wrong key or modified data") from exc

        try:
            return self._aesgcm(key).decrypt(nonce, ciphertext + tag, aad or None)
        except Exception as exc:
            raise AuthenticationError("Authentication failed: wrong key or modified data") from exc
