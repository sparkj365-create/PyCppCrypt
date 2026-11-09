from __future__ import annotations

import secrets

import pytest

from pycppcrypt.file_format import build_aad, pack_encrypted, parse_encrypted
from pycppcrypt.key_manager import KeyFileError, generate_key, load_key, save_key
from pycppcrypt.wrapper import AuthenticationError, PythonCrypto


def test_modified_ciphertext_is_rejected() -> None:
    backend = PythonCrypto()
    plaintext = b"important authenticated content"
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    aad = build_aad(nonce, len(plaintext))
    ciphertext, tag = backend.encrypt(plaintext, key, nonce, aad)
    blob = bytearray(pack_encrypted(nonce, tag, ciphertext, len(plaintext)))
    blob[-1] ^= 0x01

    payload = parse_encrypted(bytes(blob))
    with pytest.raises(AuthenticationError):
        backend.decrypt(
            payload.ciphertext,
            key,
            payload.nonce,
            payload.tag,
            payload.aad,
        )


def test_modified_authenticated_header_is_rejected() -> None:
    backend = PythonCrypto()
    plaintext = b"hello"
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    aad = build_aad(nonce, len(plaintext))
    ciphertext, tag = backend.encrypt(plaintext, key, nonce, aad)
    blob = bytearray(pack_encrypted(nonce, tag, ciphertext, len(plaintext)))

    # Change a nonce byte inside the authenticated header.
    blob[16] ^= 0x01
    payload = parse_encrypted(bytes(blob))
    with pytest.raises(AuthenticationError):
        backend.decrypt(
            payload.ciphertext,
            key,
            payload.nonce,
            payload.tag,
            payload.aad,
        )


def test_wrong_key_password_is_rejected(tmp_path) -> None:
    path = tmp_path / "key.json"
    save_key(generate_key(), path, "right-password")
    with pytest.raises(KeyFileError):
        load_key(path, "wrong-password")
