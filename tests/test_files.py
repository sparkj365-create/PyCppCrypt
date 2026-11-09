from __future__ import annotations

import secrets

from pycppcrypt.file_format import build_aad, pack_encrypted, parse_encrypted
from pycppcrypt.key_manager import generate_key, load_key, save_key
from pycppcrypt.wrapper import PythonCrypto


def test_binary_container_roundtrip() -> None:
    backend = PythonCrypto()
    plaintext = secrets.token_bytes(10_000)
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    aad = build_aad(nonce, len(plaintext))

    ciphertext, tag = backend.encrypt(plaintext, key, nonce, aad)
    blob = pack_encrypted(nonce, tag, ciphertext, len(plaintext))
    payload = parse_encrypted(blob)

    assert backend.decrypt(
        payload.ciphertext,
        key,
        payload.nonce,
        payload.tag,
        payload.aad,
    ) == plaintext


def test_password_protected_key_file(tmp_path) -> None:
    key = generate_key()
    path = tmp_path / "key.json"
    save_key(key, path, "correct horse battery staple")
    assert load_key(path, "correct horse battery staple") == key
