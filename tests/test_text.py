from __future__ import annotations

import secrets

import pytest

from pycppcrypt.wrapper import CppCrypto, PythonCrypto


def _backends():
    yield PythonCrypto()
    try:
        yield CppCrypto()
    except FileNotFoundError:
        pass


@pytest.mark.parametrize("message", [b"", b"hello", "متن فارسی 🔐".encode("utf-8")])
def test_text_roundtrip(message: bytes) -> None:
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    aad = b"authenticated metadata"

    for backend in _backends():
        ciphertext, tag = backend.encrypt(message, key, nonce, aad)
        assert ciphertext != message or message == b""
        assert backend.decrypt(ciphertext, key, nonce, tag, aad) == message


def test_cpp_and_python_interoperate() -> None:
    try:
        cpp = CppCrypto()
    except FileNotFoundError:
        pytest.skip("C++ library has not been built")

    python = PythonCrypto()
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    aad = b"PCC interoperability"
    plaintext = secrets.token_bytes(4096)

    ciphertext, tag = cpp.encrypt(plaintext, key, nonce, aad)
    assert python.decrypt(ciphertext, key, nonce, tag, aad) == plaintext

    nonce2 = secrets.token_bytes(12)
    ciphertext2, tag2 = python.encrypt(plaintext, key, nonce2, aad)
    assert cpp.decrypt(ciphertext2, key, nonce2, tag2, aad) == plaintext
