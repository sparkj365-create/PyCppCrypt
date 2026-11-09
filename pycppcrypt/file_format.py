"""Authenticated binary container format for PyCppCrypt."""

from __future__ import annotations

from dataclasses import dataclass
import struct

MAGIC = b"PCC1"
VERSION = 1
FLAGS = 0
NONCE_SIZE = 12
TAG_SIZE = 16
_HEADER = struct.Struct(">4sBBBBQ")


class FileFormatError(ValueError):
    """Raised when an encrypted payload has an invalid format."""


@dataclass(frozen=True)
class EncryptedPayload:
    nonce: bytes
    tag: bytes
    ciphertext: bytes
    original_size: int
    aad: bytes


def build_aad(nonce: bytes, original_size: int, tag_len: int = TAG_SIZE) -> bytes:
    """Build the authenticated header used as AES-GCM AAD."""
    if len(nonce) != NONCE_SIZE:
        raise FileFormatError(f"Nonce must be {NONCE_SIZE} bytes")
    if tag_len != TAG_SIZE:
        raise FileFormatError(f"Tag must be {TAG_SIZE} bytes")
    if original_size < 0 or original_size > (2**64 - 1):
        raise FileFormatError("Invalid original size")

    fixed = _HEADER.pack(
        MAGIC,
        VERSION,
        FLAGS,
        len(nonce),
        tag_len,
        original_size,
    )
    return fixed + nonce


def pack_encrypted(nonce: bytes, tag: bytes, ciphertext: bytes, original_size: int) -> bytes:
    """Pack an encrypted payload into the PCC1 binary format."""
    if len(tag) != TAG_SIZE:
        raise FileFormatError(f"Tag must be {TAG_SIZE} bytes")
    if len(ciphertext) != original_size:
        raise FileFormatError("Ciphertext size does not match original size")
    aad = build_aad(nonce, original_size, len(tag))
    return aad + tag + ciphertext


def parse_encrypted(blob: bytes) -> EncryptedPayload:
    """Parse and validate a PCC1 encrypted payload."""
    minimum = _HEADER.size + NONCE_SIZE + TAG_SIZE
    if len(blob) < minimum:
        raise FileFormatError("Encrypted payload is too short")

    magic, version, flags, nonce_len, tag_len, original_size = _HEADER.unpack_from(blob, 0)
    if magic != MAGIC:
        raise FileFormatError("Invalid file magic")
    if version != VERSION:
        raise FileFormatError(f"Unsupported format version: {version}")
    if flags != FLAGS:
        raise FileFormatError(f"Unsupported flags: {flags}")
    if nonce_len != NONCE_SIZE:
        raise FileFormatError(f"Unsupported nonce length: {nonce_len}")
    if tag_len != TAG_SIZE:
        raise FileFormatError(f"Unsupported tag length: {tag_len}")

    aad_end = _HEADER.size + nonce_len
    tag_end = aad_end + tag_len
    if tag_end > len(blob):
        raise FileFormatError("Truncated encrypted payload")

    aad = blob[:aad_end]
    nonce = blob[_HEADER.size:aad_end]
    tag = blob[aad_end:tag_end]
    ciphertext = blob[tag_end:]

    if len(ciphertext) != original_size:
        raise FileFormatError("Ciphertext size does not match authenticated metadata")

    return EncryptedPayload(
        nonce=nonce,
        tag=tag,
        ciphertext=ciphertext,
        original_size=original_size,
        aad=aad,
    )
