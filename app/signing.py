"""Canonical binary message encoding and Ed25519 verification.

The signed message is the exact concatenation of:

  * stream id bytes, prefixed by its length as an unsigned 16-bit big-endian
  * unsigned 64-bit big-endian sequence number
  * 32-byte previous digest
  * 32-byte payload digest

Signatures are created and checked against these raw bytes only; the JSON
request envelope is never re-encoded for verification.
"""
from __future__ import annotations

import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ZERO_DIGEST = b"\x00" * 32
_DIGEST_LEN = 32
_MAX_ID_LEN = 0xFFFF


def encode_message(stream_id: str, seq: int, prev_digest: bytes, payload_digest: bytes) -> bytes:
    """Build the canonical binary message covered by the Ed25519 signature."""
    if not isinstance(stream_id, str):
        raise ValueError("stream_id must be str")
    id_bytes = stream_id.encode("ascii")
    if len(id_bytes) == 0:
        raise ValueError("stream_id must not be empty")
    if len(id_bytes) > _MAX_ID_LEN:
        raise ValueError("stream_id too long")
    if not 0 <= seq <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("seq out of uint64 range")
    if len(prev_digest) != _DIGEST_LEN:
        raise ValueError("prev_digest must be 32 bytes")
    if len(payload_digest) != _DIGEST_LEN:
        raise ValueError("payload_digest must be 32 bytes")
    return struct.pack(">H", len(id_bytes)) + id_bytes + struct.pack(">Q", seq) + prev_digest + payload_digest


def decode_public_key(key_b64: str) -> Ed25519PublicKey:
    """Decode a base64 (standard, unpadded tolerated) Ed25519 public key."""
    import base64

    raw = base64.b64decode(key_b64, validate=True)
    if len(raw) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def verify_signature(public_key: Ed25519PublicKey, signature: bytes, message: bytes) -> bool:
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False
