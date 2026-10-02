import base64
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.signing import ZERO_DIGEST, encode_message


@pytest.fixture
def key_pair():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


@pytest.fixture
def pub_b64(key_pair):
    _, pub = key_pair
    return base64.b64encode(pub.public_bytes_raw()).decode()


def sign(priv, stream_id, seq, prev, payload):
    return base64.b64encode(priv.sign(encode_message(stream_id, seq, prev, payload))).decode()


def digest(n: int) -> bytes:
    return bytes([n]) * 32


def h(b: bytes) -> str:
    return b.hex()
