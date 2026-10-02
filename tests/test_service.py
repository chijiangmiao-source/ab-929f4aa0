import base64
import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import service
from app.db import connect, init_db
from tests.conftest import ZERO_DIGEST, digest, h, sign


@pytest.fixture
def conn(tmp_path):
    c = connect(str(tmp_path / "t.db"))
    init_db(c)
    yield c
    c.close()


def register(conn, stream_id, pub_b64):
    r = service.create_stream(conn, stream_id, pub_b64)
    assert r.status in (200, 201)


def test_first_record_starts_at_zero_digest_and_seals(conn, key_pair, pub_b64):
    priv, _ = key_pair
    register(conn, "buoy-1", pub_b64)
    sig = sign(priv, "buoy-1", 1, ZERO_DIGEST, digest(1))
    r = service.submit_record(conn, "buoy-1", 1, h(ZERO_DIGEST), h(digest(1)), sig)
    assert r.status == 200
    assert r.body["status"] == service.SEALED
    assert r.body["water_level"] == 1


def test_out_of_order_within_window_merges_on_gap_fill(conn, key_pair, pub_b64):
    priv, _ = key_pair
    sid = "buoy-ooo"
    register(conn, sid, pub_b64)

    p1, p2, p3 = digest(1), digest(2), digest(3)
    r3 = service.submit_record(conn, sid, 3, h(p2), h(p3), sign(priv, sid, 3, p2, p3))
    assert r3.body["status"] == service.PENDING
    assert r3.body["water_level"] == 0

    r1 = service.submit_record(conn, sid, 1, h(ZERO_DIGEST), h(p1), sign(priv, sid, 1, ZERO_DIGEST, p1))
    assert r1.body["status"] == service.SEALED
    assert r1.body["water_level"] == 1

    # Filling the gap seals 2 and 3 atomically in the same response.
    r2 = service.submit_record(conn, sid, 2, h(p1), h(p2), sign(priv, sid, 2, p1, p2))
    assert r2.body["status"] == service.SEALED
    assert r2.body["water_level"] == 3

    sealed = conn.execute("SELECT COUNT(*) c FROM records WHERE stream_id=? AND sealed=1", (sid,)).fetchone()["c"]
    assert sealed == 3


def test_beyond_window_rejected_but_stream_not_frozen(conn, key_pair, pub_b64):
    priv, _ = key_pair
    sid = "buoy-win"
    register(conn, sid, pub_b64)
    far = service.WINDOW + 1
    r = service.submit_record(
        conn, sid, far, h(digest(0)), h(digest(7)),
        sign(priv, sid, far, digest(0), digest(7)),
    )
    assert r.status == 422
    assert r.body["status"] == service.OUT_OF_WINDOW

    # Window edge: exactly water_level + 32 is accepted and buffered.
    edge = service.WINDOW + 1  # water_level is 0, so 32 accepted, 33 was rejected
    ok = service.submit_record(
        conn, sid, 32, h(digest(9)), h(digest(8)),
        sign(priv, sid, 32, digest(9), digest(8)),
    )
    assert ok.status == 200 and ok.body["status"] == service.PENDING

    state = service.get_stream(conn, sid).body
    assert state["forked"] is False and state["water_level"] == 0


def test_identical_retransmit_returns_same_verdict(conn, key_pair, pub_b64):
    priv, _ = key_pair
    sid = "buoy-rex"
    register(conn, sid, pub_b64)
    p1, p2, p3 = digest(1), digest(2), digest(3)

    first = service.submit_record(conn, sid, 3, h(p2), h(p3), sign(priv, sid, 3, p2, p3))
    assert first.body["status"] == service.PENDING
    again = service.submit_record(conn, sid, 3, h(p2), h(p3), sign(priv, sid, 3, p2, p3))
    assert again.status == 200
    assert again.body["status"] == service.PENDING
    assert again.body["retransmit"] is True

    service.submit_record(conn, sid, 1, h(ZERO_DIGEST), h(p1), sign(priv, sid, 1, ZERO_DIGEST, p1))
    service.submit_record(conn, sid, 2, h(p1), h(p2), sign(priv, sid, 2, p1, p2))

    sealed_rex = service.submit_record(conn, sid, 3, h(p2), h(p3), sign(priv, sid, 3, p2, p3))
    assert sealed_rex.body["status"] == service.SEALED
    assert sealed_rex.body["water_level"] == 3

    n = conn.execute("SELECT COUNT(*) c FROM records WHERE stream_id=? AND seq=3", (sid,)).fetchone()["c"]
    assert n == 1


def test_different_payload_same_seq_freezes_stream(conn, key_pair, pub_b64):
    priv, _ = key_pair
    sid = "buoy-fork1"
    register(conn, sid, pub_b64)
    service.submit_record(conn, sid, 1, h(ZERO_DIGEST), h(digest(1)), sign(priv, sid, 1, ZERO_DIGEST, digest(1)))

    bad = service.submit_record(conn, sid, 1, h(ZERO_DIGEST), h(digest(9)), sign(priv, sid, 1, ZERO_DIGEST, digest(9)))
    assert bad.status == 409
    assert bad.body["status"] == service.FORKED
    assert bad.body["forked"] is True

    state = service.get_stream(conn, sid).body
    assert state["forked"] is True
    assert state["water_level"] == 1

    # Even a valid new record can no longer advance the prefix.
    p2 = digest(2)
    blocked = service.submit_record(conn, sid, 2, h(digest(1)), h(p2), sign(priv, sid, 2, digest(1), p2))
    assert blocked.status == 409 and blocked.body["status"] == service.FORKED
    assert service.get_stream(conn, sid).body["water_level"] == 1


def test_different_signature_same_content_freezes_stream(conn, key_pair, pub_b64):
    priv, _ = key_pair
    other = Ed25519PrivateKey.generate()
    sid = "buoy-fork2"
    register(conn, sid, pub_b64)
    service.submit_record(conn, sid, 1, h(ZERO_DIGEST), h(digest(1)), sign(priv, sid, 1, ZERO_DIGEST, digest(1)))

    forged = sign(other, sid, 1, ZERO_DIGEST, digest(1))
    r = service.submit_record(conn, sid, 1, h(ZERO_DIGEST), h(digest(1)), forged)
    assert r.status == 409 and r.body["status"] == service.FORKED


def test_prev_digest_mismatch_at_seal_time_freezes(conn, key_pair, pub_b64):
    priv, _ = key_pair
    sid = "buoy-fork3"
    register(conn, sid, pub_b64)
    p1, p2, p2_alt, p3 = digest(1), digest(2), digest(20), digest(3)

    service.submit_record(conn, sid, 1, h(ZERO_DIGEST), h(p1), sign(priv, sid, 1, ZERO_DIGEST, p1))
    # Buffered record 3 chains through p2_alt, which the chain will never produce.
    buffered = service.submit_record(conn, sid, 3, h(p2_alt), h(p3), sign(priv, sid, 3, p2_alt, p3))
    assert buffered.body["status"] == service.PENDING

    # Gap fills with record 2 yielding p2: sealing 3 detects the mismatch and
    # freezes atomically.
    r = service.submit_record(conn, sid, 2, h(p1), h(p2), sign(priv, sid, 2, p1, p2))
    assert r.status == 409 and r.body["status"] == service.FORKED
    assert r.body["water_level"] == 2

    state = service.get_stream(conn, sid).body
    assert state["forked"] is True and state["water_level"] == 2
    # The conflicting record must not have been sealed.
    row = conn.execute("SELECT sealed FROM records WHERE stream_id=? AND seq=3", (sid,)).fetchone()
    assert row["sealed"] == 0


def test_invalid_signature_on_new_seq_rejected_not_frozen(conn, key_pair, pub_b64):
    priv, _ = key_pair
    sid = "buoy-badsig"
    register(conn, sid, pub_b64)
    r = service.submit_record(conn, sid, 1, h(ZERO_DIGEST), h(digest(1)), sign(priv, sid, 1, digest(5), digest(1)))
    assert r.status == 400 and r.body["status"] == service.INVALID_SIGNATURE
    assert service.get_stream(conn, sid).body["forked"] is False
    assert conn.execute("SELECT COUNT(*) c FROM records").fetchone()["c"] == 0


def test_public_key_cannot_be_replaced(conn, key_pair, pub_b64):
    register(conn, "buoy-key", pub_b64)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    import base64

    other_pub = base64.b64encode(
        Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    ).decode()
    r = service.create_stream(conn, "buoy-key", other_pub)
    assert r.status == 409
    # Same key is idempotent.
    assert service.create_stream(conn, "buoy-key", pub_b64).status == 200


def test_unknown_stream_record_is_404(conn, key_pair):
    priv, _ = key_pair
    r = service.submit_record(conn, "nope", 1, h(ZERO_DIGEST), h(digest(1)), sign(priv, "nope", 1, ZERO_DIGEST, digest(1)))
    assert r.status == 404
