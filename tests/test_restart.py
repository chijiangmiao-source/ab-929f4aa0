"""Restart recovery: water levels are rebuilt from persisted records."""
import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import service
from app.db import connect, init_db
from tests.conftest import ZERO_DIGEST, digest, h, sign


def test_rebuild_after_restart_buffered_then_gap_fill(tmp_path):
    db_path = str(tmp_path / "r.db")
    priv = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    sid = "buoy-restart"

    c1 = connect(db_path)
    init_db(c1)
    service.create_stream(c1, sid, pub_b64)
    p1, p2, p3 = digest(1), digest(2), digest(3)
    # 1 and 3 submitted; 3 stays buffered across the restart.
    service.submit_record(c1, sid, 1, h(ZERO_DIGEST), h(p1), sign(priv, sid, 1, ZERO_DIGEST, p1))
    buffered = service.submit_record(c1, sid, 3, h(p2), h(p3), sign(priv, sid, 3, p2, p3))
    assert buffered.body["status"] == service.PENDING
    c1.close()

    # Simulate process restart with a fresh connection (no cached state).
    c2 = connect(db_path)
    init_db(c2)
    rebuilt = service.rebuild_water_levels(c2)
    assert rebuilt[sid] == 1
    state = service.get_stream(c2, sid).body
    assert state["water_level"] == 1
    assert state["last_digest"] == h(p1)
    assert state["forked"] is False

    # Retransmit of the already-sealed record returns the same verdict...
    rex1 = service.submit_record(c2, sid, 1, h(ZERO_DIGEST), h(p1), sign(priv, sid, 1, ZERO_DIGEST, p1))
    assert rex1.body["retransmit"] is True and rex1.body["status"] == service.SEALED
    # ...and the buffered 3 is still pending until gap 2 arrives after restart.
    rex3 = service.submit_record(c2, sid, 3, h(p2), h(p3), sign(priv, sid, 3, p2, p3))
    assert rex3.body["status"] == service.PENDING and rex3.body["retransmit"] is True

    fill = service.submit_record(c2, sid, 2, h(p1), h(p2), sign(priv, sid, 2, p1, p2))
    assert fill.body["status"] == service.SEALED and fill.body["water_level"] == 3
    c2.close()


def test_rebuild_forked_stream_stays_frozen(tmp_path):
    db_path = str(tmp_path / "f.db")
    priv = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    sid = "buoy-frozen-restart"

    c1 = connect(db_path)
    init_db(c1)
    service.create_stream(c1, sid, pub_b64)
    service.submit_record(c1, sid, 1, h(ZERO_DIGEST), h(digest(1)), sign(priv, sid, 1, ZERO_DIGEST, digest(1)))
    service.submit_record(c1, sid, 1, h(ZERO_DIGEST), h(digest(2)), sign(priv, sid, 1, ZERO_DIGEST, digest(2)))
    assert service.get_stream(c1, sid).body["forked"] is True
    c1.close()

    c2 = connect(db_path)
    init_db(c2)
    service.rebuild_water_levels(c2)
    state = service.get_stream(c2, sid).body
    assert state["forked"] is True and state["water_level"] == 1

    p2 = digest(2)
    blocked = service.submit_record(c2, sid, 2, h(digest(1)), h(p2), sign(priv, sid, 2, digest(1), p2))
    assert blocked.status == 409 and blocked.body["status"] == service.FORKED
    c2.close()
