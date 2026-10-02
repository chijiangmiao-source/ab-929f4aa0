"""Concurrency: parallel connections/threads must not double-seal or observe
transient inconsistent success.
"""
import base64
import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import service
from app.db import connect, init_db
from tests.conftest import ZERO_DIGEST, digest, h, sign


def test_concurrent_retransmits_seal_once(tmp_path):
    db_path = str(tmp_path / "c.db")
    priv = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    sid = "buoy-conc"

    admin = connect(db_path)
    init_db(admin)
    service.create_stream(admin, sid, pub_b64)
    admin.close()

    n_threads = 12
    results = [None] * n_threads
    errors = []

    def worker(i):
        try:
            c = connect(db_path)
            try:
                results[i] = service.submit_record(
                    c, sid, 1, h(ZERO_DIGEST), h(digest(1)),
                    sign(priv, sid, 1, ZERO_DIGEST, digest(1)),
                )
            finally:
                c.close()
        except BaseException as exc:  # any serialization error fails the test
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    statuses = [r.body["status"] for r in results]
    assert all(s == service.SEALED for s in statuses), statuses
    retransmits = sum(1 for r in results if r.body["retransmit"])
    assert retransmits == n_threads - 1
    assert all(r.body["water_level"] == 1 for r in results)

    check = connect(db_path)
    row = check.execute("SELECT water_level, forked FROM streams WHERE id=?", (sid,)).fetchone()
    assert row["water_level"] == 1 and row["forked"] == 0
    n = check.execute("SELECT COUNT(*) c, SUM(sealed) s FROM records WHERE stream_id=? AND seq=1", (sid,)).fetchone()
    assert n["c"] == 1 and n["s"] == 1
    check.close()


def test_concurrent_filler_and_conflict_has_single_verdict(tmp_path):
    """One thread fills a gap while another sends a conflicting same-seq record;
    exactly one outcome (fork) must be globally visible, never a later sealed
    success that contradicted an earlier forked response.
    """
    db_path = str(tmp_path / "cf.db")
    priv = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    sid = "buoy-conc-fork"
    p1, p2, p2_alt = digest(1), digest(2), digest(22)

    admin = connect(db_path)
    init_db(admin)
    service.create_stream(admin, sid, pub_b64)
    service.submit_record(admin, sid, 1, h(ZERO_DIGEST), h(p1), sign(priv, sid, 1, ZERO_DIGEST, p1))
    admin.close()

    out = {}

    def good():
        c = connect(db_path)
        try:
            out["good"] = service.submit_record(c, sid, 2, h(p1), h(p2), sign(priv, sid, 2, p1, p2))
        finally:
            c.close()

    def bad():
        c = connect(db_path)
        try:
            out["bad"] = service.submit_record(c, sid, 2, h(p1), h(p2_alt), sign(priv, sid, 2, p1, p2_alt))
        finally:
            c.close()

    barrier = threading.Barrier(2)

    def both(fn):
        barrier.wait()
        fn()

    t1 = threading.Thread(target=both, args=(good,))
    t2 = threading.Thread(target=both, args=(bad,))
    t1.start(); t2.start(); t1.join(); t2.join()

    verdicts = {k: v.body["status"] for k, v in out.items()}
    check = connect(db_path)
    state = service.get_stream(check, sid).body
    check.close()

    # Both records agree on prev_digest, so whichever transaction commits first
    # legitimately seals seq 2 (level advances to 2); the conflicting follower
    # must then freeze the stream. Exactly one of each verdict, and no response
    # may contradict the committed final state.
    assert state["forked"] is True
    assert state["water_level"] == 2
    assert sorted(verdicts.values()) == [service.FORKED, service.SEALED]
    winner = "good" if verdicts["good"] == service.SEALED else "bad"
    assert out[winner].body["water_level"] == 2
    loser = "bad" if winner == "good" else "good"
    assert out[loser].body["forked"] is True
