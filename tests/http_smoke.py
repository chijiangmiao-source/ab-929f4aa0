"""End-to-end HTTP smoke test, runnable inside the compose `verify` container.

Usage:
    python http_smoke.py phase1 --url http://server:8080 --state /tmp/smoke.json
    # server restart happens in between (see docker_api.py)
    python http_smoke.py phase2 --url http://server:8080 --state /tmp/smoke.json

Exits non-zero on any violation. Only Python stdlib is used.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.signing import ZERO_DIGEST, encode_message  # noqa: E402


def digest(n: int) -> bytes:
    return bytes([n]) * 32


def h(b: bytes) -> str:
    return b.hex()


class Client:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def request(self, method: str, path: str, body: dict | None = None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def wait_health(self, attempts: int = 30) -> None:
        for _ in range(attempts):
            try:
                status, body = self.request("GET", "/health")
                if status == 200 and body.get("status") == "ok":
                    return
            except Exception:
                pass
            time.sleep(1)
        raise SystemExit("server did not become healthy")


def new_key():
    priv = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    return priv, pub_b64


def sign(priv, sid, seq, prev, payload):
    return base64.b64encode(priv.sign(encode_message(sid, seq, prev, payload))).decode()


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)
    print(f"  ok: {msg}")


def submit(client, priv, sid, seq, prev, payload):
    return client.request(
        "POST", f"/streams/{sid}/records",
        {"seq": seq, "prev_digest": h(prev), "payload_digest": h(payload),
         "signature": sign(priv, sid, seq, prev, payload)},
    )


def phase1(client: Client, state_path: str) -> None:
    client.wait_health()
    state = {}

    # --- health + registration semantics -----------------------------------
    status, _ = client.request("GET", "/health")
    check(status == 200, "GET /health -> 200")

    priv, pub_b64 = new_key()
    sid = "smoke-merge"

    status, body = client.request("POST", "/streams", {"id": sid, "public_key": pub_b64})
    check(status == 201 and body["created"] is True, "register stream -> 201 created")
    status, body = client.request("POST", "/streams", {"id": sid, "public_key": pub_b64})
    check(status == 200 and body["created"] is False, "same key re-register is idempotent")
    _, other_b64 = new_key()
    status, _ = client.request("POST", "/streams", {"id": sid, "public_key": other_b64})
    check(status == 409, "replacing public key is rejected 409")

    # --- out-of-order merge + retransmission verdicts ----------------------
    p1, p2, p3 = digest(1), digest(2), digest(3)
    status, body = submit(client, priv, sid, 3, p2, p3)
    check(status == 200 and body["status"] == "pending" and body["water_level"] == 0, "seq3 buffered as pending")
    status, body = submit(client, priv, sid, 3, p2, p3)
    check(status == 200 and body["status"] == "pending" and body["retransmit"] is True,
          "identical retransmit keeps pending verdict")
    status, body = submit(client, priv, sid, 1, ZERO_DIGEST, p1)
    check(status == 200 and body["status"] == "sealed" and body["water_level"] == 1, "seq1 seals from zero digest")
    status, body = submit(client, priv, sid, 2, p1, p2)
    check(status == 200 and body["status"] == "sealed" and body["water_level"] == 3,
          "gap fill seals through seq3 in one response")
    status, body = submit(client, priv, sid, 1, ZERO_DIGEST, p1)
    check(status == 200 and body["status"] == "sealed" and body["retransmit"] is True,
          "sealed-record retransmit keeps sealed verdict")

    # --- window -------------------------------------------------------------
    wpriv, wpub = new_key()
    wsid = "smoke-window"
    client.request("POST", "/streams", {"id": wsid, "public_key": wpub})
    status, body = submit(client, wpriv, wsid, 33, digest(0), digest(7))
    check(status == 422 and body["status"] == "out_of_window", "seq beyond water+32 rejected 422")
    status, body = submit(client, wpriv, wsid, 32, digest(9), digest(8))
    check(status == 200 and body["status"] == "pending", "seq exactly water+32 accepted and buffered")

    # --- fork freeze --------------------------------------------------------
    fpriv, fpub = new_key()
    fsid = "smoke-fork"
    client.request("POST", "/streams", {"id": fsid, "public_key": fpub})
    submit(client, fpriv, fsid, 1, ZERO_DIGEST, digest(11))
    status, body = submit(client, fpriv, fsid, 1, ZERO_DIGEST, digest(12))
    check(status == 409 and body["status"] == "forked" and body["forked"] is True,
          "conflicting same-seq content freezes stream as forked")
    status, body = submit(client, fpriv, fsid, 2, digest(11), digest(13))
    check(status == 409 and body["status"] == "forked", "forked stream can never advance again")

    # --- stream prepared for the post-restart phase ------------------------
    rpriv, rpub = new_key()
    rsid = "smoke-restart"
    client.request("POST", "/streams", {"id": rsid, "public_key": rpub})
    submit(client, rpriv, rsid, 1, ZERO_DIGEST, digest(101))
    status, body = submit(client, rpriv, rsid, 3, digest(102), digest(103))
    check(status == 200 and body["status"] == "pending", "restart stream: seq3 buffered before restart")

    state["restart_id"] = rsid
    state["restart_key"] = base64.b64encode(
        rpriv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode()

    with open(state_path, "w") as f:
        json.dump(state, f)
    print("phase1 complete")


def phase2(client: Client, state_path: str) -> None:
    client.wait_health()
    with open(state_path) as f:
        state = json.load(f)

    priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(state["restart_key"]))
    sid = state["restart_id"]

    # Water level rebuilt from persisted sealed records.
    status, body = client.request("GET", f"/streams/{sid}")
    check(status == 200 and body["water_level"] == 1 and body["forked"] is False,
          "restart rebuilds water level 1 from persisted records")

    status, body = submit(client, priv, sid, 1, ZERO_DIGEST, digest(101))
    check(status == 200 and body["status"] == "sealed" and body["retransmit"] is True,
          "post-restart retransmit of sealed record returns same verdict")
    status, body = submit(client, priv, sid, 3, digest(102), digest(103))
    check(status == 200 and body["status"] == "pending" and body["retransmit"] is True,
          "post-restart buffered record still pending")

    status, body = submit(client, priv, sid, 2, digest(101), digest(102))
    check(status == 200 and body["status"] == "sealed" and body["water_level"] == 3,
          "gap fill after restart seals through seq3")

    status, body = client.request("GET", f"/streams/{sid}")
    check(body["water_level"] == 3 and body["last_digest"] == h(digest(103)),
          "final state: continuous prefix at seq3 with correct chain tip")
    print("phase2 complete")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("phase", choices=["phase1", "phase2"])
    ap.add_argument("--url", default=os.environ.get("SERVER_URL", "http://localhost:8080"))
    ap.add_argument("--state", default="/tmp/smoke_state.json")
    args = ap.parse_args()

    client = Client(args.url)
    if args.phase == "phase1":
        phase1(client, args.state)
    else:
        phase2(client, args.state)


if __name__ == "__main__":
    main()
