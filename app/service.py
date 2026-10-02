"""Sealing service.

All state transitions for a submission -- storing the record, advancing the
contiguous water level, or freezing the stream as forked -- happen inside a
single ``BEGIN IMMEDIATE`` SQLite transaction, so every HTTP response reports
a committed, internally consistent verdict.

Sequence numbers start at 1. A stream's ``water_level`` is the highest
contiguous sealed sequence; ``last_digest`` is the payload digest of that
record (the zero digest before the first record).
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from .signing import ZERO_DIGEST, encode_message, verify_signature

WINDOW = 32

# verdicts
SEALED = "sealed"
PENDING = "pending"
FORKED = "forked"
OUT_OF_WINDOW = "out_of_window"
INVALID_SIGNATURE = "invalid_signature"
NOT_FOUND = "not_found"
BAD_REQUEST = "bad_request"
ID_CONFLICT = "id_conflict"


@dataclass
class Result:
    status: int
    body: dict


class ValidationError(ValueError):
    pass


def _forked_body(stream_id: str, seq: int, water_level: int, reason: str) -> dict:
    return {
        "stream_id": stream_id,
        "seq": seq,
        "status": FORKED,
        "water_level": water_level,
        "forked": True,
        "reason": reason,
    }


def _state_snapshot(conn: sqlite3.Connection, stream_id: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, public_key, water_level, last_digest, forked FROM streams WHERE id = ?",
        (stream_id,),
    ).fetchone()


def create_stream(conn: sqlite3.Connection, stream_id: object, public_key_b64: object) -> Result:
    if not isinstance(stream_id, str) or not stream_id:
        raise ValidationError("id must be a non-empty ASCII string")
    try:
        stream_id.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValidationError("id must be ASCII") from exc
    if len(stream_id) > 256:
        raise ValidationError("id too long")
    if not isinstance(public_key_b64, str):
        raise ValidationError("public_key must be a base64 string")
    try:
        from .signing import decode_public_key

        key = decode_public_key(public_key_b64)
    except Exception as exc:
        raise ValidationError("public_key must be a 32-byte base64 Ed25519 key") from exc
    key_raw = key.public_bytes_raw()

    conn.execute("BEGIN IMMEDIATE")
    try:
        existing = _state_snapshot(conn, stream_id)
        if existing is not None:
            if existing["public_key"] != key_raw:
                # Identifiers are permanent: the bound key can never change.
                conn.execute("ROLLBACK")
                return Result(409, {"error": "stream id already registered with a different public key"})
            conn.execute("ROLLBACK")
            return Result(
                200,
                {"id": stream_id, "public_key": public_key_b64, "water_level": 0, "forked": False, "created": False},
            )
        conn.execute(
            "INSERT INTO streams (id, public_key) VALUES (?, ?)",
            (stream_id, key_raw),
        )
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return Result(
        201,
        {"id": stream_id, "public_key": public_key_b64, "water_level": 0, "forked": False, "created": True},
    )


def get_stream(conn: sqlite3.Connection, stream_id: str) -> Result | None:
    row = _state_snapshot(conn, stream_id)
    if row is None:
        return None
    return Result(
        200,
        {
            "id": row["id"],
            "water_level": row["water_level"],
            "last_digest": row["last_digest"].hex(),
            "forked": bool(row["forked"]),
        },
    )


def _freeze(
    conn: sqlite3.Connection,
    stream_id: str,
    water_level: int,
    last_digest: bytes,
    seq: int,
    reason: str,
) -> Result:
    """Freeze the stream as forked, persisting the prefix sealed so far.

    Caller owns the open transaction.
    """
    conn.execute(
        "UPDATE streams SET water_level = ?, last_digest = ?, forked = 1 WHERE id = ?",
        (water_level, last_digest, stream_id),
    )
    conn.execute("COMMIT")
    return Result(409, _forked_body(stream_id, seq, water_level, reason))


def submit_record(
    conn: sqlite3.Connection,
    stream_id: str,
    seq: object,
    prev_digest_hex: object,
    payload_digest_hex: object,
    signature_b64: object,
) -> Result:
    # ---- purely syntactic validation, before any transaction --------------
    if isinstance(seq, bool) or not isinstance(seq, int) or not 0 < seq <= 0xFFFFFFFFFFFFFFFF:
        raise ValidationError("seq must be a positive uint64 integer")
    prev_digest = _as_32_bytes(prev_digest_hex, "prev_digest")
    payload_digest = _as_32_bytes(payload_digest_hex, "payload_digest")
    signature = _as_signature(signature_b64)

    conn.execute("BEGIN IMMEDIATE")
    try:
        stream = _state_snapshot(conn, stream_id)
        if stream is None:
            conn.execute("ROLLBACK")
            return Result(404, {"error": "unknown stream", "stream_id": stream_id})

        water_level = stream["water_level"]
        last_digest = stream["last_digest"]
        if stream["forked"]:
            conn.execute("ROLLBACK")
            return Result(409, _forked_body(stream_id, seq, water_level, "stream already frozen"))

        existing = conn.execute(
            "SELECT prev_digest, payload_digest, signature, sealed FROM records "
            "WHERE stream_id = ? AND seq = ?",
            (stream_id, seq),
        ).fetchone()

        if existing is not None:
            # Retransmission: only the exact same bytes are the same verdict.
            same = (
                existing["prev_digest"] == prev_digest
                and existing["payload_digest"] == payload_digest
                and existing["signature"] == signature
            )
            if not same:
                return _freeze(conn, stream_id, water_level, last_digest, seq, "conflicting retransmission at same seq")
            conn.execute("ROLLBACK")
            status = SEALED if existing["sealed"] else PENDING
            return Result(
                200,
                {
                    "stream_id": stream_id,
                    "seq": seq,
                    "status": status,
                    "water_level": water_level,
                    "forked": False,
                    "retransmit": True,
                },
            )

        if seq > water_level + WINDOW:
            conn.execute("ROLLBACK")
            return Result(
                422,
                {
                    "stream_id": stream_id,
                    "seq": seq,
                    "status": OUT_OF_WINDOW,
                    "water_level": water_level,
                    "window": WINDOW,
                },
            )

        # New sequence number: verify the signature over the canonical binary
        # message. The JSON envelope is never re-encoded for this check.
        message = encode_message(stream_id, seq, prev_digest, payload_digest)
        key = _public_key_from_row(stream["public_key"])
        if not verify_signature(key, signature, message):
            conn.execute("ROLLBACK")
            return Result(
                400,
                {"stream_id": stream_id, "seq": seq, "status": INVALID_SIGNATURE},
            )

        conn.execute(
            "INSERT INTO records (stream_id, seq, prev_digest, payload_digest, signature) "
            "VALUES (?, ?, ?, ?, ?)",
            (stream_id, seq, prev_digest, payload_digest, signature),
        )

        # Seal as much of the contiguous prefix as possible; a prev-digest
        # mismatch at the seal boundary freezes the stream atomically.
        while True:
            nxt = conn.execute(
                "SELECT prev_digest, payload_digest FROM records "
                "WHERE stream_id = ? AND seq = ?",
                (stream_id, water_level + 1),
            ).fetchone()
            if nxt is None:
                break
            if nxt["prev_digest"] != last_digest:
                return _freeze(conn, stream_id, water_level, last_digest, water_level + 1, "prev_digest mismatch at seal time")
            conn.execute(
                "UPDATE records SET sealed = 1 WHERE stream_id = ? AND seq = ?",
                (stream_id, water_level + 1),
            )
            water_level += 1
            last_digest = nxt["payload_digest"]

        conn.execute(
            "UPDATE streams SET water_level = ?, last_digest = ? WHERE id = ?",
            (water_level, last_digest, stream_id),
        )
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise

    sealed_now = seq <= water_level
    return Result(
        200,
        {
            "stream_id": stream_id,
            "seq": seq,
            "status": SEALED if sealed_now else PENDING,
            "water_level": water_level,
            "forked": False,
            "retransmit": False,
        },
    )


def rebuild_water_levels(conn: sqlite3.Connection) -> dict[str, int]:
    """Recompute every stream's water level and fork flag from stored records.

    Called at startup so the in-table water mark is never trusted on its own:
    the sealed records are replayed in sequence order and the prev-digest
    chain is re-checked. Unsealed (buffered) records stay buffered and can
    still seal once their gap fills after a restart.
    """
    conn.execute("BEGIN IMMEDIATE")
    rebuilt: dict[str, int] = {}
    try:
        streams = conn.execute("SELECT id, forked FROM streams").fetchall()
        for s in streams:
            stream_id = s["id"]
            level = 0
            last_digest = ZERO_DIGEST
            corrupt = False
            while True:
                row = conn.execute(
                    "SELECT prev_digest, payload_digest, sealed FROM records "
                    "WHERE stream_id = ? AND seq = ?",
                    (stream_id, level + 1),
                ).fetchone()
                if row is None or not row["sealed"]:
                    break
                if row["prev_digest"] != last_digest:
                    corrupt = True
                    break
                level += 1
                last_digest = row["payload_digest"]
            conn.execute(
                "UPDATE streams SET water_level = ?, last_digest = ?, forked = ? WHERE id = ?",
                (level, last_digest, 1 if (s["forked"] or corrupt) else 0, stream_id),
            )
            rebuilt[stream_id] = level
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return rebuilt


def _public_key_from_row(raw: bytes):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    return Ed25519PublicKey.from_public_bytes(raw)


def _as_32_bytes(value: object, field: str) -> bytes:
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be a hex string")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValidationError(f"{field} must be hex") from exc
    if len(raw) != 32:
        raise ValidationError(f"{field} must be 32 bytes")
    return raw


def _as_signature(value: object) -> bytes:
    import base64

    if not isinstance(value, str):
        raise ValidationError("signature must be a base64 string")
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValidationError("signature must be standard base64") from exc
    if len(raw) != 64:
        raise ValidationError("Ed25519 signature must be 64 bytes")
    return raw
