"""SQLite persistence.

A single database file holds streams and their records. Every HTTP response is
produced only after the record decision, the contiguous water level and the
fork verdict have been committed together in one SQLite transaction.
"""
from __future__ import annotations

import os
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS streams (
    id          TEXT PRIMARY KEY,
    public_key  BLOB NOT NULL,
    water_level INTEGER NOT NULL DEFAULT 0,
    last_digest BLOB NOT NULL DEFAULT x'0000000000000000000000000000000000000000000000000000000000000000',
    forked      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS records (
    stream_id      TEXT NOT NULL,
    seq            INTEGER NOT NULL,
    prev_digest    BLOB NOT NULL,
    payload_digest BLOB NOT NULL,
    signature      BLOB NOT NULL,
    sealed         INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (stream_id, seq),
    FOREIGN KEY (stream_id) REFERENCES streams(id)
);

CREATE INDEX IF NOT EXISTS idx_records_unsealed
    ON records(stream_id, sealed, seq);
"""


def connect(db_path: str) -> sqlite3.Connection:
    parent = os.path.dirname(os.path.abspath(db_path))
    os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    # WAL allows the verify container to inspect the file while the server
    # runs; the write lock itself still serialises transactions.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
