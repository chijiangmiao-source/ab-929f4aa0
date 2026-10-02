"""HTTP layer.

A SQLite connection is opened per request and never shared between threads;
``BEGIN IMMEDIATE`` serialises writers so concurrent submissions cannot
double-seal or briefly observe an inconsistent verdict.
"""
from __future__ import annotations

import os
import sqlite3

from flask import Flask, current_app, g, jsonify, request

from . import service
from .db import connect, init_db


def _get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = connect(current_app.config["DB_PATH"])
    return g.db


def create_app(db_path: str) -> Flask:
    app = Flask(__name__)
    app.config["DB_PATH"] = db_path

    with app.app_context():
        admin = connect(db_path)
        try:
            init_db(admin)
            rebuilt = service.rebuild_water_levels(admin)
        finally:
            admin.close()
    app.logger.info("rebuilt water levels: %s", rebuilt)

    @app.teardown_appcontext
    def _close_db(exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    @app.post("/streams")
    def register_stream():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(error="JSON object required"), 400
        try:
            result = service.create_stream(_get_db(), body.get("id"), body.get("public_key"))
        except service.ValidationError as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(result.body), result.status

    @app.post("/streams/<stream_id>/records")
    def submit(stream_id: str):
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(error="JSON object required"), 400
        try:
            result = service.submit_record(
                _get_db(),
                stream_id,
                body.get("seq"),
                body.get("prev_digest"),
                body.get("payload_digest"),
                body.get("signature"),
            )
        except service.ValidationError as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(result.body), result.status

    @app.get("/streams/<stream_id>")
    def stream_state(stream_id: str):
        result = service.get_stream(_get_db(), stream_id)
        if result is None:
            return jsonify(error="unknown stream"), 404
        return jsonify(result.body), 200

    return app
