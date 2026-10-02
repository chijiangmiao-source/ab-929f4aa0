"""Production entrypoint: waitress WSGI server."""
from __future__ import annotations

import os

from waitress import serve

from app.http import create_app

DB_PATH = os.environ.get("DB_PATH", "/data/buoy.db")
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8080"))

app = create_app(DB_PATH)

if __name__ == "__main__":
    serve(app, host=HOST, port=PORT, threads=int(os.environ.get("THREADS", "16")))
