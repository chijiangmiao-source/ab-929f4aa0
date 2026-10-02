"""Entrypoint for the compose `verify` container.

Runs, in order, and exits non-zero if any step fails:

  1. code tests (pytest): out-of-order merging, fork freezing, concurrency
     and post-restart retransmission/recovery;
  2. image build check: build the production Docker image through the mounted
     Docker socket (`docker build -f Dockerfile .`);
  3. HTTP smoke: exercise the running `server` service, restart its container
     via the Docker socket, then verify water-level rebuild and post-restart
     retransmission behaviour.
"""
from __future__ import annotations

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER_URL = os.environ.get("SERVER_URL", "http://server:8080")
SERVER_CONTAINER = os.environ.get("SERVER_CONTAINER", "buoy-server")
STATE = "/tmp/smoke_state.json"


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    print(f"\n$ {' '.join(cmd)}", flush=True)
    return subprocess.run(cmd, cwd=ROOT, check=False, **kw)


def step(name: str, ok: bool) -> None:
    print(f"\n=== {name}: {'PASS' if ok else 'FAIL'} ===", flush=True)
    if not ok:
        sys.exit(1)


def main() -> int:
    # 1. code tests -----------------------------------------------------------
    proc = run([sys.executable, "-m", "pytest", "tests", "-q"])
    step("code tests (out-of-order merge / fork freeze / restart / concurrency)", proc.returncode == 0)

    # 2. image build check ----------------------------------------------------
    if os.path.exists("/var/run/docker.sock"):
        proc = run(["docker", "build", "-f", "Dockerfile", "-t", "buoy-anchor:verify-check", "."])
        step("production image build check", proc.returncode == 0)
    else:
        print("Docker socket not mounted; skipping in-container image build")

    # 3. HTTP smoke across a server restart ----------------------------------
    proc = run([sys.executable, "tests/http_smoke.py", "phase1", "--url", SERVER_URL, "--state", STATE])
    step("HTTP smoke phase 1 (merge / window / fork)", proc.returncode == 0)

    proc = run(["docker", "restart", SERVER_CONTAINER])
    if proc.returncode != 0:
        step("restart server container", False)
    step("restart server container", True)

    proc = run([sys.executable, "tests/http_smoke.py", "phase2", "--url", SERVER_URL, "--state", STATE])
    step("HTTP smoke phase 2 (post-restart retransmit + gap fill)", proc.returncode == 0)

    print("\nALL VERIFY CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
