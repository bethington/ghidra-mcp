#!/usr/bin/env python3
"""Run the MCP bridge against a headless server on another machine, over SSH.

The bridge refuses non-loopback URLs because it speaks plain HTTP and forwards a bearer
token, so a remote server is reached through a tunnel. This owns that tunnel for the life
of one MCP session, on a free port, so sessions cannot collide or break each other when
one exits. The auth token is read from the container over SSH at startup, so no secret
has to be stored in the MCP client's config.

    python tools/bridge_via_tunnel.py --ssh user@host [--container ghidra-mcp]
"""
from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

SSH_OPTIONS = [
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=10",
    "-o", "ExitOnForwardFailure=yes",
    "-o", "ServerAliveInterval=30",
    "-o", "ServerAliveCountMax=3",
]
RESTART_DELAY_SECONDS = 5
READY_TIMEOUT_SECONDS = 20


def log(message: str) -> None:
    # stdout is the MCP stream; anything else printed there corrupts the protocol.
    print(f"bridge_via_tunnel: {message}", file=sys.stderr, flush=True)


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def tunnel_command(ssh_target: str, local_port: int, remote_port: int) -> list[str]:
    return ["ssh", *SSH_OPTIONS, "-N", "-L",
            f"127.0.0.1:{local_port}:127.0.0.1:{remote_port}", ssh_target]


def token_command(ssh_target: str, container: str) -> list[str]:
    return ["ssh", *SSH_OPTIONS, ssh_target,
            f"docker exec {container} printenv GHIDRA_MCP_AUTH_TOKEN"]


def bridge_environment(base: dict[str, str], local_port: int, token: str) -> dict[str, str]:
    """Pinned, so a local Ghidra opened to look at something cannot take over the session."""
    return {
        **base,
        "GHIDRA_MCP_URL": f"http://127.0.0.1:{local_port}",
        "GHIDRA_MCP_PIN_URL": "1",
        "GHIDRA_MCP_AUTH_TOKEN": token,
        "PYTHONIOENCODING": "utf-8",
    }


def bridge_command(extra_args: list[str]) -> list[str]:
    """The bridge beside this interpreter, so the launcher and the bridge share a venv."""
    name = "bridge-mcp-ghidra.exe" if os.name == "nt" else "bridge-mcp-ghidra"
    beside = Path(sys.executable).with_name(name)
    found = str(beside) if beside.exists() else shutil.which("bridge-mcp-ghidra")
    if not found:
        raise SystemExit(f"bridge_via_tunnel: {name} not found beside {sys.executable} or on PATH")
    return [found, "--transport", "stdio", *extra_args]


def read_token(ssh_target: str, container: str) -> str:
    result = subprocess.run(token_command(ssh_target, container), capture_output=True,
                            text=True, timeout=60, stdin=subprocess.DEVNULL)
    token = result.stdout.strip()
    if result.returncode != 0 or not token:
        raise SystemExit(f"bridge_via_tunnel: could not read the auth token from {container} on "
                         f"{ssh_target}: {result.stderr.strip() or 'empty value'}")
    return token


def keep_tunnel_up(command: list[str], stopping: threading.Event, state: dict) -> None:
    """Restart the tunnel when it drops. The bridge reconnects on its next request."""
    while not stopping.is_set():
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        state["process"] = process
        process.wait()
        if not stopping.is_set():
            log(f"tunnel exited with code {process.returncode}; restarting")
            stopping.wait(RESTART_DELAY_SECONDS)


def wait_until_listening(port: int, timeout: float = READY_TIMEOUT_SECONDS) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket() as probe:
            probe.settimeout(1)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ssh", required=True, help="SSH target of the machine running the server")
    parser.add_argument("--container", default="ghidra-mcp", help="Container holding the auth token")
    parser.add_argument("--remote-port", type=int, default=8089)
    args, extra = parser.parse_known_args(argv)

    token = read_token(args.ssh, args.container)
    port = free_port()
    stopping = threading.Event()
    state: dict = {}
    threading.Thread(target=keep_tunnel_up, daemon=True, args=(
        tunnel_command(args.ssh, port, args.remote_port), stopping, state)).start()
    try:
        if not wait_until_listening(port):
            log(f"tunnel to {args.ssh} did not come up within {READY_TIMEOUT_SECONDS}s")
            return 1
        return subprocess.run(bridge_command(extra),
                              env=bridge_environment(dict(os.environ), port, token)).returncode
    finally:
        stopping.set()
        if state.get("process"):
            state["process"].terminate()


if __name__ == "__main__":
    sys.exit(main())
