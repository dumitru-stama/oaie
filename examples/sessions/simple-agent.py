#!/usr/bin/env python3
"""
Minimal Python agent for OAIE session mode.

Connects to the OAIE dispatch socket and sends tool calls. Each tool call
is executed in its own OAIE sandbox. Output artifacts are available in
$OAIE_ARTIFACTS_DIR/<run_id>/.

Environment variables (set by OAIE session runner):
  OAIE_DISPATCH_SOCK  - Path to the Unix domain socket
  OAIE_SESSION_ID     - Current session ID
  OAIE_ARTIFACTS_DIR  - Directory where tool outputs are placed

Wire protocol (JSON newline-delimited):
  Request:  {"id": "call-1", "command": ["/bin/echo", "hello"], "timeout_s": 30}
  Response: {"id": "call-1", "run_id": "...", "exit_code": 0, "outputs": [...]}

Usage:
  oaie session run --contained=local -- python3 simple-agent.py
"""

import json
import os
import socket
import sys


def dispatch(sock, call_id, command, timeout_s=None):
    """Send a tool call and return the response."""
    request = {"id": call_id, "command": command}
    if timeout_s is not None:
        request["timeout_s"] = timeout_s

    line = json.dumps(request) + "\n"
    sock.sendall(line.encode())

    # Read response (newline-delimited JSON).
    response = b""
    while not response.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("dispatch socket closed")
        response += chunk

    return json.loads(response.decode())


def main():
    sock_path = os.environ.get("OAIE_DISPATCH_SOCK")
    if not sock_path:
        print("Error: OAIE_DISPATCH_SOCK not set. Run via 'oaie session run'.", file=sys.stderr)
        sys.exit(1)

    session_id = os.environ.get("OAIE_SESSION_ID", "unknown")
    artifacts_dir = os.environ.get("OAIE_ARTIFACTS_DIR", "/tmp")

    print(f"Agent started (session: {session_id})")
    print(f"Artifacts directory: {artifacts_dir}")

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock_path)

    # Example: run a few commands.
    commands = [
        ["/bin/echo", "Hello from OAIE agent!"],
        ["/bin/date", "+%Y-%m-%d %H:%M:%S"],
        ["/usr/bin/uname", "-a"],
    ]

    for i, cmd in enumerate(commands):
        call_id = f"call-{i}"
        print(f"\n--- Dispatching {call_id}: {' '.join(cmd)} ---")

        result = dispatch(s, call_id, cmd)

        if result.get("error"):
            print(f"Error: {result['error']}")
            break

        print(f"Exit code: {result['exit_code']}")
        print(f"Duration:  {result['duration_ms']}ms")
        print(f"Outputs:   {len(result['outputs'])} artifacts")

    s.close()
    print("\nAgent finished.")


if __name__ == "__main__":
    main()
