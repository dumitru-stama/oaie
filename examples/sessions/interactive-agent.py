#!/usr/bin/env python3
"""
Interactive approval-gated agent for OAIE session mode.

Dispatches a series of system information commands (ls, uname, uptime,
whoami, env) that each require human approval before execution. When a
call is denied by the operator, the agent skips it gracefully and moves
on to the next command. This demonstrates the --require-approval flow
where a human operator reviews each tool call before it runs.

Environment variables (set by OAIE session runner):
  OAIE_DISPATCH_SOCK  - Path to the Unix domain socket
  OAIE_SESSION_ID     - Current session ID
  OAIE_ARTIFACTS_DIR  - Directory where tool outputs are placed

Wire protocol (JSON newline-delimited):
  Request:  {"id": "call-1", "command": ["/bin/echo", "hello"], "timeout_s": 30}
  Response: {"id": "call-1", "run_id": "...", "exit_code": 0, "outputs": [...]}

Usage:
  oaie session run --contained=interactive --require-approval -- python3 interactive-agent.py
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


# Commands to run, each with a human-readable description.
COMMANDS = [
    {
        "name": "list-home",
        "description": "List files in home directory",
        "command": ["/bin/ls", "-la", os.path.expanduser("~")],
    },
    {
        "name": "system-info",
        "description": "Show kernel and OS information",
        "command": ["/usr/bin/uname", "-a"],
    },
    {
        "name": "uptime",
        "description": "Show system uptime and load",
        "command": ["/usr/bin/uptime"],
    },
    {
        "name": "whoami",
        "description": "Show current user identity",
        "command": ["/usr/bin/whoami"],
    },
    {
        "name": "environment",
        "description": "Show environment variables",
        "command": ["/usr/bin/env"],
    },
]


def main():
    sock_path = os.environ.get("OAIE_DISPATCH_SOCK")
    if not sock_path:
        print("Error: OAIE_DISPATCH_SOCK not set. Run via 'oaie session run'.",
              file=sys.stderr)
        sys.exit(1)

    session_id = os.environ.get("OAIE_SESSION_ID", "unknown")
    artifacts_dir = os.environ.get("OAIE_ARTIFACTS_DIR", "/tmp")

    print(f"Interactive Agent started (session: {session_id})")
    print(f"Artifacts directory: {artifacts_dir}")
    print(f"Approval mode: each tool call requires human approval")
    print(f"Commands to dispatch: {len(COMMANDS)}")
    print()

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock_path)

    approved = 0
    denied = 0
    failed = 0

    for i, entry in enumerate(COMMANDS):
        call_id = f"call-{i + 1}"
        name = entry["name"]
        description = entry["description"]
        cmd = entry["command"]

        print(f"--- [{call_id}] {name}: {description} ---")
        print(f"  Command: {' '.join(cmd)}")

        result = dispatch(s, call_id, cmd, timeout_s=15)

        error = result.get("error", "")

        # Check for denial / approval rejection.
        if "denied" in error.lower() or "rejected" in error.lower() \
                or "approval" in error.lower():
            denied += 1
            print(f"  DENIED by operator: {error}")
            print(f"  Skipping and continuing to next command.")
            print()
            continue

        # Check for other errors (budget, timeout, sandbox failure, etc.).
        if error:
            failed += 1
            print(f"  ERROR: {error}")
            print(f"  Skipping and continuing to next command.")
            print()
            continue

        # Successful execution.
        approved += 1
        exit_code = result.get("exit_code", -1)
        duration_ms = result.get("duration_ms", 0)
        outputs = result.get("outputs", [])
        run_id = result.get("run_id", "?")

        print(f"  APPROVED and executed.")
        print(f"  exit_code={exit_code}, duration={duration_ms}ms, "
              f"outputs={len(outputs)}, run_id={run_id}")

        # Try to read output artifacts if any were produced.
        for out_file in outputs:
            artifact_path = os.path.join(artifacts_dir, run_id, out_file)
            if os.path.exists(artifact_path):
                with open(artifact_path, "r") as f:
                    content = f.read()
                lines = content.splitlines()
                preview_count = min(8, len(lines))
                print(f"  Output ({len(lines)} lines):")
                for ln in lines[:preview_count]:
                    print(f"    {ln}")
                if len(lines) > preview_count:
                    print(f"    ... ({len(lines) - preview_count} more lines)")

        print()

    # --- Summary ---
    total = len(COMMANDS)
    print("=" * 55)
    print("Interactive Agent Summary")
    print("=" * 55)
    print(f"  Total commands:    {total}")
    print(f"  Approved/ran:      {approved}")
    print(f"  Denied by operator:{denied:>2}")
    print(f"  Failed (other):    {failed}")
    print()

    if denied > 0:
        print(f"  {denied} command(s) were denied by the operator.")
        print("  This is expected behavior with --require-approval.")
    if denied == 0 and failed == 0:
        print("  All commands were approved and executed successfully.")
    if approved == 0 and denied == total:
        print("  All commands were denied. The operator chose to block")
        print("  every tool call. The agent handled this gracefully.")

    s.close()
    print()
    print("Interactive Agent finished.")


if __name__ == "__main__":
    main()
