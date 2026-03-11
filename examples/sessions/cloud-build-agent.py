#!/usr/bin/env python3
"""
Cloud build agent for OAIE session mode.

Demonstrates a multi-step build workflow: creates a small C source file,
compiles it with gcc, runs the resulting binary, and checks the output
binary size. Each step depends on the previous one, so errors are handled
at every stage with early exit on failure.

This uses the cloud containment profile, which provides moderate resource
limits suitable for cloud API-driven agents.

Environment variables (set by OAIE session runner):
  OAIE_DISPATCH_SOCK  - Path to the Unix domain socket
  OAIE_SESSION_ID     - Current session ID
  OAIE_ARTIFACTS_DIR  - Directory where tool outputs are placed

Wire protocol (JSON newline-delimited):
  Request:  {"id": "call-1", "command": ["/bin/echo", "hello"], "timeout_s": 30}
  Response: {"id": "call-1", "run_id": "...", "exit_code": 0, "outputs": [...]}

Usage:
  oaie session run --contained=cloud -- python3 cloud-build-agent.py
"""

import json
import os
import socket
import sys
import tempfile


# Minimal C program to compile and run.
HELLO_C = r"""
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    printf("Hello from OAIE cloud build agent!\n");
    printf("Compiled at: %s %s\n", __DATE__, __TIME__);
    printf("argc = %d\n", argc);
    for (int i = 0; i < argc; i++) {
        printf("  argv[%d] = %s\n", i, argv[i]);
    }
    return EXIT_SUCCESS;
}
""".strip()


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


def step_failed(step_name, result):
    """Print error details for a failed step and return True if it failed."""
    if result.get("error"):
        print(f"[FAIL] {step_name}: {result['error']}")
        return True
    if result.get("exit_code", 0) != 0:
        print(f"[FAIL] {step_name}: exit code {result['exit_code']}")
        return True
    return False


def main():
    sock_path = os.environ.get("OAIE_DISPATCH_SOCK")
    if not sock_path:
        print("Error: OAIE_DISPATCH_SOCK not set. Run via 'oaie session run'.",
              file=sys.stderr)
        sys.exit(1)

    session_id = os.environ.get("OAIE_SESSION_ID", "unknown")
    artifacts_dir = os.environ.get("OAIE_ARTIFACTS_DIR", "/tmp")

    print(f"Cloud Build Agent started (session: {session_id})")
    print(f"Artifacts directory: {artifacts_dir}")
    print()

    # Write the C source to a temporary file that the sandbox can read.
    work_dir = tempfile.mkdtemp(prefix="oaie-build-")
    src_path = os.path.join(work_dir, "hello.c")
    bin_path = os.path.join(work_dir, "hello")

    with open(src_path, "w") as f:
        f.write(HELLO_C)
    print(f"Wrote source file: {src_path} ({len(HELLO_C)} bytes)")
    print()

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock_path)

    # --- Step 1: Compile the C source ---
    print("--- [call-1] Compile hello.c ---")
    result = dispatch(s, "call-1",
                      ["/usr/bin/gcc", "-Wall", "-O2", "-o", bin_path, src_path],
                      timeout_s=30)
    print(f"  duration={result.get('duration_ms', '?')}ms")
    if step_failed("compile", result):
        s.close()
        sys.exit(1)
    print("[OK] Compilation succeeded.")
    print()

    # --- Step 2: Run the compiled binary ---
    print("--- [call-2] Run hello binary ---")
    result = dispatch(s, "call-2",
                      [bin_path, "arg1", "arg2"],
                      timeout_s=10)
    print(f"  duration={result.get('duration_ms', '?')}ms, "
          f"outputs={len(result.get('outputs', []))}")
    if step_failed("run", result):
        s.close()
        sys.exit(1)
    print("[OK] Binary executed successfully.")
    print()

    # --- Step 3: Check binary size ---
    print("--- [call-3] Check binary size ---")
    result = dispatch(s, "call-3",
                      ["/usr/bin/stat", "--printf=%s bytes, %n", bin_path],
                      timeout_s=10)
    print(f"  duration={result.get('duration_ms', '?')}ms")
    if step_failed("stat", result):
        s.close()
        sys.exit(1)
    print("[OK] Binary stat retrieved.")
    print()

    # --- Step 4: List work directory ---
    print("--- [call-4] List work directory ---")
    result = dispatch(s, "call-4",
                      ["/bin/ls", "-la", work_dir],
                      timeout_s=10)
    print(f"  duration={result.get('duration_ms', '?')}ms")
    if step_failed("ls", result):
        print("  (non-fatal, continuing)")
    else:
        print("[OK] Directory listing retrieved.")
    print()

    # --- Summary ---
    print("=" * 50)
    print("Build Workflow Summary")
    print("=" * 50)
    print(f"  Source file:   {src_path}")
    print(f"  Binary output: {bin_path}")
    print(f"  Binary exists: {os.path.exists(bin_path)}")
    if os.path.exists(bin_path):
        size = os.path.getsize(bin_path)
        print(f"  Binary size:   {size} bytes ({size / 1024:.1f} KB)")
    print(f"  Tool calls:    4")

    s.close()
    print()
    print("Cloud Build Agent finished.")


if __name__ == "__main__":
    main()
