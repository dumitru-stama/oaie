#!/usr/bin/env python3
"""
Local reverse engineering agent for OAIE session mode.

Analyzes a binary (default: /bin/echo) using basic file inspection tools:
file identification, string extraction, hex dump, and stat. Demonstrates
a local-only workflow that needs no network access, reads output artifacts,
and tracks budget usage to avoid exhaustion.

Environment variables (set by OAIE session runner):
  OAIE_DISPATCH_SOCK  - Path to the Unix domain socket
  OAIE_SESSION_ID     - Current session ID
  OAIE_ARTIFACTS_DIR  - Directory where tool outputs are placed

Wire protocol (JSON newline-delimited):
  Request:  {"id": "call-1", "command": ["/bin/echo", "hello"], "timeout_s": 30}
  Response: {"id": "call-1", "run_id": "...", "exit_code": 0, "outputs": [...]}

Usage:
  oaie session run --contained=local -- python3 local-re-agent.py
  oaie session run --contained=local -- python3 local-re-agent.py /usr/bin/ls
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


def read_artifact(artifacts_dir, run_id, filename):
    """Try to read an output artifact from a completed run."""
    artifact_path = os.path.join(artifacts_dir, run_id, filename)
    if os.path.exists(artifact_path):
        with open(artifact_path, "r") as f:
            return f.read()
    return None


def check_budget(result):
    """Check if the response indicates budget is getting low.

    The OAIE session runner emits warning events when budget reaches 80%.
    If we see an error about budget exhaustion, we should stop early.
    """
    error = result.get("error", "")
    if "budget" in error.lower() or "exhausted" in error.lower():
        print(f"[budget] Budget limit reached: {error}")
        return False
    return True


def main():
    sock_path = os.environ.get("OAIE_DISPATCH_SOCK")
    if not sock_path:
        print("Error: OAIE_DISPATCH_SOCK not set. Run via 'oaie session run'.",
              file=sys.stderr)
        sys.exit(1)

    session_id = os.environ.get("OAIE_SESSION_ID", "unknown")
    artifacts_dir = os.environ.get("OAIE_ARTIFACTS_DIR", "/tmp")

    # Target binary: first argument or /bin/echo.
    target = sys.argv[1] if len(sys.argv) > 1 else "/bin/echo"

    print(f"Local RE Agent started (session: {session_id})")
    print(f"Artifacts directory: {artifacts_dir}")
    print(f"Target binary: {target}")
    print()

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock_path)

    call_num = 0
    results = {}

    # --- Step 1: File type identification ---
    call_num += 1
    call_id = f"call-{call_num}"
    print(f"--- [{call_id}] file {target} ---")
    result = dispatch(s, call_id, ["/usr/bin/file", "-b", target], timeout_s=10)
    if result.get("error"):
        print(f"Error: {result['error']}")
    elif not check_budget(result):
        s.close()
        return
    else:
        results["file_type"] = result
        print(f"  exit_code={result['exit_code']}, "
              f"duration={result['duration_ms']}ms, "
              f"outputs={len(result['outputs'])}")

    # --- Step 2: String extraction ---
    call_num += 1
    call_id = f"call-{call_num}"
    print(f"--- [{call_id}] strings {target} ---")
    result = dispatch(s, call_id, ["/usr/bin/strings", "-a", target], timeout_s=30)
    if result.get("error"):
        print(f"Error: {result['error']}")
    elif not check_budget(result):
        s.close()
        return
    else:
        results["strings"] = result
        print(f"  exit_code={result['exit_code']}, "
              f"duration={result['duration_ms']}ms, "
              f"outputs={len(result['outputs'])}")

    # --- Step 3: Hex dump of file header (first 256 bytes) ---
    call_num += 1
    call_id = f"call-{call_num}"
    print(f"--- [{call_id}] hexdump -C -n 256 {target} ---")
    result = dispatch(s, call_id,
                      ["/usr/bin/hexdump", "-C", "-n", "256", target],
                      timeout_s=10)
    if result.get("error"):
        print(f"Error: {result['error']}")
    elif not check_budget(result):
        s.close()
        return
    else:
        results["hexdump"] = result
        print(f"  exit_code={result['exit_code']}, "
              f"duration={result['duration_ms']}ms, "
              f"outputs={len(result['outputs'])}")

    # --- Step 4: File metadata via stat ---
    call_num += 1
    call_id = f"call-{call_num}"
    print(f"--- [{call_id}] stat {target} ---")
    result = dispatch(s, call_id, ["/usr/bin/stat", target], timeout_s=10)
    if result.get("error"):
        print(f"Error: {result['error']}")
    elif not check_budget(result):
        s.close()
        return
    else:
        results["stat"] = result
        print(f"  exit_code={result['exit_code']}, "
              f"duration={result['duration_ms']}ms, "
              f"outputs={len(result['outputs'])}")

    # --- Summary ---
    print()
    print("=" * 60)
    print(f"Analysis Summary for {target}")
    print("=" * 60)
    print(f"  Tool calls dispatched:  {call_num}")
    print(f"  Successful results:     {len(results)}")

    # Try reading output artifacts from each successful run.
    for step_name, res in results.items():
        run_id = res.get("run_id", "")
        output_list = res.get("outputs", [])
        if output_list:
            print(f"  [{step_name}] run_id={run_id}, "
                  f"{len(output_list)} artifact(s)")
            for out_file in output_list:
                content = read_artifact(artifacts_dir, run_id, out_file)
                if content is not None:
                    # Show first few lines of each artifact.
                    lines = content.splitlines()
                    preview = lines[:5]
                    print(f"    {out_file} ({len(lines)} lines):")
                    for ln in preview:
                        print(f"      {ln}")
                    if len(lines) > 5:
                        print(f"      ... ({len(lines) - 5} more lines)")
        else:
            print(f"  [{step_name}] run_id={run_id}, no output artifacts")

    s.close()
    print()
    print("Local RE Agent finished.")


if __name__ == "__main__":
    main()
