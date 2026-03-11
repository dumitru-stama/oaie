#!/usr/bin/env bash
# Demo: agent with local containment profile.
#
# The "local" profile is designed for agents backed by local LLMs
# (ollama, llama.cpp, vLLM). Tools run in sandboxes with:
#   - No network access
#   - 1G memory, 10m timeout, 128 PIDs, memfd allowed
#   - Budget: 100 tool calls, 1h wall time, 30m tool time, 2 GiB output
#
# Usage:
#   ./contained-local.sh
#
# Prerequisites:
#   - oaie init (run once to create the store)

set -euo pipefail

# Simple agent that dispatches one tool call via the OAIE dispatch socket.
AGENT_SCRIPT=$(mktemp /tmp/oaie-agent-XXXXXX.py)
cat > "$AGENT_SCRIPT" <<'PYTHON'
#!/usr/bin/env python3
"""Minimal OAIE session agent: dispatches 'echo hello' via dispatch socket."""
import os, socket, json

sock_path = os.environ["OAIE_DISPATCH_SOCK"]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)

req = json.dumps({"id": "call-1", "command": ["/bin/echo", "hello from contained-local"]}) + "\n"
s.sendall(req.encode())

resp = b""
while not resp.endswith(b"\n"):
    chunk = s.recv(4096)
    if not chunk:
        break
    resp += chunk

result = json.loads(resp.decode())
print(f"Tool call result: exit_code={result['exit_code']}, outputs={len(result['outputs'])}")
s.close()
PYTHON

chmod +x "$AGENT_SCRIPT"

echo "=== Running agent with --contained=local ==="
oaie session run --contained=local --name=local-demo -- python3 "$AGENT_SCRIPT"

rm -f "$AGENT_SCRIPT"
