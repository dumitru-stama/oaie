#!/usr/bin/env bash
# Demo: agent with cloud containment profile.
#
# The "cloud" profile is designed for agents backed by cloud LLMs
# (Claude, GPT). Tools run in sandboxes with:
#   - No network access (agent handles API calls on host)
#   - 512M memory, 5m timeout, 64 PIDs
#   - Budget: 50 tool calls, 30m wall time, 10m tool time, 1 GiB output
#
# Usage:
#   ./contained-cloud.sh
#
# Prerequisites:
#   - oaie init (run once to create the store)

set -euo pipefail

AGENT_SCRIPT=$(mktemp /tmp/oaie-agent-XXXXXX.py)
cat > "$AGENT_SCRIPT" <<'PYTHON'
#!/usr/bin/env python3
"""Agent that dispatches two tool calls to demonstrate cloud profile."""
import os, socket, json

sock_path = os.environ["OAIE_DISPATCH_SOCK"]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)

for i in range(2):
    req = json.dumps({"id": f"call-{i}", "command": ["/bin/echo", f"cloud tool call {i}"]}) + "\n"
    s.sendall(req.encode())
    resp = b""
    while not resp.endswith(b"\n"):
        chunk = s.recv(4096)
        if not chunk:
            break
        resp += chunk
    result = json.loads(resp.decode())
    print(f"Call {i}: exit_code={result['exit_code']}")

s.close()
PYTHON

chmod +x "$AGENT_SCRIPT"

echo "=== Running agent with --contained=cloud --llm=anthropic ==="
oaie session run --contained=cloud --llm=anthropic --name=cloud-demo -- python3 "$AGENT_SCRIPT"

rm -f "$AGENT_SCRIPT"
