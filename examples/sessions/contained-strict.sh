#!/usr/bin/env bash
# Demo: agent with strict containment profile + budget override.
#
# The "strict" profile is the most restrictive:
#   - No network access
#   - 128M memory, 1m timeout, 32 PIDs
#   - Budget: 20 tool calls, 10m wall time, 5m tool time, 256 MiB output
#
# This demo overrides --budget-tools=3 to show budget enforcement.
#
# Usage:
#   ./contained-strict.sh
#
# Prerequisites:
#   - oaie init (run once to create the store)

set -euo pipefail

AGENT_SCRIPT=$(mktemp /tmp/oaie-agent-XXXXXX.py)
cat > "$AGENT_SCRIPT" <<'PYTHON'
#!/usr/bin/env python3
"""Agent that tries 5 calls but strict budget only allows 3."""
import os, socket, json

sock_path = os.environ["OAIE_DISPATCH_SOCK"]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)

for i in range(5):
    req = json.dumps({"id": f"call-{i}", "command": ["/bin/echo", f"strict call {i}"]}) + "\n"
    s.sendall(req.encode())
    resp = b""
    while not resp.endswith(b"\n"):
        chunk = s.recv(4096)
        if not chunk:
            break
        resp += chunk
    result = json.loads(resp.decode())
    if result.get("error"):
        print(f"Call {i}: REJECTED - {result['error']}")
        break
    else:
        print(f"Call {i}: exit_code={result['exit_code']}")

s.close()
PYTHON

chmod +x "$AGENT_SCRIPT"

echo "=== Running agent with --contained=strict --budget-tools=3 ==="
oaie session run --contained=strict --budget-tools=3 --name=strict-demo -- python3 "$AGENT_SCRIPT"

rm -f "$AGENT_SCRIPT"
