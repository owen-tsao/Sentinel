#!/usr/bin/env python3
"""Step A(5): a hook that denies with a reason and exits 0, to check that
Cursor shows the reason (exit 2 drops it, per Gate C-H0)."""
import json
import sys

sys.stdin.read()
print(json.dumps({"permission": "deny",
                  "user_message": "Sentinel probe: DENY-WITH-REASON shown via exit 0.",
                  "agent_message": "Sentinel probe: this call was denied by a test hook; do not retry."}))
sys.exit(0)
