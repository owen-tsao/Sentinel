# Spike C2: can Cursor ask the person for Sentinel? (Option A)

Run: October 13, 2026, 21:24–21:36, Cursor 3.24.12, scratch project
`/tmp/cursor-probe`, Run Modes Allowlist, Auto-review, Run Everything.
Probe: `ask_probe.py` logged every payload and returned `permission: ask` on
`beforeShellExecution` for commands containing `ASKME`, `{}` otherwise.
Log: `/tmp/sentinel-cursor-probe/c2.jsonl` (48 events); summary via
`summarise.py`.

## Why this spike

The Week 18 live gates found that `permission: ask` on `preToolUse` is not
enforced (Cursor docs: "accepted by the schema but not enforced for
`preToolUse` today"). Live, it became *allow* for `Delete` (row 61: the
file was deleted with no popup) and *deny* for `WebFetch` (row 120:
Cursor's own text "The 'ask' permission for preToolUse hooks is not yet
implemented"). A confirm the person never sees is an allow. The docs say
`ask` works on `beforeShellExecution`; this spike checked whether that is
true and whether the two events can be stitched together.

## Verdict: pass. Confirm is deliverable for shell; file tools stay deny-or-allow.

| Question | Result |
|---|---|
| Q1 `ask` + `user_message` on `beforeShellExecution` shows a popup | **Yes, 8/8.** Forced even for an allowlisted `echo` that otherwise ran silently (`echo hello`: no card; `echo ASKME-n`: card, 3/3 in Allowlist mode) |
| Q1 our text on the card | **Mode-dependent.** Shown as "Hook requested approval: <user_message>" in Auto-review and Run Everything; **dropped** in Allowlist mode, where Cursor draws its own allowlist card (Skip / Always Run / Run) |
| Q5 `ask` under Run Everything | **Does not degrade.** Card with our text appeared |
| Q2 order | `preToolUse` → `beforeShellExecution` 72–124 ms later → `afterShellExecution` → `postToolUse`, 9/9 |
| Q2 shared id | **Yes, 9/9**: all four events carry the same `tool_use_id` |
| Q3 subagent shell | All four events fired, `parent_tool_call_id` set |
| Q3 background shell | `preToolUse`, `beforeShellExecution`, `postToolUse` fired (the last when the agent collected it, +30 s); `afterShellExecution` did not |
| Q4 after Skip | `afterShellExecution` and `postToolUse` fire with `{"output":"","exitCode":0}`, **indistinguishable from a successful silent command**. Cursor does not tell hooks the person skipped |
| `agent_message` on `ask` | **Never reached the agent**, on Run or on Skip. The agent's reason must travel as `additional_context` on `preToolUse` |
| `{}` on `beforeShellExecution` | **Accepted.** Allowlisted command ran with no card; non-allowlisted command still got Cursor's own card. Sentinel never needs to say `allow` |
| `beforeShellExecution` payload | `command`, `cwd` (empty for top-level shells, set for the subagent's), `sandbox`, `tool_use_id`, `parent_tool_call_id`, plus the common fields |

## What this decides (Option A)

- Sentinel judges every tool once, on `preToolUse` (fail-closed coverage for
  all tools). For `Shell`, a `confirm_required` (floor) or the detector's one
  budgeted message is **not** answered there; the service remembers the
  `tool_use_id` and answers `{"permission": "ask", "user_message": …}` when
  `beforeShellExecution` arrives with that id. Everything else on
  `beforeShellExecution` is `{}`.
- If `beforeShellExecution` arrives for an id Sentinel never judged (a host
  where `preToolUse` did not fire), it judges the command itself, so the
  event is self-sufficient. Both events are gating in the forwarder: with
  Sentinel down, both deny with the "not running" reason.
- File tools (`Delete`, `Write`, `StrReplace`, `ApplyPatch`) have no
  ask-capable event. Their `confirm_required` is delivered as `deny` with
  guidance to ask the person in chat (the Claude Code `ask_fallback_modes`
  shape). Rows keep `verdict: confirm_required, response: deny`.
- The agent-facing reason goes in `additional_context` on `preToolUse`
  (verified channel, spike C1), since `agent_message` never arrives.

## Stated limits

- In Allowlist mode the person sees Cursor's card without Sentinel's reason.
  Sentinel cannot see the Run Mode (no payload field), so it cannot adapt.
- A skipped command and a silent success look identical to hooks;
  `was_asked: true` on the post row records that a question was put, not the
  answer. The Week 19 "messages per hour" number counts questions, as before.
- Verified on 3.24.12 only.
