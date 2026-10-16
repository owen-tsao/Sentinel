# Spike C1 results: can a Cursor hook put words in front of the agent?

Run: October 13, 2026, Cursor 3.24.12, scratch project `/tmp/cursor-probe`,
project hooks (`.cursor/hooks.json`), model `us.anthropic.claude-fable-5-1`.
Probe: `probe_hook.py` returned five candidate context fields with distinct
markers on every event and logged every raw payload.

## Verdict: pass. Hear, Tell, and Stuck port to Cursor one-for-one.

| Question | Result |
|---|---|
| Which field reaches the agent? | **`additional_context` only.** `agent_message`, `additionalContext`, `context`, `system_message` never seen |
| On which events? | `beforeSubmitPrompt` (arrives bundled with the user message in a `<system_reminder>`), `preToolUse`, `postToolUse`, `postToolUseFailure` |
| When does `preToolUse` context land? | Alongside the tool result, after the call ran. Same as Claude Code's `PreToolUse` `additionalContext`: it shapes the next decision, not the current call |
| Person-facing text on an allowed action? | **None.** `user_message` on `permission: allow` is not shown anywhere in the UI. Cursor's own popup appears only for `ask`/`deny` |
| `sessionStart`, `beforeShellExecution`, `afterShellExecution` | Fired (`sessionStart` did not, the session pre-dated the hooks) but carried no marker: no context channel on those events |

## Payload shapes (verified from the log)

Every event carries `conversation_id`, `session_id` (equal), `generation_id`,
`tool_use_id`, `workspace_roots` (list), `cursor_version`, `model`,
`user_email`, `transcript_path` (null in this run).

- `beforeSubmitPrompt`: `prompt`, `attachments` (list), `composer_mode`,
  `model_id`, `model_params`.
- `preToolUse`: `tool_name` (`Shell`), `tool_input` (`{command, cwd, timeout}`),
  `cwd` (**empty string** for Shell; the working directory must come from
  `workspace_roots` or the hook process's own cwd).
- `beforeShellExecution`: `command`, `cwd` (empty), `sandbox` (bool). Fires
  for the same `tool_use_id` as `preToolUse`; the adapter must dedupe.
- `postToolUse`: `tool_output` is a JSON **string** `{"output": …,
  "exitCode": 0}`; `duration` in ms.
- `postToolUseFailure`: `error_message` (raw text), `failure_type`
  (`error`), `is_interrupt`. No exit code.
- `afterShellExecution`: `command`, `output` (raw), `duration`.

Privacy notes for the adapter: never store `user_email`, `prompt`,
`output`, or `error_message`; hash results as Week 17 does.

## What this changes

- Cursor hooks are **command hooks** (a script on stdin/stdout), not HTTP.
  The adapter needs a dependency-free forwarder script that POSTs the
  payload to Sentinel and prints the translated response, exiting 2 when
  Sentinel is unreachable so `failClosed: true` denies.
- There is no `systemMessage` equivalent on allow. The one budgeted
  person-facing stuck message can only be delivered as `permission: ask`
  with `user_message` (Cursor's own approval popup), or not at all.
  Decision recorded in `docs/Week 18 Plan.md`.
- Working directory: `cwd` is empty on Shell events. Use the forwarder's
  own `os.getcwd()` (project hooks run from the project root) as the launch
  directory, posted once per session, exactly as the Claude Code
  `SessionStart` hook does; `workspace_roots` is a cross-check, not authority.
