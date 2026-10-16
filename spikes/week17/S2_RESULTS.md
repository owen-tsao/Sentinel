# Spike S2 results: stuck thresholds on real agent sessions

Run: October 12, 2026. Corpus: 181 top-level Cursor agent transcripts on
this machine (164 with at least one tool call; 72,188 tool calls). The 741
subagent transcripts were excluded (short, single-purpose, not what a person
supervises). Script: `s2_stuck_replay.py <repeat_threshold>`. The transcripts
are not checked in; only the aggregate JSON is.

## Question

Do the OpenHands thresholds (same action 4x, A/B alternation over 6) flood on
legitimate work? Kill line from the Roadmap and Direction §5: more than 1 in
10 benign sessions trip.

## Method and its limit

Transcripts carry ordered `tool_use` blocks but no results, so every result
is treated as identical. The repeat signal (S1) is therefore an **upper
bound**: a 4x identical action trips here even where the real results
differed (and the real detector would not fire). Alternation (S3) uses no
results and is exact. The error-loop signal (S2) cannot be measured offline.

Action identity: tool name + SHA-256 of the input with `description`,
`timeout`, `explanation`, `block_until_ms`, `working_directory` dropped and
whitespace in shell commands collapsed; this is the identity §3.5 of the plan
specifies.

## Result: pass at threshold 4

| Threshold | Sessions tripping | Share | S1 episodes | S3 trips | Trips / 100 actions |
|---|---|---|---|---|---|
| 4 (plan) | 6 / 164 | **3.7%** | 8 | 0 | 0.019 |

Every trip was `Write` to the same path with identical contents four or more
times in a row (7 episodes) or `AwaitShell` on the same shell (1 episode).
The `Write` repeats are the agent re-saving an identical file, which is a
genuine no-progress loop; the `AwaitShell` case is a legitimate wait on a
long command and is the one false positive the upper bound surfaces. In the
real detector, waiting produces different results each time (elapsed output
changes), so it would not fire.

## One bug the spike caught in itself

The first run reported 9.8% (16/164) with 169 episodes, all `ApplyPatch`.
Cause: `ApplyPatch` inputs arrive as a raw string, not a dict, and the
identity function collapsed every non-dict input to `{}`, making all patches
"identical". Fixed by hashing string inputs as-is. Lesson for the product
detector: `tool_input` must be hashed whatever its type, never coerced to an
empty mapping.

## Decision

Thresholds stay at 4 / 3 / 6. No message is shown by the detector until the
live gate confirms the error path (`PostToolUseFailure`) and `systemMessage`
rendering (spike S3).

## What this spike measures, honestly (review finding 21)

Cursor transcripts have Cursor tool shapes (`StrReplace{path,old_string,
new_string}`, `Shell{command,...}`), not Claude Code's (`Edit{file_path,...}`,
`Bash{command}`). So the replay measures **this person's retry habits**, not
identity canonicalisation on live Claude Code inputs. The only true-shape
sample is the 12 Claude Code sessions on this machine (49 tool calls, all
Sentinel gate tests): `--claude-code` flag.

| Sample | Sessions | Actions | Tripping | Note |
|---|---|---|---|---|
| Cursor (person's habits) | 164 | 72,188 | 6 (3.7%) | 7 identical `Write` episodes, 1 `AwaitShell` |
| Claude Code (true shape) | 12 | 49 | 1 (8.3%) | the Week 16 latency gate: `echo tick` run 30x deliberately; a true loop, caught at the 4th |

The alternation signal (S3) fired on nothing in either sample. Note that the
plan now adds a result condition to S3 (review finding 17), which this replay
cannot evaluate; the measured S3 rate is for the result-free variant and is
therefore an upper bound as well.
