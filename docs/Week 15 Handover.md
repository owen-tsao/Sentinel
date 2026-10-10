# Week 15 Handover: Gates for the Hook-Based Supervisor

Date: October 10, 2026. Claude Code 2.1.296 on macOS. Commits `8a6e655`
(Gates 1 and 2a, direction) and `f0e7420` (Gate 2b, extractor hardening).

## Go/no-go for Week 16: **go**

All three gates passed their kill conditions. The adapter may be built.

| Gate | Question | Kill line | Measured | Result |
|---|---|---|---|---|
| 1 | Can a managed Claude Code hook deny an action and inject context the agent sees? | deny or injection fails | deny delivered verbatim to the model; injected boundary line quoted back; agent could not edit the hook | pass |
| 2a | Can a floor-oriented extractor classify real agent shell without failing closed? | more than 1 in 20 unclassifiable | 89 of 18,551 unparseable (0.5%) | pass |
| 2b | Does the floor catch the 2026 incidents without flagging benign twins? | below 100% incidents, below 90% held-out, more than 1 in 20 twins flagged | 14/14 incidents, 26/26 held-out, 0/120 twins | pass |

Evidence and method: `spikes/week15/gate1/RESULTS.md`,
`spikes/week15/gate2a/RESULTS.md`, `spikes/week15/gate2b/RESULTS.md`. The
evaluation sets are checked in under `spikes/week15/gate2b/` except the 120
benign twins, which carry the user's real paths and are regenerated locally
from the corpus by `build_sets.py`.

## What the gates taught, beyond pass/fail

These are the facts Week 16 is built on. Each one changed a design decision.

1. **The deny string is a product surface.** Claude Code hands the hook's
   stderr to the model verbatim. After one deny the agent explained, offered
   alternatives, re-ran only the harmless half of a compound command, and did
   not retry. Agent-facing guidance in every verdict is not optional copy.
2. **Telling the agent its boundary prevented two of three dangerous attempts
   before the hook fired.** This is why "tell" is scheduled in Week 17 as its
   own feature rather than folded into enforcement.
3. **Real agent shell is compound.** 88% of 18,551 commands use `&&`, `;` or
   `|`; 19% are multiline; 12% carry heredocs; 8% are inline interpreter
   programs. The shipped 14-command whitelist would reject nine in ten. The
   floor is allow-by-default with a deny-list of destructive shapes, and the
   heredoc body is data, stripped before parsing.
4. **Every construct the parser skips is a silent allow.** The adversarial
   pass found that `(cd / && rm -rf *)`, `pushd`, `if`/`for` bodies, and
   wrappers such as `nice -n 5 rm` were invisible to the first walker. The
   corpus had 109 destructive commands hiding in those shapes. "Does the
   walker visit every node type" becomes a permanent test, not a one-time
   check.
5. **Parser gaps must not fail open on unambiguous text.** `bashlex` cannot
   parse `time cmd` or `$((…))`. The floor now runs a literal scan for the
   deadliest shapes (`rm` + recursive flag + `/`, `~`, `$HOME`) when the
   parser fails, and warns on everything else.
6. **Home is not a trusted working directory.** Three of the incidents were
   agents launched from `~`. Children of `~` zone as "outside" even when `~`
   is the cwd; deleting the cwd itself is its own zone (`cwd_root`, confirm);
   any ancestor of home zones as home (block).
7. **Unset variables in delete targets evaluate to empty.** `rm -rf "$DIR"/*`
   with `$DIR` unset is `rm -rf /*`. This is the single rule that catches the
   Claude Code home-wipe shape, and `$(…)` stays dynamic (not judged).
8. **Interruptions, measured on months of the user's own history:** 152 raw
   confirms over 18,551 commands became 30 distinct questions once the
   boundary is worktree-aware and asks once per (cwd, target). The budget in
   Week 16 is measured against Claude Code's own prompts (about 3 per short
   session in default mode; zero in auto-accept mode, where every Sentinel
   message must justify itself alone).
9. **Windows is a separate grammar.** `rd /s /q`, `del /s`, `Remove-Item
   -Recurse` need their own pre-pass; the Cursor drive-wipe incidents
   (`cmd /c "rd /s /q \"\""`) collapse an unset variable to the drive root.
   Shipped as a regex pre-pass in the spike; honest coverage statement
   required in Week 16 (no Windows host was tested live).

## Review honesty

Independent review did not run. Bugbot failed twice and the general reviewer
was rejected by the provider's usage filter, because a review brief for this
material must list destructive commands. The adversarial pass in
`gate2b/RESULTS.md` was self-review, done as batches of concrete commands run
through `floor()`. It found eight dangerous-to-allow gaps and one grader bug
("caught" counted a matched `warn` as a catch), all fixed, all kept as the 45
`adv-*` regression cases. The test cases were still chosen by the author.

Owed: a diff-based Bugbot run against `f0e7420` once the files are committed
(a diff review may pass the filter where a prose brief did not), and a
second adversarial pass by someone who did not write the rules, before the
floor is called product code.

## Decision: the Week 14 UI is kept as the fixture bench, not deleted

The manual contract form, proposal card, and write-budget controls leave the
primary flow (Product Direction §3.3). Whether to delete the code or keep it
was deferred to this week.

**Decision: keep, behind a `/bench` route, out of primary navigation.**

Why: the MCP mediator, gateway, contract lifecycle, and budget logic are kept
for the fixture path (Direction §4), and 636 passing tests plus five
Playwright specs exercise them through this UI. Deleting the UI without
deleting the backend leaves the kept path with no driver and no regression
bench; deleting both is a day of test surgery for code the roadmap says to
keep. Moving the pages under `/bench` costs the same day and preserves the
only end-to-end exercise of the verdict model and audit store that the Week
16 hook path will share.

Revisit trigger: if the bench has not been run by Week 18's validation, it is
deleted in the release-hardening pass.

Scheduled: Week 16, one day, as the roadmap already states.

## Decision: ceiling v2 design

The ceiling (`SupervisionPolicy`) today has five fields and one environment:

```
ordinary_operations, confirm_operations, budgetable_operations,
max_write_budget, standing_read, environment ∈ {sandbox}
```

Its content hash is bound to the state database on first start, so a weaker
ceiling cannot be introduced by editing config and restarting. That property
is kept and is the reason v2 cannot be a silent upgrade.

**v2 adds, all server-owned, none editable through any agent-reachable
surface:**

| Field | Content | Source |
|---|---|---|
| `version` | `2` | new |
| `floor_rules` | the fixed rule identifiers the floor enforces: `F1` destructive write or delete whose target resolves to home, root, system, protected config (hook and Sentinel files, shell history) or a credential store (block); `F2` defense evasion (block); `F3` credential read (block); `F4` exfiltration, a file sent off the machine after a credential read earlier in the session (block); `F5` destructive outside cwd, or deleting the cwd itself (confirm); `F6` file egress and remote-script execution (confirm); `F7` force-push to protected history (confirm); `F8` network exposure, infrastructure destroy, production schema change (confirm); `W1`–`W5` observe-only warns (git history inside repo, unresolvable delete, local infra, opaque interpreter, parser gap) | Gate 2b `floor.py`; the list is the policy, the implementation is not |
| `environment` | `dev`, `sandbox`, `staging`, `production`; `production` promotes `F5`/`F7` confirms to block and disables `standing_read` | Direction §3.2 |
| `detector_thresholds` | stuck: same action → same result 4×; same action → error 3×; A/B alternation over 6 steps | Week 17 spike may raise, never lower below these |
| `message_budget_per_boundary` | 2 detector messages; the floor is not budgeted | Direction §3.2 |
| `parser_gap_policy` | `literal_fallback_then_warn` (the only value in v2; named so the audit row says which policy produced an observe) | Gate 2b finding 5 |
| existing five fields | unchanged, used by the fixture path only | Week 12–14 |

**What the floor list in the ceiling is for.** The ceiling does not make the
floor configurable downward. It names the rules so that (a) the audit row can
cite `ceiling v2 / F1` and a reader can verify the rule existed when the
verdict was made, and (b) a future rule addition changes the hash, which
forces the migration message rather than a silent widening or narrowing.

**Migration.** A v2 process opening a state database whose
`supervision_policy_binding` row has no `version` column, or has version 1,
refuses to start and prints:

> This Sentinel state database was bound to ceiling v1 (first bound
> `<first_bound_at>`, hash `<first 12 of content_sha256>`). Ceiling v2 adds
> the floor list and environments and does not migrate v1 state. Export the
> audit (`sentinel audit export --out <path>`), then move or delete
> `<database path>` and start again. Nothing in the audit is lost by the
> export; the contract and approval state is fixture-only and is discarded.

No automatic migration. The v1 database holds fixture state only; the audit
is exported, not converted. Cost: one day in Week 16, as scheduled.

## What Week 16 inherits

- `spikes/week15/gate2a/extract.py` and `spikes/week15/gate2b/floor.py` are
  the reference implementation of the floor. They are spike code: no package
  structure, `sys.path` imports, `bashlex` pulled in ad hoc. Week 16 ports
  them into `src/sentinel/` with the 15 incidents, 39 held-out, and 69 hard
  twins as the test suite, and the Gate 2a corpus run as a local regression
  check that is not committed.
- `spikes/week15/gate1/hook.py` is the shape of the adapter: read the hook
  event on stdin, resolve paths with `Path.resolve()` (macOS `/tmp` →
  `/private/tmp`), exit 2 with the reason on stderr for deny. The real adapter
  calls the decision API and writes the audit row before returning.
- The decision record must be designed before the adapter writes its first
  row. It holds a shell decision (command, resolved targets with zones, rule,
  verdict, guidance) and, in the same shape, a future service call (tool,
  recipients, audience size, purpose matched). Direction §10.
- Open from Gate 1: the hook string-matched settings filenames without
  checking read vs write and denied an `ls`. The extractor now distinguishes
  reads from writes; the adapter must use it rather than its own matching.

## Not verified this week

- No live Windows host. The Windows pre-pass is tested only against the
  forensic command text from the Cursor reports.
- No live `Edit`-deny round trip in Gate 1; the agent refused to attempt the
  edit after reading the hook. Same exit-code contract as Bash; accepted.
- Independent review (above).
- The benign-twin set is sampled from one user's projects on one machine. The
  false-flag rate is an estimate of that user's experience, not a population
  figure.
