# Week 15 Plan: Scope Decision, Threat Model v2, and Standing Permissions

> **Superseded on October 9, 2026.** This plan was never approved or started.
> The direction changed to a hook-based supervisor with an inferred boundary;
> see [Product Direction](./Product%20Direction.md) and the Week 15-18
> entries in the [Roadmap](./Roadmap.md). Kept for the record: the analysis of
> what makes an action dangerous feeds the new floor rules.

Status: **proposed on September 11, 2026 (evening); revised the same evening
after an adversarial review.** Starts from
[Week 14 Handover](./Week%2014%20Handover.md) and the
[Week 15 Scope Decision](./Week%2015%20Scope%20Decision.md). Not yet approved.
Part 1 needs your review of the scope decision before any Week 15 code; Parts
2 and 3 follow it in that order. This plan approves no new dependency.

Three terms used throughout, defined once. The **ceiling** is the set of fixed
limits Sentinel starts with, which nothing at runtime (no request, no agent, no
setting) can raise; it is what `SupervisionPolicy` is today. A **content
binding** is a fingerprint (SHA-256) of the exact text of an authority object,
so any change to it is detectable and a stale copy can be rejected. The
**shim** is the small program the agent host runs to talk to Sentinel over MCP.

**Why this replaced the Roadmap's original Week 15.** The original Week 15 was
"Transition Drafts and Persistent Guardrails". Week 14 ended with your verdict
that the write budget was the wrong abstraction and that Sentinel was quietly
building towards one toy tracker. The Roadmap was reordered on September 11:
decide what Sentinel protects and for whom first, write the threat model
against that, then build the "no click for routine work" mechanism as user-set
standing permissions rather than a startup constant. Transition drafts wait
until the scope decision shows where task changes actually happen.

## The problem in one paragraph

Today every write needs an activated task, and the task is a list of exact
record IDs decided against a fake tracker. That produces two kinds of friction
you named: an activation click for work that needed none, and a product shaped
like Jira. Meanwhile the security review that would harden the rules has
nothing real to harden against, because the only mediated tool is the fixture.
The fix is not another knob on the fixture. It is to decide the real boundary
(which resources, which hosts, which provider), write the threat model for that
boundary, and then let the person grant routine work once so that only
stepping outside, or doing something dangerous, ever asks.

## Goal

```text
person sets standing permissions once, in Settings (protected, versioned)
  "read and note issues SPIKE-1 to SPIKE-99"   (fixture bench, this week; the
                                                ceiling allows up to SPIKE-9999,
                                                so a task is still needed for
                                                SPIKE-100 and above)
  "read and post in #sentinel-dev, #random"    (Slack, Week 16, if the spike passes)

agent acts; Sentinel checks in this order
  1. never allowed by the ceiling, or outside BOTH the standing set
     and the active task                       -> block, guidance names the
                                                  smallest step outside
  2. inside the boundary but dangerous by
     provider facts                            -> one card per action
  3. inside the active task                    -> runs (or confirm-tier card)
  4. inside the standing set                   -> runs, audited, no click
                                                  (or confirm-tier card bound
                                                  to the standing version)

standing set narrows immediately; widening is the protected Settings flow
with a fresh content binding; nothing reached through Sentinel can change it
```

## Fixed decisions

- **The scope decision is reviewed before code.** Its four answers (owned
  mode only; Slack first; Cursor plus Claude Code; two-axis resource scope) are
  the inputs to Parts 2 and 3. If you change one, this plan changes with it.
- **The ceiling stays and stays immutable.** It becomes the product's outer
  bound ("what any standing set may ever contain"), and standing permissions
  are user data *inside* it. The ceiling gains one field, a per-tool-family
  shape it will accept in a grant (for the fixture: the issue pattern); a
  grant outside that shape is rejected at write time, never clamped. The three
  operation tiers stay.
- **Authority is "in the standing set OR in the active task".** Not both, not
  an intersection. A task stores only the step outside the standing set,
  computed at confirm time under the session lock from the *current* standing
  set (the card says "adds: SPIKE-901"), so narrowing the standing set later
  cannot leave a wider task behind: the task never contained the standing
  part. When a task expires, only the standing set remains. Today the proposal
  flow copies the whole target list into the contract; this changes that.
- **Standing permissions are authority, so they get contract-grade handling:**
  server-owned, versioned, content-bound, tied to the workspace identity,
  written only through the protected UI channel (cookie plus Origin), read
  under the same per-session lock that admits a write, and audited on every
  change with the old and new fingerprints.
- **Any standing-set change dismisses pending proposals**, because a
  proposal's "adds" (and even whether a task is needed at all) depend on the
  set at the moment of the answer; the agent is told to re-propose. In
  addition, **narrowing** invalidates pending approvals whose target is no
  longer in the set and suspends an active task only if the task's own "adds"
  overlap a removed grant (rare, and stated). **Widening** touches no active
  task.
- **A confirm card raised under standing authority binds to the standing
  version and grant** (fingerprint plus grant ID), exactly as a task-bound
  card binds to a contract version. A narrowing that removes the grant
  invalidates the card. This keeps the Week 10 to 12 replay and stale-view
  guarantees.
- **The runaway cap becomes well-defined.** Per task it stays as built (50
  writes, then block), counted from the durable fixture operation records
  keyed by task. Standing writes get their own durable count in the same
  table, keyed by (session, standing version, grant ID) and bounded to
  operations recorded after the current process started, so a restart or a
  new standing version starts fresh even though the records themselves
  persist. The existing `task_id` column holds `standing:<version>:<grant>`
  for these rows instead of the Week 14 placeholder. Its guidance is distinct:
  "this grant hit its runaway limit for this Sentinel session; stop and tell
  the person, who can restart Sentinel or narrow the grant", never "propose a
  task", so a looping agent cannot bounce between "propose" and "no task
  needed".
- **"Dangerous" is decided from facts, never from a model**, and a dangerous
  action asks regardless of task or standing set. For the fixture nothing is
  dangerous. For Slack the facts are the ones normalised in
  `AudienceSnapshot`: `is_external_shared`, `external_recipient_ids`,
  `guest_recipient_ids`, `recipient_count` over a breadth line, private
  channel, irreversible operation, wrong workspace.
- **Scope is resource-shaped.** Standing grants name a pattern or a resource
  list, not record IDs. This week the only grant shape with a live tool is the
  fixture issue pattern; the channel-list shape is defined as a data type with
  tests but no live tool. No path-prefix shape: Sentinel has no mediated file
  tool.
- **Hosts:** Cursor keeps its Week 12 mandatory claim under the tested
  configuration. Claude Code is added only if the Day 1 spike shows the
  managed-settings lock holds under a named configuration (its sandbox on,
  edits to `~/.claude/` denied). Codex and Hermes are written into the
  coverage map as advisory with the reason. No host code beyond a config
  template and a documented setup.
- **No Slack write this week.** The Day 1 spike reads facts with the existing
  probe and proves argument fidelity from Claude Code with the existing
  fixture tools. A mediated `slack_post_message` would need a new tool family
  in the gateway and ceiling, which is Week 16 work, so it is not smuggled in
  as "a spike".
- **ML hardening stays deferred** until a mediated provider produces real
  decisions to evaluate against.

## What happens to the Week 14 code and state

Said explicitly so nothing is deleted or kept by accident:

- `ActionContract.write_budget`, the three ceiling tiers, `WriteBudgetState`,
  and `count_spent_writes` **stay**: the per-task cap is unchanged.
- The ceiling's `standing_read` flag is **removed**; the fixture read grant in
  the shipped standing set replaces it. `STANDING_READ_TASK_ID` and the
  `supervision:standing_read` reason are replaced by `standing:<grant>`.
- `tests/test_standing_reads.py` (7 cases) is **rewritten** as standing-grant
  tests, keeping the quarantine case: a quarantined authority blocks standing
  writes and reads alike. `tests/test_write_budget.py` (13) and the two Week
  14 Playwright specs **stay**, with copy assertions updated.
- **Ceiling hash and existing state databases.** Changing the ceiling's fields
  changes its fingerprint, and `SQLiteSupervisionPolicyStore.bind` already
  refuses a state DB bound to a different fingerprint; today that refusal is a
  bare reason code and a traceback. Tier 1 adds the clear message: the
  launcher catches `supervision:policy_binding_mismatch` and prints which
  state file was bound to an older Sentinel and how to start fresh. No silent
  migration.
- **Where standing permissions live.** They must survive a restart or "set
  once" is false. They are stored in the same SQLite state DB as contracts,
  keyed by workspace identity. Reusing that DB across launches means reusing
  the whole demo root: the sample repository (the workspace identity is bound
  to its path and inode), the state DB, and the fixture DB beside it. So the
  launcher gains a `--reuse ROOT` option that points at an existing demo root
  instead of creating a timestamped one; the default stays disposable so tests
  and the fixture bench start clean. The option can only *point at* a root,
  never seed a grant: the test in Part 3 that "no route but the protected flow
  can change the set" includes launcher flags and `SENTINEL_*` environment
  variables.

## Riskiest assumption

> A person can lock a second host (Claude Code) so a provider is reachable only
> through Sentinel, and a real provider (Slack) returns the facts Sentinel
> needs to call an action dangerous, including for the channels that matter
> (Slack Connect, private, guest).

Split into checks, each **unverified** until Day 1, each with a kill condition:

1. **Claude Code lock.** Named configuration: Claude Code's sandbox on;
   `~/.claude/managed-settings.json` with `allowedMcpServers: [sentinel]` and
   `allowManagedMcpServersOnly: true`; a `managed-mcp.json` naming only
   Sentinel; a permission rule denying edits under `~/.claude/`; installed
   version recorded. Checks: (a) the agent cannot add a server via
   `claude mcp add`, a project `.mcp.json`, or `--mcp-config`; (b) the agent
   cannot edit the managed files; (c) `sentinel_issue_read` and
   `sentinel_issue_add_note` arrive at Sentinel with the same canonical
   arguments as from Cursor. **Kill:** if (a) or (b) fails, Claude Code is
   labelled advisory in the coverage map and Part 3 targets Cursor only.
2. **Slack facts for the dangerous cases.** Against the seeded disposable
   workspace (Pro trial, bot invited to the private channel), the existing
   read probe returns `is_ext_shared`, `is_private`, `num_members`, and member
   classification for a Slack Connect channel, a private channel, and a
   channel with a guest. **Kill:** if a channel that *was* seeded returns
   facts that do not classify it, "dangerous by facts" is not yet true for
   Slack, Week 16 is re-planned before any provider code, and Part 3 is built
   against the fixture bench only. A case that could not be seeded is recorded
   as *not tested* and does not trip this.
3. **Standing permissions cannot leak (design).** Widening is impossible from
   the agent, the confirm body, the activation body, launcher flags, and
   environment variables; narrowing invalidates conflicting pending items;
   task expiry leaves only the standing set; a standing write under a
   quarantined authority blocks. **Kill:** if any of these fails in the Part 3
   tests or the independent review, the build reverts to activation-per-task.

## Threat model additions (feed Part 2)

Part 2 writes threat model v2 for the whole product as scoped. These are the
items this week itself introduces and must close:

- **Widening through the settings route.** Control: same protected channel as
  activation (cookie plus Origin plus workspace identity), content-bound
  version, audit event, and a test that no other route, flag, or variable can
  change the set.
- **Stale standing set at admission.** A write admitted against version N
  lands after N+1 removed the grant. Control: the standing set is read under
  the same per-session lock that admits the write, so the two cannot
  interleave.
- **Stale cards and proposals.** Control: narrowing invalidates pending
  approvals and proposals outside the new set; widening dismisses pending
  proposals so their "adds" are recomputed; tests cover both races.
- **Task retaining authority.** Control: a task stores only its "adds", so
  there is nothing standing-shaped in it to retain; a test narrows the set
  mid-task and shows the task's reach did not change.
- **Stale provider facts (Week 16, named now).** A channel becomes externally
  shared after Sentinel read its facts. Control: facts are read per decision
  and carry a `state_version`; a decision never reuses facts older than the
  call.
- **Token exposure (Week 16, named now).** The bot token must never reach the
  agent, tool results, audit records, or frontend state. The spike keeps it in
  one environment variable read by the probe only.
- **Config edit by the agent on the second host.** Control: the deny rule
  checked in 1(b), and native shell stays advisory regardless.

## Phases

### Day 1: Part 1, decision review and spike

Morning, no code: you read the [Week 15 Scope Decision](./Week%2015%20Scope%20Decision.md),
change what you disagree with, and approve. Then the Roadmap's Week 16 and
Product Architecture's weekly list are updated to match, so the docs stop
disagreeing with each other. The ten baseline fixture runs happen while the
Slack workspace is being seeded, since both are mostly waiting. Afternoon, the
spike; if Day 1 runs long, the Slack facts run moves to Day 2 morning and the
threat model starts after it, because the facts record is an input to it:

- `scripts/week15_spike/` (disposable, like `scripts/week12_spike/`): a Claude
  Code `managed-settings.json` and `managed-mcp.json` template pointing at the
  existing shim; a checklist script that tries to add a server three ways and
  edit the managed files, recording pass or fail and the Claude Code version;
  a Slack facts run against the seeded channels using the existing probe, with
  the sanitised summaries written the way `data/spikes/` already does.
- **Record** the results in a `### Day 1 record` appended to this plan, with
  each kill condition marked hit, clear, or not tested.

### Day 2: Part 2, security deep review

One day, written up as `docs/Week 15 Threat Model v2.md`:

- Threat model v2 for the product as scoped: agent-side (prompt injection via
  channel or issue content, replay, time-of-check races, proposal floods),
  host-side (same-user process, cookie and Origin assumptions, the service
  worker, host config edits), human-side (mis-clicks, stale views,
  notification fatigue, over-wide standing grants).
- An afternoon red-team pass against the real code (gateway, mediation,
  proposals, control routes, notifications), written as findings with
  severity, using independent review subagents as well as manual reading.
- An **enforcement coverage map**: every surface (Cursor MCP fixture tools,
  Cursor shell/file/browser, Claude Code MCP, Codex, Hermes, the Docker
  executor) marked enforced / advisory / unsupported with the reason and the
  configuration the claim depends on.
- A **ranked fix list.** Anything medium or higher is fixed inside Week 15;
  low items are scheduled or accepted with a stated reason. **Budget rule:**
  if the list has two or more medium-plus findings, Part 3 shrinks to its
  first tier (below) and the Settings section lands in Week 16.

### Days 3 to 5: Part 3, standing permissions

Built in two tiers so the week can end honestly if Day 2 eats time.

**Tier 1 (must ship): the authority, without a screen.**

1. **Model and store.** `StandingPermissionSet`: version, content fingerprint,
   workspace identity, and a list of grants, each naming a tool family, a
   resource shape (fixture issue pattern now; channel list as a typed,
   tested shape with no live tool), and the operations allowed without a
   task. Validated against the ceiling's per-family shape at write time.
   Stored in the state DB with full version history.
2. **Protected routes.** Read the current set; propose a change (returns the
   diff and the new fingerprint); confirm by fingerprint. Same cookie, Origin,
   and workspace checks as activation; the confirm body forbids extra fields.
   Narrowing and widening behave exactly as the fixed decisions say. Every
   change is an audit event with old and new fingerprints.
3. **Decision order in the mediator**, as in the Goal block: block outside
   both sets first, then dangerous, then task, then standing. Standing
   decisions carry reason `standing:<grant>`; standing-bound confirm cards
   bind to (version, grant). The standing runaway cap as defined above.
4. **Fixture bench.** The shipped standing set for the fixture is "read and
   note issues `SPIKE-1` to `SPIKE-99`", deliberately narrower than the
   ceiling's `SPIKE-1` to `SPIKE-9999`, so the task path ("adds: SPIKE-901")
   and the one-click measurement stay live on the bench. `standing_read`
   leaves the ceiling; the Week 13 harness gains a row for jobs completed with
   zero interactions; the launcher gains `--reuse ROOT` and the clear
   ceiling-mismatch message.
5. **Tests (unit and API).** Widening impossible from agent, confirm body,
   activation body, launcher flag, environment variable; narrowing invalidates
   conflicting approvals and proposals; widening dismisses proposals; a task
   stores only its "adds" and narrowing mid-task changes nothing; task expiry
   leaves only the standing set; quarantined authority blocks standing writes;
   decision order incl. "unauthorised target never earns a confirm"; cap key
   and reset; fingerprint moves with every field; ceiling shape rejects a
   grant outside it.

**Tier 2 (ships if Day 2's fix list allows): the screens.**

6. **Settings.** A real "Standing permissions" section: current grants,
   version and since-when, add or remove a grant, confirm with the diff shown.
   The static "Always ask" rows that control nothing are removed; the
   notification toggle stays. Nothing on Settings may display a control that
   does nothing.
7. **Task activation names the step outside.** The proposal card and the
   manual form show "adds: SPIKE-901" as the difference between the request
   and the standing set. A proposal entirely inside the standing set is
   answered to the agent with "no task needed; this is already allowed" and
   never becomes a card. Exact guidance strings are written down in the
   handover, as Week 14 did.
8. **Playwright:** one spec, the Settings flow end to end (propose, see the
   diff, confirm, see the new version). The card and "no task needed" paths
   are covered by API tests in Tier 1.

Independent Bugbot and Security reviews before the week is called done, as in
Week 14.

## Measurement

Preregistered before the build. Honest note on the baseline: the ten-run Week
14 baseline was never run. Day 1 morning includes ten fresh-chat fixture jobs
on the current build so the "before" column exists; if that does not happen,
the first row is reported as a design fact (one activation click by
construction), not a measurement.

| Measure | Baseline (Week 14 build) | Target (Week 15) |
| --- | --- | --- |
| Human interactions per routine in-scope fixture job (read a few issues, leave notes) | 1 (activation), to be measured Day 1 | **0** |
| Interactions per job that steps outside the standing set | 1 | 1, and the card names the step |
| Cards raised for actions the facts call dangerous | n/a on the fixture | 1 per action, never 0 (unit-tested with recorded Slack facts if Day 1 clears) |
| Unnecessary prompts (judged by hand from audit) | 0 | 0 |
| Writes outside standing set and task that ran | 0 | 0 |
| Standing-set changes made by anything other than the protected flow | n/a | 0 (tested, incl. flags and env) |
| Threat model v2 findings medium or higher left open at week end | n/a | 0 |
| Hosts with a documented, tested "mandatory" configuration | 1 (Cursor) | 2 if the spike passes, else 1 with the reason recorded |

## Out of scope this week

- Any live Slack tool, the token store, OAuth, and the Connections page (Week
  16, conditional on Day 1).
- Proxy mode for user-configured MCP servers.
- Codex and Hermes beyond a coverage-map entry.
- Path-prefix grants; there is no mediated file tool to grant against.
- Transition drafts and task-change classification.
- ML retraining, calibration, or any ONNX change.
- Agent-proposed standing permissions: the agent proposes tasks only.
- Notifications for standing-set changes; the person is the one making them.
- Any hosted or multi-user concern.

## Deliverable

A reviewed scope decision; a threat model v2 with a coverage map and a ranked
fix list, medium-plus items closed; standing permissions (Tier 1 at minimum)
that make routine in-scope work click-free on the fixture bench while the
decision order still blocks unauthorised targets first; a Claude Code lock
either proven with a documented configuration or honestly labelled advisory;
and a Slack facts record that either clears or re-plans Week 16.

## Definition of done

- You approved the scope decision (with your edits) before Day 1 code.
- Roadmap Week 16 and Product Architecture's weekly list match the decision.
- Day 1 record appended with every kill condition marked hit, clear, or not
  tested, and the Claude Code version recorded.
- `docs/Week 15 Threat Model v2.md` exists with findings, coverage map, and
  fix list; no medium-plus finding open.
- Tier 1 tests green; independent reviews clean or triaged; a Week 14 state DB
  is refused with a clear message rather than silently migrated.
- If Tier 2 shipped: Settings shows no dead controls and the Playwright spec
  passes. If not: the handover says so and Week 16 opens with it.
- Harness shows 0 interactions for a routine in-scope fixture job.
- Week 15 Handover written in the Week 14 style, with a "Not verified" list
  that is honest about what only a live run can show.
