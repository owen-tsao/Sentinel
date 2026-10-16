# Sentinel Product Direction (October 2026)

This document records the direction decision made on October 9, 2026, after
Week 14 shipped and before Week 15 began. It supersedes the Week 15 Plan and
Week 15 Scope Decision drafted on September 11, and it changes several
statements in `docs/Product Architecture.md` and `docs/Roadmap.md`; those
documents point here where they conflict. Research behind the decision is
summarised in the appendix.

## 1. The decision in one paragraph

Sentinel stops being a tool where the person writes a task boundary and the
agent works inside it. It becomes an independent supervisor that sits beside
the agents a person already runs (Cursor, Claude Code, Codex), infers the
boundary from what the person asked, tells the agent that boundary, watches
every action, and speaks up only when an action is **unsafe**, the agent is
**stuck**, or the agent has gone **off-track**. It can actually stop the
dangerous actions because it holds the host's hook, and it keeps a
tamper-evident audit written before each action runs. The web app becomes
the monitor and flight recorder, not a form to fill in before work.

The coding floor (Weeks 15-18) is the first adapter and the proving ground,
not the destination. The problem Sentinel is built to solve is the ambiguous
one that no fact decides: did this Slack send, this email archive, this
calendar edit match what the person meant? That layer, reached through an
MCP proxy with inferred purpose and one-tap authority, is §10.

## 2. Why

The contract model (Weeks 10-14) proved the enforcement seam works: a paired
browser, server-owned authority, one-use approvals, a mandatory MCP path, and
a confined executor. It also proved the front door is wrong. Writing operation,
environment, targets, expiry, rollback, dry-run, and forbidden actions for work
whose scope shifts every ten minutes is friction with no safety payoff. The
Week 13 proposal card and the Week 14 budget were both attempts to make a
person approve a boundary they should never have had to author.

Three findings from the October 9 research settled the direction:

1. **One sentence of scope in the prompt is the most effective safety
   intervention measured anywhere.** Paired prompts with and without a
   sentence stating what the agent may touch moved Claude Code's overeager
   rate from 17.1% to 0.0% (OverEager-Gen, 2026). Developers almost never
   write that sentence; they refine scope as they go.
2. **Prompt-inferred scope cannot be authority.** The best deployed intent
   classifier (Claude Code auto mode) publishes 0.4% false positives and 17%
   misses on real traffic, and 70-81% misses on deliberately ambiguous
   prompts. Legitimate scope growth (a helper file, a config read while
   debugging) is indistinguishable from drift at the action level. Inferred
   scope can suggest and route to `warn` or `confirm`; it cannot grant or
   block on its own.
3. **The seam exists only in coding agents.** Cursor, Claude Code, Codex, and
   Gemini CLI all expose a pre-tool hook that sees the prompt, sees every tool
   call before it runs, and can deny it. Nothing comparable exists for closed
   consumer assistants, and OS-level monitors see effects, not decisions.

## 3. The model

Four verbs, in order, every time the person sends a prompt:

1. **Hear.** The hook delivers the person's prompt. Sentinel infers a
   *boundary*: the places the agent may work (this repository, these paths,
   this environment, these channels) and the kind of change. If the prompt is
   ambiguous about something that matters (a destructive verb with no clear
   target, two plausible environments), Sentinel asks one question before the
   agent starts. It never rewrites the person's words.
2. **Tell.** Sentinel attaches the boundary to the prompt as one line of
   context the agent sees ("Boundary: this repository, dev environment. Ask
   before touching anything outside it."). This is the cheapest intervention
   in the research and costs the person nothing.
3. **Watch.** Every tool call, shell command, file edit, and MCP call passes
   through the hook. The floor runs first on hook facts alone; the two
   deterministic detectors run only when the floor did not decide.
4. **Speak only at the edges.** Routine work produces no message. The person
   hears from Sentinel only for the verdicts below, delivered as a desktop
   notification or in the web app, and can approve or deny from there. A
   hook waits a bounded time for an answer (five seconds under the shipped
   Cursor configuration, up to sixty on Claude Code). Where the host can
   render a hook-supplied question, a `confirm` is delivered as the host's
   own permission prompt carrying Sentinel's reason (Claude Code's
   `permissionDecision: "ask"`, Week 16); the person answers in the host and
   Sentinel never holds the approval. Where it cannot, a `confirm` is
   delivered as a deny with an approval reference and retry guidance, exactly
   as the Week 12 MCP path does today; the agent retries unchanged once the
   person has answered. Phone delivery is notification-only until a paired
   relay exists; there is none in Weeks 15-18.

**Boundaries across prompts.** A boundary persists for the session. A later
prompt that carries scope facts supersedes it (states: `inferred →
superseded`); a follow-up with no scope facts ("yes, do it", "fix the test
too") keeps the current one. Supersession invalidates pending approvals and
resets the stuck and off-track counters. The boundary is not an
`ActionContract`: it has no activation, no human author, and grants nothing.
For hook hosts the contract lifecycle of Weeks 10-14 is retired; the fixture
MCP path keeps it as a regression bench.

**What Sentinel stores.** The boundary, the prompt's hash, the canonical
action, the verdict, and the reason. Not the prompt text, which keeps the
Week 11 invariant that unnecessary prompt content is never persisted. Opt-in
text retention for debugging, with a stated TTL, is a later decision.

> **Amendment (Week 17, October 12).** In Week 17 the clarifying question is
> delivered as agent context, not as a direct message to the person: the
> prompt is never held back, the agent is told the named location is outside
> the boundary and to ask before touching it, and the person hears the
> question only if the agent asks. A person's in-chat answer does not widen
> the boundary; Sentinel has no authenticated channel for it yet, and the
> agent acting on such an answer is governed by the floor alone. Rows are
> tagged `caution` so the gap is measurable. Direct delivery and an
> authenticated widening answer arrive with the monitor. Reason: the first
> design blocked the prompt and accepted `include <path>` from the next
> prompt, which review showed was forgeable from Bash and dead in `-p` mode
> (`docs/Week 17 Plan.md` §10).

### 3.1 Authority: a mandatory floor and an observed middle

The contract model gated everything. A pure monitor gates nothing. Sentinel
does neither:

- **Mandatory floor (deterministic, uses only facts the hook delivers).** A
  short list of dangerous-by-facts actions is blocked or confirmed through
  the hook regardless of what the prompt said. The facts are the canonical
  action, the working directory, the home directory, system paths, the
  repository root, and the environment the process was launched in; the
  inferred boundary is **not** an input to the floor. The list: destructive
  operations whose target is outside the working directory (or is the home,
  root, or a system path), credential reads, outbound transfer of secrets,
  force-push to protected branches, production database or infrastructure
  deletion, disabling security tooling, writes to any hook or Sentinel
  configuration file (`.cursor/hooks.json`, `.claude/settings*.json`,
  `managed-settings.json`, `requirements.toml`, the Sentinel state
  directory), and external sends to broad or unknown audiences. Each of the
  real incidents found in the research (Replit's production wipe,
  Antigravity's `rmdir d:\`, three Claude Code home-directory wipes, Cursor
  YOLO deleting a machine) is a destructive operation whose target escaped
  the working directory, so the first item is designed to catch them; whether
  it does is Week 15's second gate, not a claim made here.
- **Observed middle (inference allowed, authority not).** Everything else
  runs. The inferred boundary is an advisory signal with no authenticated
  provenance: it may raise `warn` or `confirm` through the rules in §3.2,
  never `allow` or `block`. The stuck detector raises `warn` only. There is no
  judge model in Weeks 15-18; the detectors are deterministic. A model may be
  reconsidered after the evaluation set exists, under the existing promotion
  rules (calibrated, blind-tested, never able to downgrade a floor decision,
  never sending prompt content off the machine).

Decision order per action, fixed: **floor block → floor confirm → stuck
(warn) → off-track (warn or confirm) → allow.** The floor runs on hook facts
alone; the detectors run only after the floor did not decide.

> **Amendment (Week 18, October 14): four floor rules the corpus showed are
> denying ordinary work.** The gates tested the dangerous cases and passed.
> The person's corpus (62,320 tool calls) and the published evidence show
> that on Cursor, where a file-tool `confirm` is delivered as a deny, the
> benign-but-outside cases dominate and some rules deny them wholesale.
> Reproduced in-process against the real payload shapes:
>
> 1. **`.cursor/` is split.** `~/.cursor/hooks.json`, `~/.cursor/hooks/`,
>    `~/.cursor/mcp.json`, and `~/.cursor/rules/` stay `block`
>    (`F1.write_protected_config` / `F1.write_home`): they are the agent's own
>    guardrails. `~/.cursor/plans/`, `~/.cursor/projects/`, and
>    `~/.cursor/canvases/` are Cursor's artefact stores for the agent's own
>    output (156 plan writes in the corpus; a canvas write was blocked live on
>    October 14) and are zone `home`, not a carve-out, so they `allow`.
>    Same treatment for `.claude/` once its artefact folders are enumerated.
> 2. **Credential taint decays and is only set by reads that happened.** A
>    *blocked* credential read (`F3.credential_read` → deny) leaks nothing and
>    sets no history fact. An *allowed* read of a credential path sets the
>    fact for 30 minutes, not the session. Reason: one blocked gate test muted
>    `WebSearch`/`WebFetch` for seven hours in a working chat, and the rule's
>    own text ("ask the user") had no channel through which the answer could
>    arrive. `F4.web_egress_after_credential_read` otherwise unchanged.
> 3. **`ApplyPatch` is parsed, not opaque.** Its input is a raw patch string
>    with `*** Update File:` / `*** Add File:` / `*** Delete File:` headers;
>    each path is judged exactly as `Write` / `Delete` would be. Until it is
>    parsed it is `confirm_required F5.opaque_write`, which on Cursor denies
>    every edit for a model that patches (1,759 calls, 11 chats, 676 in one).
>    A patch whose headers cannot be parsed stays `F5.opaque_write`.
> 4. **The undeclared sibling-repository write stays a `confirm`.** The corpus
>    showed many writes under home outside the workspace, and a `warn` zone for
>    sibling repositories was proposed. Published evidence says deliberate
>    multi-repository work launches from a parent folder (covered by the
>    default) and that the vendor's own tiering sends out-of-project writes to
>    review. Decision: no rule change until the corpus split (sibling repo vs
>    `~/.cursor` vs scratch) is measured; the confirm is made tolerable by the
>    asynchronous approval below rather than removed. Kill condition for the
>    `warn` proposal: if most sibling writes come from chats launched in a
>    parent folder, it is dropped.

**Inference may only narrow.** The default boundary is the working
directory, the repository that contains it, and the environment the process
was launched in. A prompt may narrow that (one subdirectory) silently. Any
widening (a second repository, the home directory, a staging or production
environment, an external channel) requires the one clarifying question in
"Hear", answered by the person, never silently accepted from prompt text.
This is what stops pasted issue text or file contents from steering the
boundary.

> **Amendment (Week 18, October 14): the boundary is the launch directory;
> a named folder is a focus hint, not a narrower boundary.** The authority
> rule above stands unchanged: nothing a prompt says can move the boundary
> past the launch directory, its repository, or its environment. What changes
> is silent narrowing. Week 17 made a prompt that named a subdirectory narrow
> the boundary to it for the rest of the session, and widening back needed a
> question that was never built. Two live gates and the person's own corpus
> (`spikes/week18/prompt_corpus/`, 144 chats, 5,782 prompts) showed this is
> wrong in practice, not just unbuilt: a Cursor chat is a workstream (median
> 8.5 prompts over 21 hours, p90 105 prompts), 79% of prompts name no path,
> and of the 1,052 later prompts that did name one after a narrowing, 1,052
> pointed outside the narrowed folder. 98% of the agent's writes in those chats
> landed outside the first-named folder. A sticky narrowed boundary predicts
> the next prompt 2% of the time and tells the agent to ask before touching
> the file it was just asked to edit.
>
> New rule: the boundary **is** the launch directory (plus repository and
> environment) for the life of the session, and it is what the off-track
> detector and the record use. A folder named in a prompt is attached to the
> context line as a **focus hint** for that prompt only ("this prompt points
> at `src/sentinel/boundary`") and is recorded on the `boundary` row; it
> resets nothing and persists to no later prompt. Cautions for paths outside
> the launch directory are unchanged. The "widening question" is therefore
> moot inside the launch directory and remains required past it. Published
> evidence (`spikes/week18/prompt_corpus/OUTSIDE_EVIDENCE.md` §3) agrees that
> one agent, one directory, one task is the modal pattern and that deliberate
> multi-repository work launches from a parent folder, which the default
> already covers. The corpus is a power-user sample; the mechanism cost of
> this change is near zero either way, since it removes code.

### 3.2 The detectors

| Detector | Signal | Verdict | Evidence it works |
| --- | --- | --- | --- |
| Floor (unsafe) | The list in §3.1, computed from hook facts | `block` or `confirm` | Deterministic rules reach ~0% miss on closed lists (Progent, AgentSpec, AGrail) |
| Stuck | Same action → same result 4×; same action → error 3×; A/B alternation over 6 steps. Action identity is tool name plus canonical arguments, so legitimate retries with changed arguments do not count | `warn`: tag only; one message when the pattern persists past the threshold a second time | OpenHands `StuckDetector` thresholds; loops in 25-29% of weak-model runs, under 4% for frontier models |
| Off-track | A target touched outside the inferred boundary | First touch: `warn`, tag only. Third distinct out-of-boundary target under one boundary: one message. Any out-of-boundary **write or send** that the floor did not already decide: `confirm`. Reads outside the boundary never confirm | Best production system: 0.4% false positive / 17% miss on routine traffic; sold as "surfaces most scope violations", never as near-complete recall |

Cost-based stuck signals (spend with no progress) need data the hooks do not
deliver and are out of scope for Weeks 15-18.

False positives compound across a session: at 2% per action, a 50-action
session has a 64% chance of at least one flag. The message budget is a rate
per boundary: at most two person-facing advisory messages (cautions and
detector messages together) in any rolling 30-minute window under one
boundary; once two have been sent, detectors tag the record and stay silent
until the window moves on. The floor has no budget; it speaks every time.
(Amended Week 18: the budget was "two per boundary, refilled only when the
boundary narrows". On Cursor the boundary is the workspace root for the whole
conversation, so a six-hour session went permanently silent after two
cautions and withheld a real stuck popup at gate C-H5. Attention is a rate,
not a lifetime count; the window is a guess and moves if C-H6 ever shows a
second popup on a benign 20-minute task.)

### 3.3 Hosts and the "buddy deployed with the agent"

The buddy is a thin adapter per host, not one binary. Each adapter translates
the host's hook events into one Sentinel decision API and translates the
verdict back. First version, in order:

1. **Claude Code**: richest contract (`PreToolUse` allow/deny/ask with
   `updatedInput`, `UserPromptSubmit` with context injection, `Stop` with
   transcript path, `ConfigChange` to block hook tampering) and a root-owned
   `managed-settings.json` tier the agent cannot edit. Mandatory under
   managed settings; advisory without them. This is where the boundary is
   proven first.
2. **Cursor**: Sentinel's home host; same-shaped hooks (`preToolUse`,
   `beforeShellExecution`, `beforeMCPExecution`, `afterAgentThought`), the
   existing mandatory MCP fixture path, and the existing sandbox. Project
   hooks live in `.cursor/hooks.json`, which the agent can edit, so Cursor's
   hook path is **advisory** unless enterprise or MDM hooks are installed;
   only the MCP fixture path is mandatory today. Built in Week 18 as a
   translation layer over the Claude Code service (`docs/Week 18 Plan.md`),
   after Spike C1 verified that `additional_context` reaches the agent on
   prompt submit and tool events. Host amendments: Cursor shows no
   person-facing text on an allowed action, so the one budgeted stuck
   message is delivered as Cursor's own `ask` popup (`confirm` tier, which a
   detector may raise), never as a downgrade of a floor verdict; and Cursor
   enforces `ask` only on `beforeShellExecution` and `beforeMCPExecution`,
   not `preToolUse` (Spike C2, October 13), so confirms for shell and MCP are
   delivered there and confirms for file tools (`Write`, `StrReplace`,
   `Delete`, `ApplyPatch`) are delivered as a deny that tells the agent to
   ask the person in chat. A confirm the person never sees is an allow.
3. **Codex**: parity hooks and the strongest lock (`requirements.toml`);
   its app-server protocol would let Sentinel act as the approval client in
   headless runs. Not in Weeks 15-18; listed so the adapter shape is designed
   for three hosts, not one.

Coverage is stated per host and per surface, exactly as today: *mandatory*
where the hook can deny and the config is locked, *advisory* where it can only
observe or where the agent can edit the hook, *unsupported* where there is no
hook (Aider, Devin, closed consumer assistants). The audit records the hook
configuration's hash at session start so a later edit is visible. Cloud and
background agents run only repo-committed hooks and are observed, not
enforced, until a spike proves otherwise. "Nudge" means `PostToolUse`
additional context on Claude Code and is unsupported elsewhere.

### 3.4 What the web app is now

A monitor and flight recorder: active agents and their boundaries, every
decision with its reason, the stuck and off-track signals over time, and the
audit record. It is where a person goes *afterward* or when a message sends
them there. It is not a form before work. The manual contract form, the
proposal card, and budget controls leave the primary flow; the audit,
approvals, and settings pages survive. Whether the removed code is deleted or
kept as the fixture regression bench is decided in Week 15 and costs a day
either way.

The audit is promoted from feature to hero and made **tamper-evident**: every
hook-path verdict is written durably before the action runs (the hook fails
closed if the write fails), and rows are hash-chained so deletion or edit of
any row is detectable. Honest limit: Sentinel runs as the same operating-system
user as the agent, so an agent with shell access can delete the database file.
The chain proves tampering happened; it does not prevent it. Root-owned state
or off-host mirroring is a later hardening step and is listed as an open gap.
In three of the 2026 incidents the agent deleted its own transcript and no
cause could be established; a detectable gap in Sentinel's chain is still
evidence.

> **Amendment (Week 18, October 14): the product is floor + asynchronous
> approval + after-action report. The web app is not a live monitor.** Both
> the person's corpus and the published measurements say the person is not
> watching: median Cursor chat 21 hours of wall time for 8.5 prompts; 93% of
> Claude Code permission prompts approved; auto-approve rising to over 40% of
> sessions with tenure; the vendor's own conclusion that approving every
> action "will create friction without necessarily producing safety
> benefits". A dashboard assumes an audience. What unattended use needs is:
>
> - **A floor that holds with nobody there.** Built and gated. Blocks offer no
>   Allow button: a block with a click is an ask with extra steps, and three
>   documented incidents (Replit, Gemini CLI, the DataTalks Terraform destroy)
>   are the person clicking approve on the fatal step.
> - **Confirm becomes asynchronous.** A `confirm` the host cannot show, or
>   that nobody is present to answer, is delivered as a deny **that creates a
>   one-use pending approval** bound to the exact action, rule, working
>   directory, and session, and the deny text carries its review link. The
>   agent is told to finish what does not depend on it and hand off clearly.
>   The person approves from the link (laptop, or phone through the paired
>   tab), re-prompts, and the floor sees the matching approval. Sentinel does
>   not resume the agent; whether a host SDK can is a later spike. On Cursor
>   file tools this is the *only* form a confirm can take, so it is not
>   optional there.
> - **Everything denied is visible in three places from one record:** the
>   deny text in the chat (immediate, with the link), the approvals page
>   (actionable), and an **after-action summary** when the person returns
>   ("while you were away: 47 files written, 3 outside the repo, 1 blocked,
>   1 stuck loop stopped"), pushed as a notification where one is paired.
>   Same `DecisionRecord` behind all three.
>
> The live path tree considered on October 14 (every path touched, by zone,
> with its verdict) survives as the *content* of the summary and the
> approvals page, not as a page someone is expected to keep open. The
> message budget keeps its bar, now with a number from the field: Cursor's own
> cards plus a 5–9% human interrupt rate is what Sentinel must stay under.
> Headless and cloud agents are the fastest-growing surface and the least
> measured; they stay out of scope and are named as the largest gap.

## 4. What survives, what is removed, what is added

| Layer | Fate |
| --- | --- |
| Four verdicts, one-use approvals, Docker executor, SQLite audit store, notifications, pairing, protected routes | **Kept** |
| MCP mediator and gateway | **Kept for the fixture path only.** They are wired to two fixture tools and the fixture lifecycle; the hook decision path is new code that shares the verdict model and audit store, not the mediator |
| Shell canonicalizer (`actions/shell.py`) | **Extended or replaced.** Today it knows 14 commands, rejects compound shells, pipes, and globs, and errors on anything else. A Bash hook delivers every command. The floor needs a target-extraction pass that handles `cd x && …`, `git clean`, `find -delete`, interpreters, and globs *without* failing closed on benign compound commands. This is the single hardest engineering item and has its own gate |
| Dangerous-by-facts rules (Weeks 3, 7) | **Promoted** to the floor; list extended with the incident-derived and hook-tamper entries |
| Ceiling (`SupervisionPolicy`) | **Versioned to v2**: gains the floor list, detector thresholds, message budget, and environments beyond `sandbox`. The content hash changes, so a v2 process refuses a v1 state database with a clear message; this migration costs a day and is scheduled |
| Contract (`ActionContract`) and its lifecycle | **Retired for hook hosts**, replaced by the `Boundary` record above (no activation, no author, grants nothing). Kept unchanged for the fixture path |
| Week 13 proposal flow | **Not reused.** It is the agent declaring its own scope from a tool call; prompt-to-boundary inference is new code |
| Manual contract form, proposal card, write budget UI | **Removed from the primary flow**; delete-or-bench decided in Week 15 |
| Week 15 standing permissions, Slack provider build, scope matrix as user input | **Dropped as builds**; the analysis of what makes an action dangerous becomes floor rules |
| Claude Code hook adapter | **Added**, Weeks 15-16 |
| Boundary inference and injection; stuck detector | **Added**, Week 17, each behind its own spike |
| Cursor hook adapter | **Added**, Week 18 (October 13), as a translation layer over the Claude Code service; `enforcement: advisory` because the user-level hooks file is agent-writable |
| Off-track detector, hash-chained audit, web monitor view, Codex adapter | **Deferred past Week 19**; listed in the roadmap as the next phase |
| Incident-derived evaluation set | **Added** in Week 15; the project's proof |

## 5. Assumptions, verified and not

| Assumption | Status | How it is checked | Kill condition |
| --- | --- | --- | --- |
| Claude Code `PreToolUse` can deny a floor action under `managed-settings.json`, and `UserPromptSubmit` can inject the boundary line | Unverified (documented, not run) | Week 15 gate 1: a spike on the user's machine, recording the Claude Code version | If deny or injection fails, Claude Code drops to advisory and the hook work pauses until a host passes |
| The floor's target-extraction can be computed for compound shell, globs, interpreters, and `cd` prefixes without failing closed on benign compound commands | Unverified; today's canonicalizer cannot | Week 15 gate 2a: run extraction over real `Bash` arguments captured from the user's own sessions (at least 200 commands); count uncanonicalizable commands | If more than 1 in 20 benign commands cannot be classified, the floor cannot ship on Bash and the direction is revisited before any adapter is built |
| The floor rules catch the real 2026 incidents and held-out dangerous cases without flagging benign look-alikes | Unverified | Week 15 gate 2b: an evaluation set of the incidents, held-out dangerous commands from BashArena and Terminal-Bench the rules were not written against, and at least 100 benign twins (`rm -rf node_modules`, an intentional migration, `git clean -fdx` inside the repo) | Below 100% recall on the incidents, below 90% on held-out dangerous cases, or more than 1 in 20 benign twins flagged: the list is fixed before anything else is built |
| Claude Code's transcript exposes the host's own permission prompts, so "Sentinel messages vs host prompts" is computable | Unverified | Checked inside gate 1 | If not, the comparison is dropped and only Sentinel's own message rate is reported |
| One injected boundary line measurably reduces out-of-scope actions | Verified in the literature; for Sentinel's phrasing, live anecdotes only (Gate 1: 2 of 3; Week 17 H3: the agent honoured a negation and disclosed the line's hook origin) | Week 19 evaluation pack: paired runs on 20 benign tasks with the pre-registered pass line from `docs/Week 17 Plan.md` | If the effect is not visible, the line is tuned; nothing else depends on it |
| OpenHands stuck thresholds transfer to Claude Code traces without flooding on legitimate retries | **Verified** (October 12): 3.7% of 164 real sessions trip the repeat signal under an upper bound that assumes identical results; live loop nudged at the 3rd failure and messaged once | Week 19 (carried from Week 17 H6): a twenty-minute benign task with zero advisory messages, now on Cursor | If more than 1 in 10 benign sessions trip it, thresholds rise before any message is shown |
| Off-track detection reaches roughly 85-90% recall at 2-5% per-action false flags | Plausible with caveats (published numbers) | Deferred past Week 19 with the detector | If below, the detector stays `warn`-only and the claim is "surfaces", never "prevents" |
| Cursor hooks can deny a tool call and inject `additional_context`; a stopped Sentinel fails closed on gating events | Deny and injection **verified** (Spike C1, October 13, Cursor 3.24.12); fail-closed **verified live** (gate C-H0b, October 13) | Week 18 live gates C-H0 to C-H6 | A stopped Sentinel letting a Cursor action through, or a verdict differing from the Claude Code path, kills the adapter |
| Cursor can put Sentinel's confirm in front of the person | **Falsified for `preToolUse`, verified for `beforeShellExecution`/`beforeMCPExecution`** (gate C-H3 and Spike C2, October 13): a Delete under `ask` ran with no popup; the shell event's `ask` shows the popup in all three Run Modes | Rerun of C-H3 and C-H5 after the fix; Week 19 counts `ask_undelivered` rows | If the capable event fails to fire for a judged shell call in real work, shell confirms also become deny-with-guidance |
| Cursor cloud agents execute repo-committed `.cursor/hooks.json`; Codex headless `ask` degrades to deny | Unverified | Ten-minute checks when those hosts are scheduled | Cloud and headless stay "observed, not enforced" |

Per the project rules, no implementation starts on an item while its
load-bearing assumption is unverified. Week 15 therefore contains gates only.

## 6. Measurement

Published alongside the code, computed on the evaluation set and on the
user's own sessions:

- **Dangerous recall** on the incident set (target 100% on the floor list)
  and on held-out dangerous cases the rules were not written against (target
  90%). The second number is the honest one; the first is a regression check.
- **False-flag rate** per benign trajectory (target under 1 in 10 sessions
  producing any message; under 1 in 20 for the floor alone) on at least 100
  benign twins and the user's own sessions.
- **Messages per hour of agent work** from Sentinel, and, on Claude Code only
  if gate 1 shows the transcript exposes them, the host's own permission
  prompts for the same sessions. If Sentinel is louder than the host, it has
  failed its own premise.
- **Decision latency** p50/p95 at the hook. The shipped Cursor hook
  configuration gives five seconds and fails closed; Claude Code defaults to
  sixty. Rules must answer in well under one second.
- **Audit integrity**: every hook-path verdict written before the action and
  the chain verifiable afterward; a deliberate deletion in a test is detected.

Anthropic's published auto-mode numbers (0.4% false positive, 17% miss) are
reported as reference context, not as a like-for-like comparison: auto mode
classifies intent per action, while Sentinel's floor is a closed rule list.

## 7. Non-goals

- A general prompt-writing or prompt-restructuring assistant. Sentinel touches
  the boundary line only; it never fixes spelling, reformats, or rewrites.
- Orchestrating agents (launching, sequencing, scheduling). Sentinel
  supervises agents the person started.
- A phone or menu-bar app as a product. Verdicts go through existing relays
  (desktop notifications, ntfy-style push, host remote-control apps).
- Monitoring closed consumer assistants (Grok, Meta AI, chat-app bots) that
  expose neither hooks nor MCP. No interception point, no claim. Agents that
  reach Gmail, Slack, or calendars *through MCP* are in scope for §10.
- Enterprise multi-tenant control, SIEM integration, or sales-led security
  platform features.
- Claims of security against an adversarial agent that crafts retries using
  Sentinel's own guidance. The threat model is an honest but overeager agent.
- Kernel-level or eBPF containment. The Docker executor remains the bounded
  execution story.
- A model-based judge in Weeks 15-18. Detectors are deterministic until an
  evaluation set exists to calibrate against.

## 8. Risks stated plainly

- **Platform absorption.** Anthropic or Cursor can ship loop detection or
  cross-session alerts any quarter. Sentinel's position is independence from
  the vendor and coverage across hosts, which no single vendor will offer.
- **Hook unevenness.** Fail-open defaults, headless `ask` degrading to deny,
  cloud agents ignoring user hooks. Every coverage claim is per host, per
  surface, and tested.
- **Trust spend.** Every interruption costs attention. The detectors must
  produce fewer messages than the host's own prompts or people turn Sentinel
  off; this is measured, not assumed.
- **Weaker headline guarantee.** The contract model could say "no write
  without a task." Sentinel now says "no floor action without a human, and
  most drift surfaced." The floor keeps the hard claim where incidents
  actually happen; the softer claim is stated as such.
- **Name collision.** `sentinelrca/sentinel` and SentinelOne exist in adjacent
  spaces. A rename is not in scope for Week 15 but is noted.

## 9. How the roadmap changes

Weeks 15-18 are replanned in `docs/Roadmap.md`, one gate or one deliverable
per week, so that the project's own rule (no implementation on an unverified
load-bearing assumption) is obeyed:

- **Week 15: gates only.** Gate 1: Claude Code hook deny and boundary
  injection under managed settings. Gate 2a: target extraction over real Bash
  commands. Gate 2b: the floor against the incident set, held-out dangerous
  cases, and benign twins. Plus the decision on deleting or benching the
  removed UI, and the ceiling v2 migration design. No adapter code.
- **Week 16: Claude Code adapter with the floor.** One host, one detector
  (the floor), the Boundary record with its default (cwd, repo, environment),
  ceiling v2, durable pre-action audit writes, and the measurement harness
  producing the §6 numbers. Nothing infers anything yet.
- **Week 17: hear and tell, and stuck.** Boundary inference (narrow-only),
  the clarifying question, injection through `UserPromptSubmit`, and the
  stuck detector in `warn`, each gated by the spikes in §5.
- **Week 18: Sentinel on Cursor.** The same floor, boundary line, and stuck
  detector through Cursor's hooks, via a translation layer over the Claude
  Code service; built October 13, live gates pending. Inserted because the
  person who must live with Sentinel for a week lives in Cursor.
- **Week 19: validation and release decision**, unchanged in shape, with the
  evaluation numbers as the artifact.
- **Next phase (after Week 19):** off-track detector, hash-chained audit,
  web monitor view, Codex adapter, in that order, as the on-ramp to §10.

## 10. The destination: the ambiguous layer (decided October 9, 2026)

The coding floor is the first adapter, not the product. The problem Sentinel
exists to solve is the one the floor cannot touch:

> Given one sentence from a person, decide whether a specific tool call
> matches what they meant, with few enough wrong answers that the person does
> not turn the supervisor off.

The failures here are plausible, not catastrophic: a reply sent to the wrong
Slack thread, the wrong emails archived, a message to forty people that was
meant for one. No "outside the working directory" fact decides them. Intent
is the only evidence, and the best production system found in the research
runs at 0.4% false positives and 17% misses on routine traffic, which at
fifty actions a session still interrupts one session in five wrongly.
Nobody has solved this; the market has shipped around it.

**What the market did instead (October 2026).** Clawvisor ("approve a task
once; every request must match that purpose"), comail (per-agent Gmail
slices by label), and AWP (time-limited Gmail permits) all sit between the
agent and the service as an MCP proxy and require the person to configure
the scope. Runtime and Salus sell infra-level allow/deny to teams and agent
builders. The lesson is twofold: the task-scoped check that Sentinel's
contract model attempted is what the market converged on; and the friction
problem was the forms, not the idea.

**Sentinel's position.** Infer the purpose instead of asking for it; show it
as one line; one tap gives it authority. Host-agnostic, local-first, and
backed by an evaluation discipline that the configuration-first products do
not need and therefore do not have.

**Mechanism.**

- *Plug:* an MCP proxy for the services the agent reaches (Gmail, Slack,
  calendar, GitHub, browser-over-MCP). The agent routes through Sentinel, so
  there is no hook to tamper with and every call carries structured
  arguments (recipient, audience, thread, label) instead of a shell string.
  Hooks remain the plug for raw shell on coding hosts.
- *Authority:* the inferred purpose is advisory until the person taps it,
  exactly as in §3.1. After the tap it may `confirm`; it still never
  silently `allow`s a floor action. The one-tap purpose is the smallest form
  that can grant authority: one field, pre-filled, one gesture.
- *Decision record:* must hold a service call (tool, audience size,
  recipients, thread, purpose matched or not) in the same shape as a shell
  decision (command, target, zone). Designed in Week 16 so the recorder and
  the web app do not need a second schema later.
- *Gate before building:* an intent-match evaluation set with labelled
  (purpose, call, verdict) triples, including benign twins ("reply to Sarah"
  where Sarah is in a 40-person thread). Kill condition to be set from the
  false-positive budget in §3.2, not from recall. Gate 2b in Week 15 is the
  first rep of this muscle on the easier problem.

**Who pays, stated honestly.** The teams market (Runtime, Salus) pays today;
the consumer agent-safety products look indie. This does not change the
portfolio value of the problem; it informs the eventual pitch, which is to
people and small teams who already let agents into their inbox and chat.

## Appendix: research summary (October 9, 2026)

Three parallel research passes informed this decision. Full reports are in the
October 9 session transcript; the load-bearing findings:

- **Market.** Approve-from-phone and menu-bar presence are shipped free by
  every vendor (Cursor iOS, Claude Code Remote Control, Codex mobile) and by
  open-source relays (Happier, MIT, 13 agents). Enterprise vendors (Zenity,
  Noma, HiddenLayer) sell cross-host coding-agent enforcement to CISOs.
  Independent, cross-host, enforceable supervision with stuck detection and
  a tamper-evident audit is not offered to individual developers by anyone
  found; the closest attempts are demos, pre-customer, or post-hoc.
- **Feasibility.** Claude Code, Cursor, Codex, and Gemini CLI expose
  blocking pre-tool hooks that see the prompt and run headless. There is no
  host-agnostic interception point for intent; OS-level tools see effects.
  Tamper resistance exists only where a managed settings tier exists.
- **Evidence.** Dangerous-by-facts rules and loop detection are
  well-supported. Boundary inference is plausible as a suggestion. Drift
  detection cannot reach near-complete recall at low false-flag rates;
  realistic is ~85-90% recall at 2-5% per-action false flags with a confirm
  tier. Public trace datasets (Terminal-Bench trajectories, SWE-agent
  trajectories, BashArena, UnderSpecBench) can serve as benign negatives and
  labelled dangerous cases for the evaluation set.
