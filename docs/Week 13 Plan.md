# Week 13 Plan: Automatic Task Preparation

Status: proposed on September 9, 2026, starting from
[Week 12 Handover](./Week%2012%20Handover.md). Implementation requires explicit
approval, and this plan approves no new dependency.

Week 13 is a friction milestone, not an enforcement milestone. Week 12 proved
that one tool family cannot act around Sentinel. Week 13 makes that path
pleasant to use without weakening it: the agent proposes the task, the human
confirms it in one protected click, and ordinary in-scope work then proceeds
without further review.

## The problem in one paragraph

Today, before the agent can touch `SPIKE-1`, a human must open the control
center, describe the task, build settings, confirm five fields, save, and
activate. That is a good security proof and a bad daily workflow; the Week 12
live run showed it with two wrong-setting dead ends. The contract must keep
existing (it is what the mediator checks every call against), but it should
usually be prepared *for* the human, not *by* the human.

## Goal

Ship one supported flow where:

```text
agent proposes a task for the fixture family (structured, ceiling-checked)
  -> Sentinel stores a non-authorizing draft
  -> browser shows one compact card with exactly the five authority facts
  -> one protected click activates it
  -> at least three matching reads pass with no further review
  -> a note write still waits for exact approval (unchanged from Week 12)
```

with no manual field entry for the supported proposal, no change to what a
proposal can grant (the startup ceiling and the browser click remain the only
authority), and measured friction reduction against the Week 12 manual form.

## Fixed decisions

- FastAPI remains the authority. A stored draft grants nothing. Only the
  browser's protected activation creates task authority.
- The agent's proposal is advisory input. It carries no provenance and is
  treated as coming from the agent, not the user. The compact card says so.
- The proposal is structured, not natural language. Sentinel does not guess
  authority-bearing facts from prose this week; the agent must state
  operation, exact issue IDs, and duration explicitly, or the proposal is
  rejected with guidance.
- Everything a proposal can request is bounded by the immutable Week 12
  startup ceiling: allowed operations, issue-ID scope, and a maximum duration.
  A proposal can only ask for something narrower than the ceiling.
- Raw text from the agent is never persisted. Drafts hold the structured
  facts and a content hash; the Week 11 draft-only rule still applies.
- One pending proposal per supervision session. A newer proposal supersedes
  the older one, which is recorded and can no longer be confirmed.
- The Week 11 manual form stays as the advanced fallback and is reachable from
  the compact card ("Adjust in full form").
- ML stays off. No new dependency. Contracts stay per workspace (Week 16).
- The Week 12 UI direction holds: Overview shows the task and what needs
  attention; the compact confirmation *is* an attention item.

## Riskiest assumption

> The agent can hand Sentinel a complete, correct fixture-task proposal
> through a channel Sentinel already controls, early enough that the human
> confirms it before the agent's first real tool call, and the compact card
> can show exactly what will be granted without hiding anything.

Two sub-questions decide the design and must be answered in Phase 0:

1. **Channel.** Two candidates exist and both are advisory:
   - *MCP tool* `sentinel_task_propose(operation, issue_ids, minutes)` offered
     by the existing shim and mediated by the existing gateway. Structured by
     construction, no parsing, authenticated the same way as the fixture
     tools, and already covered by the Week 12 hooks. Unverified: whether
     Cursor's agent will call it unprompted when a fixture read fails with
     "no active task", or only when the user asks.
   - *Cursor `beforeSubmitPrompt` hook* posting the prompt text to Sentinel.
     Catches intent earlier but depends on a hook payload Week 10 found to
     carry no provenance, requires parsing prose or a strict grammar, and
     adds a second intake path to secure. Unverified: whether the hook can
     reach the local API from inside the sandbox in time.

   Recommendation going in: the MCP tool, because it reuses every Week 12
   control (bearer, ceiling, canonicalization, audit) and needs no parser.
   The hook path is adopted only if the spike shows the agent will not
   propose on its own.

2. **Compact card fidelity.** The card must render the five authority facts
   (operation, exact targets, environment, allowed changes, expiry) from the
   server-stored draft, not from anything the browser or agent sends at
   confirmation time, and the activation request must reference the draft by
   ID only. Unverified: whether the existing `/control/contracts/activate`
   path can take a server-side draft as its source without duplicating the
   contract-building logic in `_accepted_fixture_contract`.

Kill condition: if the supported proposal still needs manual field entry, if
a draft can change any explicit fact between proposal and activation, if an
unconfirmed proposal can alter authority, or if the agent will not use either
channel without hand-holding, Week 13 ends with the Week 11 manual flow kept
and this documented as a spike.

## Threat model additions

In scope this week:

- The agent proposes an over-broad task (many issues, long duration, write
  when read would do). Control: the ceiling bounds every field; the card shows
  each target explicitly; the human confirms or adjusts.
- The agent proposes repeatedly to wear the human down. Control: one pending
  proposal per session; supersession is audited; the card shows the proposal
  count; the human can dismiss.
- A stale or superseded draft is activated. Control: activation references the
  draft ID; superseded, expired, dismissed, or already-confirmed drafts return
  409; the draft binds to the supervision session and ceiling hash.
- The card summarizes in a way that hides scope. Control: no summarization of
  targets; each ID is listed; the card carries a "proposed by the agent, not
  verified as your request" line.
- Browser-side tampering with the confirmation request. Control: the request
  carries only the draft ID; the server rebuilds the contract from stored
  facts and re-validates against the ceiling at activation time.

Out of scope: proving the proposal came from the user; multi-agent or
multi-session drafts; natural-language task inference; OS-level notification
or popup surfaces (see "Explicitly deferred").

## Phase 0: Spike (one day, kill decision at end of day)

Build the smallest disposable version of both channels against the Week 12
launcher and record what actually happens.

1. Add a throwaway `sentinel_task_propose` tool to the shim that posts to a
   temporary route which only logs the structured proposal. In a fresh Cursor
   chat with no active task, ask the agent to "read SPIKE-1" and observe:
   does the failed read's guidance lead it to call `sentinel_task_propose`
   without being told to? Repeat three times.
2. Install a throwaway `beforeSubmitPrompt` hook that posts the prompt to the
   same logging route from inside the sandbox. Record whether it fires, what
   the payload contains, and whether the request arrives before the agent's
   first tool call.
3. Read `_accepted_fixture_contract` and the activation route and write down
   the minimal refactor that lets activation take a server-stored draft.

Exit evidence: a short table of the three trials per channel, the chosen
channel with reasons, and the activation refactor sketch. Kill if neither
channel works in at least two of three trials.

## Phase 1: Server-owned proposal store

- `ProposedTask` model: `draft_id`, `supervision_session_id`, `policy_sha256`,
  `source` (`agent_mcp` or `host_hook`), `operation`, `exact_targets`,
  `environment`, `expires_in_minutes`, `content_sha256`, `state`
  (`pending`, `confirmed`, `superseded`, `dismissed`, `expired`),
  `created_at`, `expires_at`.
- Process-local store with a single-pending invariant per session and a
  bounded history of terminal drafts for the Activity view. Proposals expire
  after a short window (default 15 minutes) so stale intent cannot be
  confirmed hours later.
- Validation at proposal time against the immutable ceiling: operation in
  the ceiling's ordinary or confirm-required set, every target in scope,
  duration ≤ ceiling remaining lifetime, environment fixed to the process's
  environment. Rejections return agent-facing guidance naming the field.
- Audit events: `task_proposed`, `task_proposal_superseded`,
  `task_proposal_dismissed`, `task_proposal_confirmed` (with `draft_id`,
  `content_sha256`, and the resulting contract ID).
- Tests: single-pending invariant, supersession, expiry, ceiling rejection,
  no raw text persisted, content hash stable across equivalent proposals.

## Phase 2: Intake channel

Assuming the MCP channel is chosen (adjust if Phase 0 says otherwise):

- Add `sentinel_task_propose` to the shim's tool list and to the mediator's
  canonicalizer with an exact argument set: `operation` (`read`|`write`),
  `issue_ids` (list of strings), `minutes` (integer).
- Route through `McpMediator` so the same bearer, ceiling, and audit apply.
  The response is `confirm_required`-shaped with `draft_id` and guidance:
  "A task proposal is waiting for the user in Sentinel. Do not retry until
  they confirm."
- When a fixture read or write arrives with no active task but a pending
  proposal, the block reason becomes `task:awaiting_confirmation` with the
  same guidance, so the agent stops hammering.
- When no task and no proposal exist, the block guidance tells the agent to
  call `sentinel_task_propose` with explicit fields.
- Tests: proposal through the route, agent guidance strings, ceiling
  rejections through the route, and that a proposal never changes
  `/control/authority/active`.

## Phase 3: Compact protected confirmation

- New `GET /control/proposals/pending` and
  `POST /control/proposals/{draft_id}/confirm` and `/dismiss` on the protected
  router (same session cookie, Host, and Origin checks as every control
  route).
- Confirmation rebuilds the `ActionContract` server-side from the stored
  draft through the same code path the manual form uses, re-validates against
  the ceiling, and activates through the existing authority service. If a
  task is already active, activation suspends it atomically, as "Create
  replacement task" does today.
- Overview: a "Proposed task" card at the top of the attention column
  showing objective, the five authority facts with each target listed,
  duration, "Proposed by the agent 2 minutes ago; Sentinel has not verified
  this is your request", and three actions: **Activate**, **Adjust in full
  form** (prefills the Week 11 form from the draft), **Dismiss**.
- Approvals page: no change. Writes still land there as exact approvals.
- Activity: proposal events render with their outcome.
- Tests (mocked Playwright): card renders all five facts and every target;
  activate → active contract updates and card disappears; dismiss → recorded;
  superseded draft → 409 surfaced honestly; "Adjust in full form" prefills.

## Phase 4: Agent continuity

- After confirmation, at least three matching reads pass with no browser
  interaction. This is already true of the Week 12 mediator; the test proves
  the proposal path produced an equivalent contract.
- A write still produces one pending approval; the approval card is unchanged.
- Agent guidance strings are reviewed for the full loop: no task → propose →
  waiting → confirmed → reads pass → write waits → approved once.
- Live check: one Cursor chat completes the loop with the human clicking
  exactly once for the task and once for the note.

## Phase 5: Measurement

Preregister before running, then report exact denominators:

| Measure | How | Target |
|---|---|---|
| Proposal success | proposals accepted by the store / proposals attempted by the agent in ≥10 fresh chats | ≥ 80% |
| Time to confirm | seconds from `task_proposed` to `task_proposal_confirmed`, human present | median < 15 s |
| Manual edits | confirmations via "Adjust in full form" / all confirmations | < 20% |
| Repeated reviews | browser interactions per completed loop (task + one note) | exactly 2 |
| False interruptions | proposals or approvals the human judged unnecessary | 0 in scripted runs; report count in free use |
| Raw text retained | grep of state DB and audit for agent prose | 0 |
| Authority changed by unconfirmed proposal | test | 0 |

If time-to-confirm or manual-edit targets are missed, keep the manual flow as
default and ship the compact card as opt-in; do not lower the targets after
seeing results.

## Phase 6: Verification

- Focused tests per phase; full Python suite; frontend type check, lint,
  generated types, build; mocked Playwright; real Cursor loop recorded as in
  Week 12 (agent proposes, human confirms once, reads, write, approve, stop,
  inspect state).
- Independent correctness and security reviews of the full change, briefed in
  neutral language (the Week 12 correctness review was blocked once by the
  model provider's classifier over security vocabulary).
- Fix every confirmed blocker and high-severity finding before calling Week 13
  complete. Record findings and disposition in the Week 13 handover.
- Update README, Product Architecture, Roadmap, and the handover to the
  verified result only.

## Explicitly deferred

- **Natural-language task inference.** The agent must state fields; Sentinel
  does not infer them this week.
- **OS-level confirmation surface** (a small native window or notification
  the agent cannot drive). Attractive, but it is a new trust surface and a
  possible new dependency. Revisit after the compact browser card proves the
  loop; the cheap first step would be a macOS notification that deep-links to
  the pending card.
- **Per-agent sessions** (Week 16, order kept by decision on September 9).
- **Persistent guardrails and transition drafts** (Week 14).
- **Any provider tool** (Week 15).
- **Hook-based intake** unless Phase 0 shows the MCP channel is insufficient.

## Definition of done

Week 13 is complete only when:

- Phase 0 recorded both channels and a kill decision was made in the open;
- one supported structured proposal becomes a complete draft with no manual
  field entry;
- the draft grants nothing until one protected browser click, and that click
  references the draft by ID only;
- the ceiling bounds every proposed field and rejections carry guidance;
- superseded, expired, dismissed, and already-confirmed drafts cannot be
  activated;
- at least three matching reads follow confirmation with no further review,
  and a write still requires exact approval;
- no agent prose is persisted;
- measurements are reported with denominators against the preregistered
  targets, and the default flow follows the result honestly;
- full regressions pass and both independent reviews have no unresolved
  blocker or high-severity finding;
- docs describe only what was verified.

## Recommended implementation order

1. Phase 0 spike and kill decision (day 1).
2. Phase 1 store and audit events (day 2).
3. Phase 2 intake through the mediator (day 2–3).
4. Phase 3 compact card and confirm/dismiss routes (day 3–4).
5. Phase 4 continuity and guidance pass (day 4).
6. Phase 5 measurement and Phase 6 verification, reviews, docs (day 5).

## Recommended commits

- "Store agent task proposals without granting authority"
- "Let the agent propose a fixture task through the mediated MCP path"
- "Confirm a proposed task in one protected click"
- "Measure and document automatic task preparation"
