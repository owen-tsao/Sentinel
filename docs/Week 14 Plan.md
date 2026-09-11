# Week 14 Plan: Consent at Activation

Status: proposed on September 11, 2026, starting from
[UI Foundation Handover](./UI%20Foundation%20Handover.md) and
[Week 13 Handover](./Week%2013%20Handover.md). Implementation requires
explicit approval. This plan approves no new dependency.

**This plan reorders the Roadmap and needs a decision.** The Roadmap's Week 14
is "Transition Drafts and Persistent Guardrails". The Week 13 live run ended
with a clear user verdict: the loop works, but per-write approval after a
reviewed contract is overkill, and a browser tab is the wrong place to click
"Approve". That verdict is the first free-use false-interruption report, and
the Roadmap already names the Week 13 friction measures as the yardstick.
Recommendation: spend Week 14 on friction (this plan) and move transition
drafts and versioned guardrails to Week 15, pushing provider mediation to
Week 16 and sessions to Week 17 alongside validation. Alternative: keep the
Roadmap order and accept that the product stays annoying for two more weeks
while more machinery is added on top of the annoying part. The rest of this
document assumes the recommendation.

## The problem in one paragraph

Today a person reviews a contract that says "write notes to SPIKE-1 for 30
minutes", clicks Activate, and is then interrupted again for the first note,
because the startup ceiling puts `issue_add_note` in `confirm_operations`
regardless of what the contract said. The contract review and the write
approval ask the same question twice. Meanwhile, the approval lives in a
browser tab the person had to leave Cursor to find. Cursor's own inline
approve box sets the bar: one small decision, right where you are.

## Goal

Ship one supported change to *when* consent is asked, without changing *what*
can be granted:

```text
human activates a task (contract review, one click)
  -> the activation itself carries a bounded write budget
     ("up to 3 notes on SPIKE-1, 30 minutes")
  -> matching reads run freely (unchanged)
  -> matching in-budget writes run and are audited, no card
  -> the 4th note, any out-of-scope target, or any irreversible/bulk effect
     still stops for exact approval; blocks stay blocks
  -> reads never raise a card even before a task exists
```

Routine work (read a few issues, leave one or two notes) costs one human
click. The Week 13 harness must show it.

## Fixed decisions

- The startup ceiling stays the outer bound and stays immutable at runtime.
  Nothing in this week lets an HTTP request, an agent, or a task widen it.
- A write budget is *consent*, not *authority*: it is granted only by the
  human's protected activation click, is part of the contract's content
  hash, is shown on the ticket and the receipt, and is bounded by the ceiling
  (a new ceiling field says which operations may be budgeted at all and the
  maximum count).
- Budgets count *applied* writes, are decremented under the session lock,
  and never carry across tasks. A replaced or expired task takes its
  remaining budget with it.
- The ceiling's `confirm_operations` keep their meaning: an operation there
  can never be budgeted. Budgetable operations are a separate, explicit set.
  The shipped default ceiling budgets only `issue_add_note`, maximum 5.
- Standing read permission is a *policy* the ceiling declares, not a task the
  browser creates. "No active task" keeps its meaning for writes and for the
  stale-view and supersession rules.
- An OS-level confirmation surface is a spike, not a commitment. It is built
  only if the Phase 0 check shows it can be done with no new dependency and
  cannot be driven by a same-user agent process. Otherwise the browser card
  stays and the finding is written down.
- ML stays off. Contracts stay per workspace. No new dependency.

## Riskiest assumption

> A write budget granted at activation can be enforced so that no write ever
> runs outside both the contract's exact scope and a confirm/block tier, and
> doing so brings routine fixture work to one human interaction per job.

Sub-questions for Phase 0:

1. **Enforcement seam (unverified).** The mediator decides per call using the
   ceiling (`SupervisionPolicy.decide`) and then the contract. Can the budget
   be applied *after* both say "in scope" and *before* execution, as a
   decrement under the same session lock that approvals use, with the
   idempotency key preventing a retried write from spending the budget twice?
   If the check has to live anywhere the agent influences, stop.
2. **Contract binding (unverified).** Can the budget be a field of the
   accepted contract so it is covered by the existing content hash,
   activation stale-view guard, and audit record, with no new route?
3. **Measurement baseline (unverified).** Week 13 left "≥10 fresh chats"
   unmeasured. Ten runs of the *current* flow, counted with
   `scripts/week13_measure.py`, are needed before changing policy or there is
   no before/after.
4. **OS surface feasibility (unverified, spike only).** On macOS with only the
   standard library, can Sentinel show a confirmation the person can act on
   without a browser tab, such that another process running as the same user
   cannot press its button? Known facts going in: `osascript display
   notification` has no action buttons; a Python `tkinter` always-on-top
   window is possible with the standard library but is, like every same-user
   window, scriptable by a same-user process. The realistic outcome is
   "deep-link notification that opens the existing card", which shortens the
   trip but is not a new trust boundary. Decide in half a day, not a week.

Kill condition: if any path lets a write escape both the exact scope and a
confirm/block tier, or a budget can be set or increased by anything but the
protected activation click, budgets are dropped and per-write approval stays.
If the ten-run baseline plus ten post-change runs do not show routine work at
one interaction per job, the friction problem is recorded as unsolved and
Week 15 proceeds without claiming otherwise.

## Threat model additions

- **Agent inflates the budget.** A proposal asks for 50 notes. Control: the
  ceiling caps the count; the card shows the number as its own fact; the
  default proposal budget is the minimum that completes the stated job (one
  note per issue listed), and the human can lower it before activating.
- **Budget spent on the wrong target.** Control: budget applies only after
  the contract's exact-target check passes; out-of-scope writes are blocked
  exactly as today.
- **Retry double-spends or free-rides.** Control: the existing idempotency
  key; a retried already-applied write returns `mcp:already_applied` and
  spends nothing; a retried failed write spends nothing.
- **Budget survives replacement.** Control: budget state lives on the task
  record and dies with it; a replacement task starts at its own count.
- **Standing reads leak scope.** Control: the standing read policy is bounded
  by the ceiling's issue pattern and fixture project, exactly like a task;
  reads outside it are blocked exactly as today; it grants no write.
- **Spoofed OS prompt.** Addressed by the Phase 0 kill rule above: if the
  surface can be driven by a same-user process, it may only *open* the
  browser card, never approve.

## Phases

**Phase 0 (day 1): de-risk and baseline.**
Ten fresh-chat runs of the current flow, measured. Read-through of the
mediator to confirm the enforcement seam and lock. Half-day OS surface spike
with a written verdict. Gate: seam confirmed, baseline table in this document.

**Phase 1 (days 2–3): write budget.**
Ceiling gains `budgetable_operations` and `max_write_budget`; contract gains
`write_budget`; mediator decrements under lock after scope checks pass;
proposals and the manual form carry the field; ticket, proposed-task card,
and receipt show it as one fact ("Up to 3 notes"). Tests: budget exhaustion
stops for approval; out-of-scope never spends; retry never double-spends;
ceiling cap rejects; replacement resets; content hash changes with the
budget; a budget on a `confirm_operations` op is rejected at draft time.

**Phase 2 (day 4): standing reads.**
Ceiling gains `standing_read: bool` (default false; true for the demo
launcher). With no active task, in-pattern fixture reads pass and are audited
as `supervision:standing_read`; writes still return the propose guidance.
Overview ticket copy for "No task is active" says reads are open. Tests:
reads pass, writes blocked, out-of-pattern reads blocked, stale-view rules
unchanged.

**Phase 3 (day 5): measure and record.**
Ten post-change fresh-chat runs. Fill the table below. Independent Bugbot and
Security review on the branch. Handover.

**Optional (only if Phase 0 says yes):** deep-link notification that opens
the existing Approvals card for the pending item.

## Measurement

Preregistered, same harness as Week 13, ten runs before and ten after:

| Measure | Baseline (Week 13 flow) | Target after Week 14 |
|---|---|---|
| Human interactions per completed routine job (propose → reads → 1–2 notes) | expected 2 | 1 |
| False interruptions per job (approval cards for in-scope, in-budget writes) | expected 1 | 0 |
| Writes that ran without either exact-scope match or a confirm/block tier | 0 | 0 (zero tolerance) |
| Budget exhaustion handled by a card, not a silent block | — | 100% |
| Proposals accepted without "Adjust in full form" | Week 13: 3/4 | ≥ 80% |

## Out of scope this week

Transition drafts, versioned guardrails, any widening flow, provider tools,
sessions, dark mode, any change to the Cursor-native advisory posture, any
OS surface that approves rather than opens.

## Deliverable

A task activation that carries the consent it needs, so routine fixture work
costs one click; standing reads under the ceiling; a measured before/after;
and a written verdict on whether an OS-level surface is worth building. If
the kill condition trips, the honest deliverable is the baseline measurement
and the reasons budgets were rejected.
