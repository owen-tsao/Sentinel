# Week 14 Plan: Consent at Activation

Status: proposed on September 11, 2026, starting from
[UI Foundation Handover](./UI%20Foundation%20Handover.md) and
[Week 13 Handover](./Week%2013%20Handover.md). The reorder was approved the
same day. Amended and **implementation approved** the afternoon of
September 11 after a review found three gaps (see "Amendments" at the end).
This plan approves no new dependency.

**Verdict after the build (September 11, evening).** The write budget was
built, tested, and reviewed, and then judged the wrong abstraction by the
user: the goal was never "fewer approvals per note" but "no activation click
for work that does not need one, and no per-action prompt unless the action is
actually dangerous." A per-task count is a patch on the last of those for a
toy tracker where nothing is dangerous. Standing reads and the three ceiling
tiers stay; the user-facing count was removed the same evening (in-scope notes
run, the cap is a silent runaway block) and the idea is generalised into
standing permissions in Week 15 (see the Roadmap's Week 15 entry). The
fixture's exact-ticket scope is recorded as a lab proof, not the product's
scope model.

**Why this replaced the Roadmap's original Week 14.** The original Week 14
was "Transition Drafts and Persistent Guardrails". The Week 13 live run ended
with a clear user verdict: the loop works, but per-write approval after a
reviewed contract is overkill, and a browser tab is the wrong place to click
"Approve". That verdict is the first free-use false-interruption report, and
the Roadmap already names the Week 13 friction measures as the yardstick. So
Week 14 is now friction (this plan); transition drafts and guardrails moved to
Week 15, provider mediation to Week 16, sessions to Week 17, and validation to
Week 18. The Roadmap and Product Architecture reflect this.

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
  can never be budgeted. Budgetable operations are a separate, explicit set,
  and the three sets (`ordinary`, `budgetable`, `confirm`) are disjoint.
  A budgetable operation behaves exactly like a confirm operation whenever the
  active task has no budget left (including a budget of zero), and runs
  without a card only while the task still has budget. The shipped default
  ceiling moves `issue_add_note` from `confirm_operations` to
  `budgetable_operations`, maximum 5; a task that grants no budget therefore
  behaves exactly as Week 13 did.
- Standing read permission is a *policy* the ceiling declares, not a task the
  browser creates. "No active task" keeps its meaning for writes and for the
  stale-view and supersession rules.
- The confirmation notification is sent by the **paired browser tab**, using
  the browser's own Notification API, never by the Python backend or an OS
  script. Its click handler runs as page code inside the tab that already
  holds the session cookie, so an approve-from-notification goes through the
  same protected route as the button on the card and adds no new door. Where
  the browser supports notification action buttons (Chrome, Edge) the
  notification offers an explicit **Activate** / **Approve** button next to
  **Open**; where it does not (Safari, Firefox) a click only focuses the tab
  and scrolls to the card. Nothing in Sentinel accepts a deep link, URL
  scheme, or unauthenticated request as an approval.
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
4. **Notification surface (unverified, spike only).** Can the paired Sentinel
   tab, with no new dependency, show a system notification when a proposal or
   approval is pending, and can a click on it complete the decision through
   the existing protected route? Known facts going in: the Notification API
   is standard in every desktop browser and the OS draws the banner, so the
   same page code works on macOS, Windows and Linux; action buttons need a
   service worker and exist only in Chromium browsers; the tab must be open
   (backgrounded is fine) and the person must grant permission once;
   Cursor's built-in browser is unlikely to grant it, so the tab lives in a
   normal browser. The earlier idea of an OS-native prompt from Python
   (`osascript`, `tkinter`) is dropped: it is macOS-only and any click it
   offers can only open a link, which a same-user process can also open.
   Decide in half a day, not a week.

Kill condition: if any path lets a write escape both the exact scope and a
confirm/block tier, or a budget can be set or increased by anything but the
protected activation click, budgets are dropped and per-write approval stays.
If a notification click can complete a decision without going through the
paired session and Origin check, approve-from-notification is dropped and the
notification only opens the card. If the ten-run baseline plus ten post-change
runs do not show routine work at one interaction per job, the friction problem
is recorded as unsolved and Week 15 proceeds without claiming otherwise.

## Threat model additions

- **Agent inflates the budget.** A proposal asks for 50 notes. Control: the
  ceiling caps the count; the card shows the number as its own fact; the
  default proposal budget is the minimum that completes the stated job (one
  note per issue listed), and the human can lower it before activating.
- **Agent shapes the default budget indirectly.** Because the default is one
  note per listed issue, the agent's `issue_ids` list decides the number the
  human sees. Control: the list is already bounded by the ceiling's issue
  pattern and the count by `max_write_budget`; the budget is shown as its own
  fact on the card rather than folded into the objective; the agent cannot
  pass a budget field at all (the proposal tool has no such argument).
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
- **Forged notification click.** A same-user process fires a notification or
  synthesises a click. Control: the notification is created by page code in
  the paired tab from the server's pending list, so there is nothing to fire
  from outside; the click handler calls the same cookie-and-Origin-protected
  route as the card button, so a synthesised click is no stronger than a
  synthesised click on the card, which is the trust boundary Week 12 already
  accepted. No deep link or URL scheme is registered.
- **Mis-click approves the wrong thing.** Control: the notification body
  states the exact action ("Add a note to SPIKE-1") or the exact grant
  ("write, SPIKE-1, 30 min, up to 1 note"); the one-click button is offered
  only where the browser renders it as a distinct action button; a plain
  click on the body always opens the card instead of approving.

## Phases

**Phase 0 (day 1): de-risk and baseline.**
Ten fresh-chat runs of the current flow, measured. Read-through of the
mediator to confirm the enforcement seam and lock. Half-day notification
spike with a written verdict. Gate: seam confirmed, baseline table in this
document. The ten human runs are the one Phase 0 item only the user can do;
code work may start on the seam read-through while they are collected, but
the before/after claim is not made until they exist.

**Phase 1 (days 2–3): write budget.**
Ceiling gains `budgetable_operations` and `max_write_budget`; contract gains
`write_budget`; mediator decrements under lock after scope checks pass;
proposals and the manual form carry the field; ticket, proposed-task card,
and receipt show it as one fact ("Up to 3 notes"). Tests: budget exhaustion
stops for approval; out-of-scope never spends; retry never double-spends;
ceiling cap rejects; replacement resets; content hash changes with the
budget; a budget on a `confirm_operations` op is rejected at draft time; a
task with zero budget behaves exactly as Week 13.

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

**Notification (only if Phase 0 says yes):** the paired tab shows a system
notification when a proposal or approval appears, with an action button that
completes the decision through the existing route where the browser supports
it, and a plain click that focuses the card everywhere.

## Measurement

Preregistered, same harness as Week 13, ten runs before and ten after.
Standing reads change what a "job" looks like: a read-only request that
needed one proposal and one click in Week 13 needs nothing after Phase 2, so
it produces no proposal and no loop. The harness therefore reports read-only
jobs separately (as "zero-interaction jobs") and the per-job rows below count
only jobs that include at least one write. The "proposals accepted" row is
comparable across the change because it is computed over proposals, not jobs.

| Measure | Baseline (Week 13 flow) | Target after Week 14 |
|---|---|---|
| Human interactions per completed routine write job (propose → reads → 1–2 notes) | expected 2 | 1 |
| False interruptions per write job (approval cards for in-scope, in-budget writes) | expected 1 | 0 |
| Read-only jobs completed with zero human interactions | 0 (a task was always needed) | 100% |
| Writes that ran without either exact-scope match or a confirm/block tier | 0 | 0 (zero tolerance) |
| Budget exhaustion handled by a card, not a silent block | — | 100% |
| Proposals accepted without "Adjust in full form" | Week 13: 3/4 | ≥ 80% |

## Out of scope this week

Transition drafts, versioned guardrails, any widening flow, provider tools,
sessions, dark mode, any change to the Cursor-native advisory posture, any
OS-native prompt drawn outside the browser, any custom-styled notification
window.

## Deliverable

A task activation that carries the consent it needs, so routine fixture work
costs one click; standing reads under the ceiling; a measured before/after;
and a notification from the paired tab that brings the decision to the
person instead of making them find the tab. If the kill condition trips, the
honest deliverable is the baseline measurement and the reasons budgets were
rejected.

## Amendments (September 11, 2026, afternoon)

A review of this plan against the code found three gaps, fixed above before
implementation was approved:

1. **The budgetable tier was implied, not defined.** The plan said an op in
   `confirm_operations` can never be budgeted and that the default ceiling
   budgets `issue_add_note`, but today's default ceiling has `issue_add_note`
   *in* `confirm_operations`. The fixed decisions now define three disjoint
   sets and state that a budgetable op with no budget behaves as confirm.
2. **The OS-native spike targeted the wrong mechanism.** `osascript` and
   `tkinter` are macOS-only and can only open a link, so a click could never
   safely approve. The spike now targets the browser Notification API from
   the paired tab, which is cross-platform and lets the click run through the
   existing protected route.
3. **Standing reads would have broken the before/after comparison.** Read-only
   jobs stop producing proposals after Phase 2, so the harness now separates
   them and the per-job rows count write jobs only.
