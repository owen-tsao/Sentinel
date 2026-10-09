# Week 14 Handover

Written September 11, 2026, after the in-process build, the independent
Bugbot and Security reviews, the fixes they prompted, and a same-evening
revision that removed the user-facing "write budget" (see "What changed since
the first build"). Uncommitted on the working tree at the time of writing;
nothing here has been committed, pushed, or measured in a live session yet.
The live before/after runs are the one item only the user can do, and they
are still owed (see "Not verified").

## What changed, in one paragraph

Activating a task is now the only click routine fixture work needs. Under an
active task that lists an issue, a note on that issue simply **runs**: no
approval card, no count shown to anyone. The ceiling still holds a per-task
write limit, but it is a **runaway bound**, not a consent knob: it is never
chosen by the agent or offered to the person, and when a looping agent reaches
it the write is *blocked* with "propose a fresh task", so a runaway can never
turn into a stream of approval cards. Separately, the ceiling can declare
**standing reads**: in-pattern fixture reads run with no active task at all, so
a purely read-only job needs no click. Finally, the paired browser tab can show
a **desktop notification** when a proposal or write is waiting; where the
browser draws action buttons (Chromium) the notification offers Activate /
Approve, and the click completes the decision through the same protected route
as the on-screen button. Nothing outside the browser is involved.

## What changed since the first build (same evening)

The first build exposed the write limit as a per-task "Notes without asking"
number on the card, the ticket, the receipt, and the full form, defaulted to
one note per listed issue, and turned exhaustion into an approval card. The
user judged that the wrong abstraction: the goal was never "fewer approvals per
note" but "no activation click for work that does not need one, and no
per-action prompt unless the action is actually dangerous" (Roadmap, Week 15).
So the number was stripped from every surface and from the agent's guidance,
the server now stamps the ceiling's cap (50) on every in-scope note task, the
form no longer sends a count, and reaching the cap blocks instead of asking.
The three ceiling tiers, the content-hash binding, and the fixture's exact
scope check are unchanged. Nothing about this can widen a block: a note on an
unlisted issue is still blocked before the limit is even read.

## What the person sees

- **Proposed-task card** shows the grant in words: "Read and add notes",
  the issues, the duration. No count.
- **Current-task ticket** footer states the rule: "Reads run freely; notes
  inside this task run without asking. Anything outside it is blocked." A shell
  write task still says "each write pauses for your approval" (shell tools are
  in the confirm tier); a read-only task says it cannot write.
- **Idle ticket** copy changes only when the ceiling declares standing reads:
  "Your agent can read fixture issues, but every write stays blocked until
  you activate a task."
- **Full form** has no budget field. The targets hint for a fixture write task
  reads "Notes on these issues run inside the task; anything else is blocked."
- **Activation receipt** and the Tasks-page ticket carry the same sentence.
- **Activity** explains in-task notes ("ran inside the task you activated"),
  runaway blocks ("hit its runaway write limit ... told to propose a fresh
  task"), and standing reads in plain words.
- **Settings › Approval preferences** gains "Desktop notifications", off by
  default. Turning it on asks the browser once. It is honest about "blocked"
  and "unsupported" states.

## What the agent sees

- An in-scope note returns `allow` with reason `mcp:budgeted_write` and the
  guidance "This write ran within the active task." No numbers.
- A note past the runaway limit returns `block` with reason
  `supervision:write_budget_exhausted` and guidance to stop and call
  `sentinel_task_propose` for a fresh task. A retry of an attempt that already
  ran is still answered truthfully (`mcp:already_applied`), not re-blocked.
- With standing reads on and no task, `sentinel_issue_read` on an in-pattern
  issue returns `allow` with `supervision:standing_read`; a write returns the
  same `contract:not_found` block as before, pointing at `sentinel_task_propose`.
- `sentinel_task_propose` still accepts exactly `operation`, `issue_ids`,
  `minutes`; a `write_budget` argument is rejected as `mcp:unknown_argument`.

## Where authority lives (unchanged principle, new fields)

- **Ceiling** (`SupervisionPolicy`) has three disjoint operation tiers,
  `ordinary`, `budgetable` (in-scope writes that run without a card), and
  `confirm`, plus `max_write_budget` (the runaway limit) and `standing_read`.
  All are in the ceiling hash. Construction rejects overlapping tiers and a
  limit with no middle-tier op (or the reverse). The default fixture ceiling
  places `issue_add_note` in the middle tier with a limit of 50; the demo
  launcher also turns standing reads on.
- **Contract** carries `write_budget`. It is set by exactly one builder,
  `_accepted_fixture_contract`, which stamps the ceiling's limit on an in-scope
  note task and zero otherwise, on both the manual draft route and the proposal
  confirm route. A request value above the limit, or on a read task, is
  rejected with 422 rather than clamped; the confirm body still forbids extra
  fields, so nothing can be smuggled in.
- **Gateway** reads the spent count from the fixture's durable operation
  records (`count_spent_writes`, counting admitted/applying/succeeded/unknown
  so a crashed write stays spent) under the same session lock that admits the
  write. Blocked, denied, failed, and replayed attempts spend nothing. A
  replacement task starts at zero because the count is keyed by task.
- **Decision composition** never lets the limit widen anything: `forbidden`,
  no task, and target mismatch are all checked before the limit is read.
- **Standing reads** require the ceiling verdict `ordinary` (tool family,
  environment, and issue pattern already enforced), no active record, *and*
  authority available. Bugbot caught that a quarantined authority also yields
  "no record"; that state now stays fully fail-closed.
- **Notifications** are built by page code from the server's pending list.
  The service worker (`web/public/sentinel-sw.js`) never fetches the backend;
  it only forwards a click to the paired tab, which re-checks the item is
  still pending and calls the existing cookie-and-Origin-protected route. If
  the tab is closed, a click can only open one. Deletes and production
  approvals (typed-target items) are open-only. Click paths are whitelisted.

## Verification run (after the revision)

| Check | Result |
| --- | --- |
| `python3 -m pytest tests` | 636 passed |
| `python3 scripts/generate_control_types.py --check` | clean |
| `cd web && npm run typecheck && npm run lint` | clean |
| `SENTINEL_WEB_PORT=3100 npx playwright test` | 33 passed |
| Bugbot review (first build) | 1 medium (quarantine standing read), 4 low; all fixed |
| Security review (first build) | no medium+ findings; 2 optional hardenings, 1 applied |
| Independent review of the revision | see the chat summary of September 11 |

Test files: `tests/test_write_budget.py` (13 cases: every in-scope note runs
with no card and no count in guidance; runaway limit blocks with a next step
and raises no card; zero limit equals Week 13; out-of-scope spends nothing;
retry at the limit never double-spends and is answered truthfully; replacement
starts fresh; proposals carry the ceiling limit regardless of issue count;
manual form cannot raise or choose it; confirm-tier op never runs card-free;
agent and confirm body cannot carry it; hash moves with it; pure decision
tiers), `tests/test_standing_reads.py` (7 cases, including quarantine),
`web/tests/e2e/week14-write-budget.spec.ts` (4: idle copy, ticket rule with
no count, card with no count, form with no field and a confirm body with no
count) and `web/tests/e2e/week14-notifications.spec.ts` (4, with the
Notification API and service worker stubbed because headless Chromium has no
system tray). Note: port 3000 on this machine belongs to another project; run
Playwright with `SENTINEL_WEB_PORT` set to a free port or the running Sentinel
dev server.

## Measurement harness

`scripts/week13_measure.py` separates read-only proposals from write jobs
(standing reads remove read proposals entirely after the change, which would
otherwise flatter the per-job count), counts notes that ran inside the task,
counts *distinct attempts* blocked at the runaway limit (expected to be zero;
any non-zero value means a looping agent), and counts standing reads. The
target row reads "2 before Week 14; 1 after".

## Not verified

- **The ten-run baseline and ten post-change runs.** Not done. Without them
  the before/after claim in the plan is not made. Run the demo launcher,
  do ten fresh-chat jobs, stop, and point the harness at the run directories
  as `docs/Week 13 Handover.md` describes.
- **A real desktop notification.** The spike is verified with stubs only. A
  live check in Chrome (action buttons) and Safari or Firefox (plain click)
  is owed before the notification is called done.
- **The settings toggle branch** (no spec; verify by hand, step 6 below).
- **The runaway limit against a live agent.** Unit- and API-tested only; no
  live loop of 51 notes has been run.

## Manual verification

Start the demo: `python3 scripts/week12_control_demo.py` and open the pairing
link it prints. Then:

1. **Notes just run (critical).** From Cursor, propose a write task on SPIKE-1
   and SPIKE-2. The card shows "Read and add notes", the two issues, and the
   duration; no number anywhere. Activate. Have the agent add a note to each,
   then a third and fourth: every one returns `allow` with
   `mcp:budgeted_write`, Approvals stays empty, and the ticket footer reads
   "notes inside this task run without asking".
2. **Out of scope is still blocked (critical).** Have the agent try a note on
   SPIKE-3: blocked (`contract:` reason). A note on PROD-1: blocked
   (`supervision:issue_out_of_scope`). Then a note on SPIKE-1: runs.
3. **Standing reads (critical).** With no task, have the agent read SPIKE-1:
   `allow`, `supervision:standing_read`; the idle ticket says reads are
   allowed. A read of PROD-1 is blocked; a write is blocked with the propose
   guidance.
4. **Agent cannot carry a limit (critical).** Have the agent call
   `sentinel_task_propose` with a `write_budget` argument: blocked as
   `mcp:unknown_argument`.
5. **Notification with action button (nice to check, Chrome).** Settings →
   Desktop notifications → On; grant. Switch focus to Cursor and propose a
   task. A notification appears with Activate / Open and a body like "read
   and add notes · SPIKE-1 · 30 min". Click Activate: the tab focuses and the
   ticket turns blue. Repeat in Safari or Firefox: the notification has no
   buttons and a click only opens the card.
6. **Settings toggle (nice to check).** With the preference on, reset the
   site's notification permission in the browser, reload Settings: it shows
   Off; one click re-prompts.
7. **Manual form (nice to check).** Tasks → fixture tool family → write: there
   is no "Notes without asking" field; the hint under the issues says notes run
   inside the task; the ticket preview shows the same sentence.
8. **Runaway limit (nice to check, scripted).** Not practical by hand (51
   notes). `tests/test_write_budget.py::InScopeWritesRunTests::
   test_runaway_limit_blocks_with_a_next_step_instead_of_a_card` proves it
   with a limit of 2.
