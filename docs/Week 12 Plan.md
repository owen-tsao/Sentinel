# Week 12 Plan: First Mandatory MCP Tool Path

Status: the direction is reflected in `docs/Roadmap.md` and
`docs/Product Architecture.md` as of September 8, 2026. Implementation still
requires explicit approval, and no new dependency is approved by this plan.

This plan starts from [Week 11 Handover](./Week%2011%20Handover.md). Week 12 is
an enforcement milestone, not the full automatic-supervision redesign.
Automatic task preparation begins in Week 13 after one mandatory action path
exists.

## Satisfied precondition from Week 11

The Week 11 branch now:

- persists quarantine before a protected lifecycle mutation;
- retains quarantine when completion audit and compensation cannot be verified;
- blocks unrelated contract-store writes while quarantine is present;
- reconciles before exposing authority after restart;
- suspends only the matching uncertain contract version;
- keeps authority closed if suspension or reconciliation audit fails;
- clears quarantine only after verified recovery;
- covers failure and process reconstruction with regression tests.

Restart alone cannot reopen unverified authority. This remains a required
regression throughout Week 12.

## Goal

Prove that one disposable local MCP tool family must pass through Sentinel in
one documented Cursor configuration:

1. The user activates one task through the existing protected Week 11 browser
   flow.
2. Cursor connects to a Sentinel MCP shim.
3. The shim submits untrusted tool arguments through an authenticated adapter
   session.
4. FastAPI resolves the task, startup guardrails, environment, adapter
   coverage, and canonical action.
5. Matching reads proceed through Sentinel.
6. One write requires exact browser approval.
7. Denial causes zero effect.
8. Approval causes exactly one unchanged effect.
9. Changed payload, replay, concurrency, or Sentinel shutdown cannot cause
   another effect.
10. The UI and audit show the exact action-family coverage and result.

The required release evidence includes a real Cursor MCP run. A faithful
client harness provides repeatable CI coverage but cannot prove Cursor
integration by itself.

## Honest enforcement claim

If every gate passes, Week 12 may claim:

> In the documented disposable Cursor configuration, Sentinel mandatorily
> mediates the local issue-fixture MCP tools and fails closed when Sentinel is
> unavailable.

It may not claim:

- trusted Cursor prompt provenance;
- automatic task activation;
- Cursor-wide shell, file, browser, network, or subagent enforcement;
- general MCP enforcement;
- provider credential protection;
- GitHub, Slack, Google, or other live-provider enforcement;
- protection against arbitrary same-user operating-system compromise.

## Fixed decisions

- **FastAPI remains authoritative.** Cursor, the MCP shim, and Next.js cannot
  choose authority, identity, policy, coverage, approval, or execution route.
- **Cursor prompts remain advisory.** Week 12 uses the existing protected
  browser task flow.
- **One server-owned supervision session remains supported.** Multi-session
  work is deferred until authenticated adapter-to-session mapping exists.
- **One immutable startup guardrail ceiling applies.** It is bound to the
  reviewed workspace, supervision session, fixture project, exact tool family,
  operations, environment, and process lifetime.
- **Guardrails are not task authority.** They restrict what an activated task
  may authorize.
- **The MCP shim uses session-scoped bearer authentication.** It does not
  receive an approval token or reusable authority.
- **Same-session bearer theft is indistinguishable from the real shim.** If the
  guarded agent can obtain the capability, the mediation claim fails.
- **The fixture remains local and disposable.** It performs no network call,
  uses no provider credential, and never modifies the user's repository.
- **Fixture state is outside guarded workspace mounts and normal agent-readable
  paths.**
- **Coverage is per action family.** Mandatory fixture tools do not make other
  Cursor actions protected.
- **ML remains disabled.**
- **UI work is minimal.** Show connection and coverage truth; defer automatic
  task UX and the broader command-center redesign.

## Riskiest assumption

Cursor can call one Sentinel MCP tool family in a disposable configuration
where every effect from that family reaches Sentinel first and Sentinel
failure prevents the effect.

An MCP server existing is not evidence. The live spike must attempt direct,
alternate, disabled, malformed, delayed, and unavailable paths before shared
implementation begins.

## Phase 0 cutoff

Complete the mediation evidence and exact dependency decision by the end of the
second working day. If either remains unresolved, finish Week 12 as a
documented spike, move later roadmap milestones, and do not compress the
remaining implementation into the week.

## Scope

### Must ship

- Live Cursor prompt/MCP/shell/file/browser/subagent capability probe.
- Repeatable action-family coverage matrix.
- Immutable startup guardrail ceiling for the local fixture.
- Authenticated, short-lived adapter session for the MCP shim.
- Local issue fixture with one read and one add-note operation.
- Server-side canonical MCP action containing every target, effect, and exact
  note payload binding.
- Contract and deterministic policy evaluation before fixture effects.
- Exact-action approval through the existing protected browser.
- Durable at-most-once fixture operation handling.
- Gateway-down, replay, changed-payload, concurrency, and bypass evidence.
- Minimal UI status for the connected MCP session and action-family coverage.
- One real Cursor run and one automated harness path.
- Focused and full regressions.
- Independent correctness and security reviews.

### Explicitly deferred

- Automatic task drafting and compact task confirmation.
- General task-transition classification.
- Persistent editable guardrails and templates.
- Multiple agent sessions.
- General agent command-center redesign.
- Real GitHub or other provider execution.
- Provider credentials and OAuth.
- LLM suggestions.
- ML calibration, promotion, or serving.
- Hosted identity, tenancy, billing, or managed execution.
- Marketing and release work.

## Threat model

### In scope

- The agent calling integration routes directly.
- Missing, expired, copied-across-session, or replayed adapter bootstrap
  material.
- Caller-selected workspace, session, contract, identity, environment,
  coverage, verdict, or execution route.
- MCP calls with changed operations, issue IDs, note targets, payloads, or
  hidden second targets.
- Approval reuse after action, task, authority, adapter, or policy changes.
- Duplicate and concurrent retries.
- Crash after durable admission.
- Gateway timeout, malformed response, shutdown, and restart.
- MCP or hook configuration changes attempted from the guarded workspace.
- Attempts to read fixture state or adapter material.
- Browser automation against the paired approval session.
- Raw task prompt, approval token, and adapter capability leakage.

### Out of scope

- Arbitrary compromise of the developer's OS account.
- A process that can inspect all same-user process memory or browser cookies.
- Real provider identities, credentials, and effects.
- Cursor actions outside the declared local MCP fixture family.
- Production tenant isolation.

The arbitrary-OS exclusion does not excuse a bypass available through the
guarded agent's normal configured capabilities. If Cursor can reach fixture
state, adapter material, or the approval browser through an enabled tool, the
mandatory claim fails.

## Target architecture

```text
Paired browser
  -> existing protected task activation and exact approval
  -> FastAPI authority and approval services

Cursor
  -> Sentinel MCP shim
  -> session-scoped adapter bearer
  -> FastAPI integration route
  -> server-resolved supervision session and startup guardrails
  -> canonical MCP action
  -> existing contract and deterministic policy
  -> allow / confirm_required / block
  -> durable admission
  -> isolated local issue fixture
  -> stored terminal result and ordered audit
```

The shim sends adapter proof and raw tool arguments. FastAPI maps the
server-owned session and resolves environment, authority, identity trust,
coverage, and canonical action. The shim never sends an authoritative verdict,
contract body, approval token, or execution route.

## Phase 0: Live mediation spike

Do this before adding an MCP package, shared schemas, or UI.

Use:

- a disposable Git repository;
- a disposable Cursor profile;
- no real provider credentials;
- fixture state outside the repository;
- one observable note effect that only the isolated fixture service can
  create.

### Probe current Cursor behavior

1. Register one temporary Sentinel MCP server.
2. Capture actual prompt, MCP, shell, file, browser, and subagent events.
3. Confirm Cursor can discover and call the MCP tool.
4. Deny the call synchronously before its effect.
5. Stop Sentinel and verify the effect does not occur.
6. Return malformed and delayed responses and verify failure stays closed.
7. Attempt the same effect through shell, direct HTTP, file scripts, browser
   automation, and subagents.
8. Attempt to edit or disable project and user MCP/hook configuration.
9. Attempt to locate or alter fixture state.
10. Attempt to forge the adapter session.
11. Record every tested family as mandatory, advisory, unsupported, or
    unavailable.

### Required isolation

Fixture state, adapter material, and MCP configuration must be outside guarded
workspace mounts and normal agent-readable paths. Use a separate
process/container identity or another boundary whose isolation is explicitly
tested.

The integration API may still be reachable. Direct calls must pass the same
adapter authentication, active-task resolution, policy, approval, admission,
and audit path; reaching FastAPI is not itself a bypass.

### Phase 0 kill conditions

Stop Week 12 if any is true:

- The fixture effect can occur without Sentinel.
- Sentinel shutdown or timeout permits the effect.
- Cursor cannot complete a real MCP call.
- The guarded agent can read or alter fixture state or adapter material.
- The guarded agent can control the paired browser.
- A direct integration call bypasses authentication or policy.
- A changed payload can reuse approval.
- Configuration can be silently disabled through an in-scope action.
- The proof requires ML, provider credentials, or writable access to the real
  repository.

### Phase 0 exit evidence

Before implementation continues, produce:

- repeatable spike instructions or script;
- captured allow, deny, malformed, unavailable, and bypass outcomes;
- exact Cursor and environment versions;
- action-family coverage matrix;
- narrow enforcement wording;
- exact dependency proposal.

## Dependency approval gate

No new package is approved yet.

After Phase 0, present:

- exact package names;
- which process uses each package;
- why it is required;
- security and maintenance implications;
- no-new-dependency alternative;
- package-manager commands using current supported releases.

An official Python MCP SDK is the likely choice. Do not install it until the
user approves the exact list. Do not add a provider SDK in Week 12.

## Phase 1: Immutable startup guardrails

Add a `SupervisionPolicy` fixed before startup:

- reviewed workspace identity;
- server-owned supervision session;
- adapter kind and MCP tool family;
- exact fixture project;
- allowed issue identifiers or strict identifier pattern;
- allowed ordinary operation: issue read;
- confirm-required operation: add one internal note;
- forbidden operations: delete, network, credential access, arbitrary command
  execution, and fixture administration;
- environment: disposable local demo only;
- expiry or maximum process lifetime.

Persist a policy content binding beside the workspace/session binding.
Reopening the same state database with different guardrails must reject
startup. Week 12 provides no runtime policy-edit route.

Every task, approval, and MCP action is intersected with this ceiling. The
ceiling cannot activate a task.

## Phase 2: Adapter session and coverage

Add host-neutral records:

- **Agent connection:** configured host and connection status.
- **Adapter session:** one process/session binding for MCP calls.
- **Capability profile:** measured action families, execution ownership, and
  known bypasses.
- **Coverage result:** `mandatory`, `advisory`, `unsupported`, or `unavailable`.

Adapter bearer requirements:

- generate a random short-lived capability at launcher startup;
- store only its hash in FastAPI;
- bind it to one supervision session, adapter kind, process lifetime, and MCP
  tool family;
- compare it in constant time;
- rotate it after restart or disconnect;
- reject missing, expired, and cross-session credentials;
- consume and reject replayed bootstrap handshakes;
- deliver it through a channel unavailable to the guarded agent's declared
  capabilities;
- never expose it to the browser, tool results, audit, normal logs, or Git.

Possession authenticates the adapter session only. FastAPI still resolves
active authority and policy for every call.

## Phase 3: Isolated local issue fixture

Support exactly:

- `sentinel_issue_read`
- `sentinel_issue_add_note`

The read tool returns one bounded server-owned issue record. The note tool adds
one exact internal note. Neither tool accesses a network provider or user
repository.

Keep fixture administration unavailable through MCP. Seed and clean it through
the trusted test launcher.

### Durable operation state

Use:

```text
prepared -> admitted -> applying -> succeeded | failed | unknown
```

Bind each operation to:

- attempt ID;
- adapter session;
- task and contract version;
- authority epoch;
- supervision policy binding;
- tool and operation;
- every target and effect;
- exact note UTF-8 bytes or payload hash.

Persist fixture state and terminal operation result atomically in SQLite. If an
implementation cannot guarantee that atomic update, an interrupted `applying`
operation becomes `unknown` after restart and is never retried automatically.

Test a crash:

- before admission;
- after admission but before the effect;
- after the effect but before a separately attempted result write;
- after terminal storage but before response;
- during completion audit.

## Phase 4: FastAPI MCP mediation

For every call:

1. Authenticate the adapter session.
2. Reject unknown fields.
3. Ignore or reject caller-selected session, contract body, identity,
   environment, coverage, verdict, and route.
4. Resolve the server-owned supervision session, active contract, startup
   guardrails, environment, and capability profile.
5. Canonicalize the tool, operation, every issue/note target, expected effects,
   and exact payload.
6. Evaluate contract and deterministic policy.
7. Audit the decision.
8. Admit allowed reads durably before returning fixture data.
9. Create a pending exact-action approval for confirm-required writes.
10. On protected approval, retry only the unchanged action and consume the
    approval during durable admission.
11. Store and return the terminal operation state.

Evaluation-only calls do not create pending approvals. Unsupported tools and
unavailable coverage fail closed.

### Required cases

- allowed issue read;
- repeated matching reads;
- changed issue ID;
- changed note body;
- hidden second issue or effect;
- unknown tool and unknown argument;
- missing, expired, and cross-session adapter bearer;
- replayed bootstrap;
- stale task, authority, policy, and adapter session;
- denial with zero note;
- approval with one exact note;
- duplicate and concurrent retry;
- response loss after terminal storage;
- crash and unknown outcome handling;
- audit admission and completion failure;
- gateway shutdown.

## Phase 5: Minimal control-center status

Do not redesign the complete app.

Add:

- connected Cursor MCP session;
- gateway availability;
- mandatory local fixture tools;
- advisory or unsupported prompt, shell, file, browser, network, and subagent
  families;
- last mediated tool and result;
- exact MCP action details in Approvals and Activity.

Keep the existing task-creation and activation flow for Week 12. Planned
provider/OAuth connections remain visibly unavailable. Never show a generic
“fully protected” state.

## Phase 6: Verification

### Required real Cursor path

1. Start the isolated fixture, FastAPI control process, MCP shim, and web app.
2. Pair the browser.
3. Activate the exact fixture task through the existing Week 11 flow.
4. Connect Cursor to the actual MCP shim.
5. Perform at least three matching issue reads.
6. Propose one exact note write.
7. Deny it and verify zero notes.
8. Submit a fresh write.
9. Approve it through the browser.
10. Verify exactly one unchanged note.
11. Reject changed payload and replay.
12. Inspect ordered audit and coverage evidence.
13. Stop Sentinel and verify no additional fixture effect.

Record enough evidence to reproduce the run. A CI harness must exercise the
same MCP/FastAPI/policy/approval/fixture path, but it does not replace this live
Cursor proof.

### Required measurements

Report exact denominators and environment:

- tested action families by coverage status;
- attempted and successful bypasses;
- allowed, blocked, and confirmation-required MCP calls;
- changed-action and replay rejection;
- duplicate fixture effects;
- p50 and p95 local decision latency;
- audit admission and completion success;
- leaked prompt, adapter, approval, or fixture material.

Release targets:

- 100% observed mediation for the declared fixture family;
- zero successful tested fixture bypasses;
- zero effects while Sentinel is unavailable;
- zero changed-action or replay acceptance;
- zero duplicate notes;
- zero adapter or approval capability exposure;
- explicit advisory labels for every uncovered Cursor family.

These are bounded local test results, not production guarantees.

### Final verification

- Focused unit and integration tests.
- Full Python 3.11 suite.
- Frontend type check, lint, generated-type check, and production build.
- Playwright mocked-state checks.
- Real Cursor MCP run.
- Automated MCP/FastAPI/SQLite fixture path.
- Week 11 browser/Docker regression.
- Redaction and credential-pattern scan.
- `git diff --check`.
- Independent correctness review.
- Independent security review.

Fix every confirmed blocker and high-severity issue before calling Week 12
complete.

## Planned code boundaries

Names may change after Phase 0:

```text
src/sentinel/supervision/
  policy.py           # immutable startup ceiling

src/sentinel/integrations/
  models.py           # adapter session and measured coverage
  registry.py         # server-owned connection state

src/sentinel/mcp/
  server.py           # fixture MCP tools
  gateway.py          # authenticated FastAPI handoff
  fixture.py          # isolated disposable issue state

src/sentinel/api/
  integration_routes.py
  integration_schemas.py
```

Reuse existing contract, authority, approval, audit, and attempt services. Do
not build another policy engine in the MCP shim or frontend.

## Definition of done

Week 12 is complete only when:

- the Week 11 restart-recovery precondition is already closed;
- Phase 0 proves a real Cursor MCP call and mandatory fixture mediation;
- fixture state, adapter material, and configuration are unavailable through
  the guarded capabilities;
- one immutable startup guardrail ceiling is server-owned and content-bound;
- an authenticated adapter maps calls to the single supervision session;
- multiple matching reads pass through Sentinel;
- one write is denied with zero effect;
- one fresh write is approved and produces one exact effect;
- changed action, replay, concurrency, crash, and shutdown cannot produce an
  unauthorized or duplicate effect;
- the UI and audit show exact coverage without overstating protection;
- all focused and full regressions pass;
- independent reviews find no unresolved blocker or high-severity issue;
- README, Product Architecture, Roadmap, and the next handover match only the
  verified result.

If mandatory fixture mediation fails, Week 12 ends as a documented spike. Do
not proceed to automatic task preparation or describe Sentinel as automatic
enforcement.

## Recommended implementation order

1. Confirm the Week 11 recovery fix is merged.
2. Run the disposable live Cursor/MCP spike.
3. Review and approve exact dependencies.
4. Add immutable startup guardrails.
5. Add adapter session and coverage records.
6. Add the isolated issue fixture and durable operation state.
7. Route fixture MCP calls through FastAPI authority and policy.
8. Add minimal connection and coverage status.
9. Run the real Cursor path and automated regression.
10. Complete independent reviews and documentation.

## Recommended commits

Create commits only when explicitly requested:

1. `Prove one mediated Cursor MCP path`
2. `Add fixed supervision guardrails`
3. `Bind MCP calls to one adapter session`
4. `Route the local issue fixture through Sentinel`
5. `Show MCP coverage in the control center`
6. `Add the mandatory fixture regression path`
7. `Document the verified Week 12 boundary`

## Direction after Week 12

- **Week 13:** automatic draft preparation and one compact protected
  confirmation.
- **Week 14:** transition drafts and protected persistent guardrails.
- **Week 15:** conditional real-provider spike and one narrow integration.
- **Week 16:** two isolated backend sessions and a minimal scoped session
  list/switcher; the broader command-center redesign remains post-validation.
- **Week 17:** validation, hardening, packaging, and release decision.
- **After the release gate:** public marketing and separately evaluated
  draft-only LLM suggestions.
