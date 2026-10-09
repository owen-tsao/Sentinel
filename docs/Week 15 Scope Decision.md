# Week 15 Scope Decision (draft for your review)

Status: **draft, September 11, 2026, evening; revised the same evening after
an adversarial review.** This is the written decision the Roadmap's Week 15
Part 1 asks for. Nothing in it is built. You review it, change what you
disagree with, and only then does Week 15 code start. Every claim below is
marked **verified** (checked in the repo or in the vendor's own documentation
today) or **unverified** (a belief the Week 15 spike must confirm). Companion:
[Week 15 Plan](./Week%2015%20Plan.md).

Two words used throughout, defined once: **mandatory** means the agent has no
way around Sentinel for that action, so Sentinel's decision is the last word.
**Advisory** means Sentinel can see or warn about the action but cannot stop
it, because the agent has another route.

## The decision in four sentences

Sentinel is the single door between an agent and the things that agent is
allowed to touch, for one person on their own machine. It protects specific
resources, named by kind and pattern (this repo; these Slack channels; later,
this inbox minus these labels), never "your whole account" and never a list of
exact record IDs by default. Inside the door, routine work runs with no
clicks; stepping outside asks you once; a genuinely dangerous act asks every
time; a few things are never allowed. Enforcement is claimed as mandatory only
where Sentinel is the only route to the resource, and everywhere else Sentinel
says plainly that it is advisory.

## Who this is for

An individual developer running coding or assistant agents (Cursor first,
Claude Code second) against their own accounts on their own machine. It is not
for teams or admins yet, and it does not defend against someone who already
controls the machine. Those belong to the hosted half of the Roadmap, not
Week 15.

## Question 1: where do integrations live?

**Decision: owned mode only. Proxy mode is deferred, not planned for Weeks
15 or 16.**

- *Owned mode* means Sentinel holds the provider credential (a Slack bot token,
  later an OAuth connection) and Sentinel makes the provider call. The agent
  only ever talks to Sentinel's MCP tools. This is the only arrangement where
  "the agent cannot bypass the check" is true, because the agent never has
  anything to bypass with. **Verified** that this matches the architecture's
  local-product rule that Sentinel keeps the broad credential behind its
  gateway and gives the agent only a short-lived task grant (Product
  Architecture §3.4, and the future-boundaries note in §17).
- *Proxy mode* (Sentinel forwards to an MCP server the user configured
  themselves) would be "mandatory only when Sentinel is the sole configured
  route", which is a claim about the host's configuration rather than about
  Sentinel. It is honest but weak, and building it now would spread effort
  across two enforcement stories before one is proven. Deferred until owned
  mode works for one real provider.
- **What today's repo has (verified):** no credential store, no OAuth flow, no
  provider write path. The Slack and Google code under `src/sentinel/spikes/`
  is read-only metadata probing with a token passed in by the caller, over a
  GET-only HTTP client. Owned mode therefore needs, in Week 16 and not Week
  15: a Sentinel-held secret (paste-a-token first; OAuth later, because Slack
  OAuth needs a public HTTPS redirect that a local-first app does not
  naturally have), a real Connections page, a provider write path with the
  durable lifecycle the architecture already specifies, and a Slack tool
  family added to the gateway and ceiling (today the gateway knows exactly two
  fixture tools and the ceiling supports only the `sandbox` environment).

## Question 2: which provider first?

**Decision: Slack first, in a disposable workspace. Gmail second, once a
Google Workspace tenant exists. GitHub is deferred, replacing the Roadmap's
Week 16 "preferred proof".**

Why Slack and not the others:

- **Slack is the only provider Sentinel has live-validated.** On September 7 the
  read-only spike returned all sixteen facts Sentinel needs from one public
  internal channel, stable across a double read (`data/spikes/README.md`).
  **Verified.** What it did *not* cover: private channels, guest accounts, and
  Slack Connect channels (a channel shared with another company). Those are
  exactly the "dangerous" cases, so they are the first thing the Week 15 spike
  must seed and read. **Unverified.**
- **The facts that decide "dangerous" are Slack facts, not model guesses.**
  `is_ext_shared`, `is_private`, `num_members`, and per-member
  `is_restricted` / `is_stranger` flags are returned by the API and already
  normalised into Sentinel's `AudienceSnapshot` as `is_external_shared`,
  `external_recipient_ids`, `guest_recipient_ids`, and `recipient_count`.
  **Partly verified in code**, with two honest limits: the snapshot's
  `is_broadcast` flag is *not* a member-count fact (it records a thread-reply
  broadcast), so a "too many people" rule must be written from
  `recipient_count`; and the probe refuses channels above 198 members and
  spends up to 500 API calls classifying them, so a large channel is today a
  fail-closed "cannot classify", not a classified broadcast.
- **Gmail is blocked on money, not design.** Sentinel's Google probe needs a
  Google Workspace tenant because recipient classification uses the Admin
  Directory API; on a consumer Gmail account the required identity fields are
  missing and the probe fails closed. **Verified.** Whether recipient
  classification can be done well enough *without* Directory
  (domain-of-address only) is **unverified** and is not a Week 15 question.
- **GitHub is third in the domain gate** (communications, then CRM, then
  code/deployment), and a coding agent already has git and `gh` natively, so
  Sentinel fronting a GitHub MCP tool would be advisory on every host anyway.
  Deferring it is consistent with Question 3.

**Seeding reality (verified from Slack's plans, stated so the spike cannot
fail for billing reasons and be misread as a design failure):** guest accounts
and Slack Connect both need a paid plan on at least one workspace. A free
trial of Pro on the throwaway workspace covers both for the spike. The bot must
also be invited into each private channel before it can see it. If a case
cannot be seeded, the spike records it as *not tested*, which is different
from *facts absent*.

## Question 3: which agent hosts, and can they be locked?

The deciding question per host is: *can the user configure it so the provider
is reachable only through Sentinel, and can the agent not undo that?*

| Host | Lock mechanism | Status | Sentinel's claim |
| --- | --- | --- | --- |
| **Cursor** | Cursor's agent sandbox provides the write boundary; Sentinel's hooks add a fail-closed check on any agent read or edit of `.cursor/mcp.json`, `hooks.json`, `permissions.json`, `sandbox.json`; the person launches Sentinel. Cursor's own server allowlist is Enterprise-dashboard-only; `permissions.json`'s `mcpAllowlist` governs which tools auto-run, not which servers may exist. | **Verified** in repo (`policies/cursor/sentinel_hooks.py`) and Cursor docs. Already the Week 12 claim. | Mandatory under the tested configuration, for tools reached through Sentinel. Native shell, file, browser: advisory. |
| **Claude Code** | `managed-mcp.json` makes its server list the *only* list that loads; users and plugins cannot add servers. `allowedMcpServers` plus `allowManagedMcpServersOnly: true` in a managed settings source (`~/.claude/managed-settings.json`, or a device-management profile) makes the allowlist authoritative. Bypasses via `--mcp-config`, reconnect, IDE-typed configs, and subagent definitions were closed by v2.1.169 (June 2026). | **Verified in vendor docs today; unverified live.** The managed file is same-user-writable and Claude Code has a shell tool, so the lock only holds with Claude Code's own sandbox on plus a permission rule denying edits to `~/.claude/`; whether that combination holds is **unverified**. The spike records the installed Claude Code version. | Candidate for "mandatory under a documented configuration". The Week 15 spike decides. |
| **Codex** | `~/.codex/config.toml` `[mcp_servers]`, plus project `.codex/config.toml` in trusted directories. Per-server `enabled_tools` / `disabled_tools` exist. No mechanism found that forbids *adding* a server. | **Verified** that the config exists; **no lock found** in the docs read today. | "Mandatory only when configured", i.e. advisory. Not in the Week 15 spike; this narrows the Roadmap's "check config parity on Codex" to a documented reason. |
| **Hermes** | Has an MCP client (`~/.hermes/config.yaml` `mcp_servers`), but its core tools (terminal, and sending on Telegram, Discord, and other platforms) are native and never pass through an MCP server. | **Verified** from vendor docs. | Advisory. Fronting Hermes's messaging with Sentinel would be a Hermes-side feature, not ours. Not in Week 15. |

**Decision:** prove Cursor (already proven) and Claude Code in the Week 15
spike; write Codex and Hermes into the coverage map as advisory with the
reason above; revisit Codex if a server allowlist appears.

**Shared caveat, stated up front:** on every host, a same-user agent that has
an unsandboxed shell could edit the host's own config. That is why native
shell stays advisory everywhere, and why each host's "mandatory" claim carries
a named configuration (sandbox on, hooks or managed settings in place,
Sentinel launched by the person). This is the same posture the repo already
takes for Cursor; Week 15 extends it to Claude Code or says why it cannot.

## Question 4: what does "scope" mean?

**Decision: two axes, resource-shaped, with four outcomes.** "Resource-shaped"
means a grant names a kind and a pattern (these channels; issues matching
`SPIKE-*`; files under this folder), not individual record IDs.

- **Exposure** answers *what may the agent touch at all*, reads included. A
  customer's Slack Connect channel is confidential even though reading it
  changes nothing.
- **Damage** answers *which operations on those resources ask first*. It is
  decided from provider facts: reversibility (post vs delete), breadth (6
  members vs 200), and whether the effect leaves the boundary (an external or
  shared channel, an external recipient).

Those two axes produce four outcomes, which replace the Week 14 idea of a
"budget". The order matters and is the same order the code will check:

1. **Block** (no card, clear guidance): never allowed by Sentinel's fixed
   limits, or outside *both* the standing set and the active task. Checked
   first, so an unauthorised target can never earn a confirm card. The
   guidance differs: "never allowed" says so; "outside your authority" names
   the smallest task that would cover it, which is what the table below calls
   "task needed".
2. **Confirm every time** (one card per action): inside the boundary but
   dangerous by the facts, regardless of any task.
3. **Task** (one click): the person's way to step outside standing
   permissions. The card names exactly the step outside ("also #general",
   "also SPIKE-9xx"), and the task grants only that step.
4. **Standing permission** (no task, no click): work the person granted once,
   in Settings, for this workspace. Audited, never silent.

**What changes from today (verified):** scope today is exact record IDs
(`exact_targets: ["SPIKE-1"]`) plus a startup regex. Standing permissions are
resource-shaped instead. Tasks may still be exact when the person wants them
to be.

### A concrete boundary, for a disposable Slack workspace

Suppose the standing set says: *read and post in #sentinel-dev and #random;
read #general.* The workspace also has #general (200 members), #cust-acme (a
Slack Connect channel with an external company), and a private #leadership.

| The agent tries to... | Outcome | Why (the fact that decided it) |
| --- | --- | --- |
| Read #sentinel-dev, post "build is green" there | Standing: runs, audited | In the standing set; internal; 6 members |
| Read #general | Standing: runs | Read is in the standing set |
| Post in #general | Task needed (one click); and the post asks again once the task exists | Outside standing; 200 members is over the breadth line, so it is also dangerous |
| Read #cust-acme | Task needed (one click) | Not in the standing set; exposure is confidential |
| Post in #cust-acme, even under a task that lists it | Confirm every time | `is_external_shared`: the effect leaves the company |
| Post in #leadership | Task needed; confirm too if private posting is marked dangerous | Not in standing set; `is_private` |
| Delete any message | Confirm every time | Irreversible |
| Post in a channel from another workspace | Block | Wrong workspace: never allowed |
| Read or change Sentinel's own config or token | Block | Never allowed on any host |

The same shape applies to the fixture (standing: read and note issues
`SPIKE-1` to `SPIKE-99`, narrower than Sentinel's fixed limit of `SPIKE-9999`
so that the "task needed" path stays testable; nothing in the fixture is
dangerous, so it is a regression bench only) and, later, to a repo (standing: read and edit under this folder; tasks
for a second repo; confirm for anything that runs, ships, or deletes broadly).
Note that Sentinel has no mediated file tool today, so the repo example is a
direction, not a Week 15 deliverable.

## What this changes elsewhere

- **Roadmap Week 16** becomes "Slack, owned mode": Sentinel-held bot token,
  a Connections page, a `slack_post_message` and `slack_read_channel` tool
  pair with the durable write lifecycle, a Slack tool family in the gateway
  and ceiling, and the dangerous-by-facts rules above. GitHub issue triage is
  dropped as the preferred proof.
- **Product Architecture** still lists the pre-September-11 weekly headlines
  (Week 14 as write budget, Week 15 as transition drafts, Week 16 as GitHub);
  it is updated on Day 1 of Week 15 alongside the Roadmap.
- **Threat model v2** (Week 15 Part 2) is written against *this* scope: an
  agent inside a Slack workspace and a repo, not against the fixture.

## Kill conditions

- If Claude Code's managed settings can be undone by the agent in the spike
  under the named configuration (its sandbox on, edits to `~/.claude/`
  denied), Claude Code is labelled advisory and the plan says so before Part 3
  starts. Sentinel's posture is then "mandatory on Cursor under its tested
  configuration; advisory elsewhere until proven".
- If a seeded Slack Connect, private, or guest channel *returns* facts that do
  not classify it (in particular `is_ext_shared` and member classification for
  a Connect channel), "dangerous by facts" is not yet true for Slack, and Week
  16 is re-planned before any provider code is written. A case that could not
  be seeded is recorded as *not tested* and does not trip this.
- If a standing permission can be widened by anything except the protected
  Settings flow, or a task can keep authority after it expires that the
  standing set did not grant, the build reverts to activation-per-task.

## What I need from you

1. Approve or change the four decisions above (owned-only; Slack first; Cursor
   plus Claude Code; two-axis resource scope with block checked first).
2. Create a disposable Slack workspace, start a Pro trial on it, and create an
   app with a bot token holding `team:read`, `channels:read`, `groups:read`,
   `users:read`, `chat:write`. Seed one private channel (invite the bot), one
   guest account in a channel, and one Slack Connect channel with a second
   throwaway workspace. Keep the token in the one local environment variable
   the spike names and nowhere else.
3. Confirm Claude Code is installed, note its version, and confirm you are
   willing to place a `managed-settings.json` and a `managed-mcp.json` under
   `~/.claude/` for the spike, with Claude Code's sandbox on.
