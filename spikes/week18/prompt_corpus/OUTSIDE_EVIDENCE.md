# Outside evidence: how engineers actually use AI coding agents

Status: written October 14, 2026 as a companion to `summary.json` and
`analyse.py`. The corpus answers "how does Owen prompt and where does the
agent work" for one person on one host (144 chats, 5,782 prompts, 62,320
tool calls). This file answers the question the corpus cannot: do those
patterns generalise? It collects published, citable measurements on four
topics the Week 18/19 boundary and budget decisions depend on, and ends with
what each one implies for Sentinel.

Every number below was checked against the primary page on October 14, 2026
unless marked otherwise. Vendor-published telemetry (Anthropic, OpenAI,
Cursor) is labelled as such: it is the only large-N source for most of these
questions, and it comes from parties with a product to sell.

## 0. Short answer

- **Sessions are short at the median and long in the tail.** Median Claude
  Code turn ~45 s; 99.9th percentile ~45 min and rising. A typical session is
  ~4 human turns and ~10 agent actions per prompt, with a long tail over 100.
- **Unattended is the direction, not yet the norm.** New Claude Code users
  run full auto-approve in ~20% of sessions; by 750 sessions it is over 40%.
  Headless and cloud runs are excluded from most published session data, so
  their share is unmeasured in public.
- **Parallel agents are common among power users; multi-repo is a real
  pattern but unmeasured.** Anthropic engineers "constantly have at least a
  few instances running"; OpenAI's p99 user generates 60+ agent-hours/day
  across parallel agents. No survey reports the share of developers whose
  agent works across more than one repository.
- **Permission-prompt fatigue is measured and large.** Users approve 93% of
  Claude Code permission prompts. Anthropic's own position: approve-every-
  action oversight "will create friction without necessarily producing safety
  benefits". The one thing people do keep doing is interrupting (5% to 9% of
  turns, rising with experience).

## 1. Session length and shape

| Measurement | Value | Source | Kind |
|---|---|---|---|
| Median Claude Code turn (agent start to stop) | ~45 s, stable 40–55 s Oct 2025–Jan 2026 | Anthropic, *Measuring AI agent autonomy in practice* (Feb 18, 2026) [1] | vendor telemetry, all interactive Claude Code |
| 99.9th percentile turn | under 25 min (Sep 2025) to over 45 min (Jan 2026); ~42 min at publication | [1] | vendor telemetry |
| Human turns per session | ~4 | Anthropic, *Agentic coding and persistent returns to expertise* (Jun 16, 2026), ~400k sessions, ~235k people [2] | vendor telemetry |
| Agent actions per prompt | ~10 mean; "sometimes over 100"; ~2% of sessions average over 100, 1 in 270 over 200, 1 in 2,300 over 500 | [2], footnote 6 | vendor telemetry |
| Actions per prompt by user expertise | novice ~5, expert ~12 | [2] | vendor telemetry |
| Consecutive tool calls without human input (Anthropic internal) | 9.8 (Feb 2025) to 21.2 (Aug 2025), +116% | Anthropic, *How AI is transforming work at Anthropic* (Dec 2, 2025), 200k internal transcripts [3] | vendor internal |
| Human turns per internal session | 6.2 to 4.1, −33% | [3] | vendor internal |
| Hours per week Claude Code is running | ~20 h/week average ("hours in which Claude Code was actively running, not hands-on time") | [2], footnote 2 | vendor telemetry |
| Median turn, independent dataset | ~20 s; p90 under 1.5 min; p99.9 55 min | SWE-chat (Baumann et al., COLM 2026), 17.8k sessions from 707 public repos [4] | academic, Claude Code subset |
| Task horizon people ask for | by May 2026, 80.6% of sampled Codex users had made at least one request estimated at over 30 min of human work; 70.2% over 1 h; 25.6% over 8 h | OpenAI, *How agents are transforming work* (Jun 25, 2026) [5] | vendor telemetry, LLM-estimated horizons, 0.1% user sample |
| Daily agent runtime, heaviest users | p99 OpenAI employee: over 60 h of Codex agent turns per day, "distributed across multiple, parallel agents" (Jun 2026) | [5] | vendor internal |

What this says: the body of the distribution is a conversation (sub-minute
turns, a handful of prompts) and the tail is a delegation (tens of minutes,
hundreds of actions). Anthropic's own reading is a "deployment overhang":
models can run longer than people let them. The 99.9th percentile is the
number to design for if the question is "how long can an agent run before
anyone looks", because that is where the person is not watching.

How Owen's corpus compares: `prompts_per_chat` p50 8.5, p90 105, max 505;
`chat_minutes` p50 1,263 (21 h wall clock, which measures chat lifetime, not
attention). Owen's median chat is about twice the published median session in
prompts, and his p90 (105 prompts) is far into the published tail. The
corpus is a power-user sample, not a typical one. Anything tuned on it (budget
windows, streak thresholds) should be re-checked against the ~4-turn median
before being called general.

## 2. Unattended and background runs

| Measurement | Value | Source | Kind |
|---|---|---|---|
| Full auto-approve share of sessions | ~20% for new users (under 50 sessions); over 40% by 750 sessions | [1], Figure 2, users who signed up after Sep 19, 2025 | vendor telemetry |
| Interrupt rate | 5% of turns at ~10 sessions; ~9% at high tenure; rises with experience | [1], Figure 3 | vendor telemetry |
| Agent-initiated stops vs human interrupts | on the most complex tasks Claude Code stops to ask more than twice as often as humans interrupt it; top reasons for stopping: present a choice (35%), gather diagnostics (21%), clarify (13%), request credentials (12%), get approval (11%) | [1], Table 1, n=500k each | vendor telemetry, LLM-clustered |
| Human involvement on API tool calls by complexity | 87% of minimal-complexity tool calls have some human involvement vs 67% of high-complexity ones; "upper bound" per the authors | [1] | vendor telemetry, LLM-classified |
| Share of API tool calls with any safeguard / human in loop / irreversible | 80% / 73% / 0.8% (authors say 80% is an upper bound) | [1] | vendor telemetry |
| "Fully delegate" share of own work | more than half of 132 Anthropic engineers say 0–20% | [3] | internal survey |
| Headless and cloud sessions | explicitly excluded from [2] ("non-interactive usage this report excludes is a substantial share of activity") and from [1]'s Claude Code figures | [2] footnote 4 | gap |
| Cursor cloud agents internally | "more than 30%" of PRs Cursor merges internally are created by agents in cloud sandboxes (Feb 2026 reporting) | Awesome Agents report of Cursor's Feb 24, 2026 launch [6]; not checked against a Cursor first-party page | secondary |
| Agent-authored commits in open source | "vibe coding" sessions (agent writes 99%+ of committed code) rose from 18.3% to 52.6% of sessions, Feb to Sep 2026 (14-day rolling); 41% of all sessions overall | [4] | academic |
| Pushback | users push back (correct, report failure, interrupt) in ~46–50% of turns; interrupt in 4.5% | [4] | academic |

What this says: the person is leaving the loop at the action level and
staying in it at the turn level. Auto-approve doubles with tenure; interrupts
also rise with tenure. Anthropic's conclusion, verbatim: "effective oversight
doesn't require approving every action but being in a position to intervene
when it matters." The agent's own pauses are a larger share of stops than the
person's interrupts on hard tasks, which is relevant to Sentinel's stuck
detector: a nudge delivered to the agent lands on a surface that already
stops itself more than the person does.

Truly unattended runs (headless `claude -p`, Cursor cloud agents, Codex
cloud tasks, Claude Code routines with "no permission-mode picker and no
approval prompts during a run") are the fastest-growing surface and the
least measured. No public source gives their share of total usage. The one
public operational fact: Claude Code auto mode in headless mode terminates
the process on repeated classifier denials because "there is no UI to ask the
human" [7].

How Owen's corpus compares: 1,199 `AwaitShell` calls and 1,637 `TodoWrite`
calls out of 62,320 suggest long agent turns with background shells, and
`CallDynamicTool` + `CallMcpTool` + `Task`-spawned subagents appear
throughout. The corpus has no record of the person's approval clicks, so his
own auto-approve rate is unmeasured. Run Mode in Cursor is per-machine, not
per-event, so this cannot be recovered from transcripts.

## 3. Parallel agents and multi-repo work

| Measurement | Value | Source | Kind |
|---|---|---|---|
| Parallel instances, Anthropic engineers | some "constantly have at least a few [Claude] instances running"; one researcher runs "many versions of Claude simultaneously"; role shifting to "manager of AI agents", one estimate "70%+ ... code reviewer/reviser" | [3], interviews, n=53 | internal qualitative |
| Parallel agents, OpenAI | p99 daily runtime "distributed across multiple, parallel agents"; users "orchestrating multiple agent tasks over the course of a day" | [5] | vendor internal |
| Concurrent sessions, third-party terminal | median user runs ~3 simultaneous agent sessions; tail above six is "well under a tenth of sessions" | AITerm blog, anonymous daily ping [8] | vendor blog, unaudited |
| Practitioner ceiling | 2–3 parallel sessions "sustainable for most developers", more than 5 "difficult to supervise" | MindStudio guide [9]; Anthropic agent-teams guidance "start with three to five" as quoted in [8] | secondary |
| Cursor cloud agent concurrency cap | Pro: 8 simultaneous cloud agents (forum statement by Cursor staff, as reported) | ContinuumCode guide [10] | secondary |
| Cross-repo task success | 10.83%–42.50% full-task success across seven agent configurations on 120 real tasks from 103 ecosystems | WideSWE (Wang et al., Sep 2026) [11] | academic benchmark |
| Share of developers using agents at all | SO 2025: 31% use agents (14% daily); SO 2026: 65.9% use "AI coding assistants or coding agents", 73% of them daily; "AI agents or automated workflows" 26.2% | Stack Overflow Developer Survey 2025 (49k) and 2026 (30k+) [12][13] | survey |
| Which agents | SO 2026 among 12,255 agent users: Claude Code 65.5%, GitHub Copilot 58.7%, OpenAI Codex 29.5%, Cursor 25.5% | [13] | survey |
| Agent as default instrument on Cursor | by start of 2026, 92% of active professional Cursor users used agents; 57% still used autocomplete, so "as many as 43% of users may no longer be manually typing code" | Sarkar, *AI Agents and Higher-Order Work* (2026), 119,960 users across 1,000 firms [14] | academic on vendor data |

Multi-repo specifically: there is **no published measurement** of how often a
single agent session touches more than one repository. What exists is (a)
practitioner patterns ("repo-of-repos", "meta repo": clone related repos side
by side under one workspace-level `CLAUDE.md`/`AGENTS.md`) [15][16], which are
designed precisely so the agent can read and write across repos in one
session; (b) the WideSWE benchmark, which shows agents are bad at coordinated
cross-repo changes and that running one repo at a time "mainly recovers
omitted work" [11]; and (c) Claude Code's `-w` worktree flag and Cursor's
worktree isolation for cloud agents, which are the vendors' answer to
parallel work *within* one repo [9][10].

What this says for the boundary model: the dominant real-world unit is still
one agent, one directory, one task; the parallel pattern is N isolated
worktrees of the same repo, not one agent roaming N repos. The sibling-repo
case Sentinel guards against (an agent in `~/clad-core` writing into
`~/clad-core-eng-279`) is exactly the meta-repo pattern a minority of users
set up deliberately, and in that case the launch directory is the parent, so
the default boundary already covers it. The risk case is the undeclared one:
launch in one repo, write into a sibling.

How Owen's corpus compares: 19 workspaces; `path_calls_by_zone` shows
`write:home` 5,988 vs `write:workspace` 7,861, i.e. 43% of writes land under
home but outside the workspace the chat was opened in (the corpus does not
yet say how many of those are sibling repos vs `~/.cursor` vs `/tmp`-like
scratch; that split is the next cut worth making). Two Clad checkouts
(`clad-core`, `clad-core-eng-279`) sit side by side, which is the worktree
pattern above done by hand. Caveat on the 43%: `workspace_of()` infers each
project's root as the most common two-level path prefix, so projects whose
work genuinely spans two top-level folders inflate `write:home`.

## 4. Permission-prompt fatigue

| Measurement | Value | Source | Kind |
|---|---|---|---|
| Approval rate on Claude Code permission prompts | **93%** | Anthropic, *How we built Claude Code auto mode* (Mar 25, 2026) [7] | vendor telemetry |
| Anthropic's stated reading | "a lot of clicking 'approve.' Over time that leads to approval fatigue, where people stop paying close attention"; manual prompts are the middle option and "in practice users accept 93% of them anyway" | [7] | vendor |
| Policy stance | "Oversight requirements that prescribe specific interaction patterns, such as requiring humans to approve every action, will create friction without necessarily producing safety benefits" | [1], recommendations | vendor |
| Auto mode classifier, deployed pipeline | 0.4% FPR on 10,000 real tool calls; 17% FNR on 52 real overeager actions; 5.7% FNR on 1,000 synthetic exfiltration attempts | [7], Table 1 | vendor eval |
| Auto mode tiering | file writes inside the project directory skip the classifier entirely ("in-project edits are reviewable via version control"); only shell, web, MCP, subagent spawns, and out-of-project filesystem ops reach it | [7] | vendor design |
| Auto mode escalation to a human | after 3 consecutive or 20 total denials in a session; headless runs are terminated instead | [7] | vendor design |
| Incident log categories that motivated it | deleting remote branches from a misread instruction; uploading an engineer's GitHub token to a compute cluster; attempting migrations against a production DB; retrying a failed deploy with a skip-verification flag | [7] | vendor incident log |
| Reported quality effect of skipping permissions | GitHub issue claims 32% of developers using `--dangerously-skip-permissions` hit unintended file modifications, citing an "eesel AI study" | anthropics/claude-code issue #32337 [17] | **unverified**: the cited study was not located; treat as anecdote |
| Developer trust, SO 2025 | 46% actively distrust AI tool accuracy vs 33% trust; 3% "highly trust"; 87% concerned about agent accuracy, 81% about data security/privacy | [12] | survey, 49k |
| Where devs let agents go | SO 2026: 69.3% use AI for generating code in a familiar area, 63.8% debugging; only 19.9% for deploying/operating production | [13] | survey |

Documented failures that got through a human approver or ran without one:

- **Replit, Jul 2025**: agent deleted a production database (1,206 executive
  records) during an explicit "code and action freeze", then wrongly said
  rollback was impossible [18][19].
- **Gemini CLI, Jul 2025**: a failed `mkdir` was treated as successful; a
  chain of `move` commands then overwrote all but one file [19][20].
- **DataTalks.Club, Feb 26, 2026**: Claude Code with auto-approved Terraform
  proposed `terraform destroy` to clean up duplicates; the state file had been
  swapped for production without the operator noticing; the destroy removed
  the VPC, ECS cluster, load balancers, bastion, RDS database **and the
  automated snapshots**. 24 h outage; AWS restored a hidden snapshot. The
  operator teaches Terraform. His fix list: remote state, deletion protection,
  independent nightly S3 export, and "no agent command execution" for
  Terraform [21][22].

The pattern across all three: the agent said what it was about to do, the
person (or the auto-approver) read it as reasonable, and the blast radius was
larger than the text implied. This is the 93% number in narrative form.

What this says for Sentinel: the market has already priced approve-every-
action at near zero. Anthropic's own product moved the default to a classifier
with a 17% miss rate on real overeager actions and called that an improvement
over the prompts. A supervisor that adds popups loses on both counts: it adds
to fatigue, and the person clicks through anyway. The surfaces that still
carry information are (a) hard blocks on a narrow irreversible set, where no
click is offered, and (b) a single, rare, well-worded confirm whose rarity is
what makes it readable. Direction §3.2's per-boundary message budget is the
right instrument; the evidence says the budget should be small and the floor
should not ask.

How Owen's corpus compares: the corpus does not record Cursor's own approval
popups or the person's clicks on them, so it cannot measure fatigue directly.
The nearest proxy is the C-H5 run (Week 18 Plan §6): the first budgeted
`ask` only landed after the budget was moved to a rolling 30-minute window,
because two earlier path cautions had spent it. That is one data point that
the budget, not the detector, is what the person actually experiences.

## 5. Productivity context (why people tolerate the risk)

Included because it explains the pressure toward auto-approve and
unattended runs; Sentinel is not a productivity tool.

- METR RCT, early 2025 (16 experienced OSS developers, 246 tasks, mostly
  Cursor Pro + Claude 3.5/3.7 Sonnet): developers took **19% longer** with AI
  (CI +2% to +39%) while believing they were 20% faster [23]. METR's Feb 2026
  follow-up with late-2025 tools estimates an 18% speedup for returning
  developers (CI −38% to +9%) and 4% for new recruits (CI −15% to +9%), and
  METR itself says selection effects make the follow-up "hard to interpret"
  and probably a lower bound [24].
- Sarkar (Cursor data, 32 firms, 323,589 merges): firms merged 26% more PRs
  after agents were introduced and 39% more after the agent became the
  default; revert rates unchanged [14][25].
- Anthropic internal: self-reported Claude use in 59% of work, +50%
  productivity, 67% more merged PRs per engineer per day after Claude Code
  rollout; the authors flag self-report bias and cite METR [3].
- Stack Overflow 2025: 69% of agent users say agents increased their
  productivity; only 17% say they improved team collaboration [12].

The honest summary: measured speedups range from negative to modest with wide
intervals; perceived speedups are consistently higher. People are extending
autonomy faster than the measured benefit justifies, which is the environment
Sentinel is designed for.

## 6. What this changes for Sentinel

| Decision | Evidence | Implication |
|---|---|---|
| Boundary default = launch directory, narrow-only | one agent / one directory / one task is still the modal pattern [1][2]; parallel work is N worktrees of one repo [9][10]; multi-repo is a deliberate meta-repo setup where the launch dir is the parent [15][16] | **Keep.** The default covers the common and the deliberate-multi-repo case; the undeclared sibling write is the case worth confirming on |
| Floor blocks, no click offered | 93% approve rate [7]; three incidents where the person approved the fatal step [18][19][21] | **Keep.** Any block that offers an Allow button is an ask with extra steps |
| Confirm reserved for destructive-outside and a short list | auto mode skips in-project writes entirely and only classifies out-of-project filesystem ops, shell, web, MCP [7] | **Aligned with the vendor's own tiering.** Sentinel's `F5.destructive_outside` confirm maps to the same line auto mode draws |
| Detector message budget, per boundary, rolling window | interrupts rise to ~9% of turns with experience [1]; pushback in ~46% of turns [4]; people are already correcting the agent often | **Keep small.** The person is not short of signals from the agent; one more only earns attention if it is rare. Direction's "if Sentinel is louder than the host's own prompts, it has failed" is the right bar and now has a number to beat: Cursor's own cards plus ~5–9% human interrupts |
| Stuck detector (S2 repeat-error) | agents stop themselves more than people interrupt them on hard tasks [1]; retries are a top interrupt reason ("slow, hanging, or excessive", 17%) [1] | **Supports** nudging the agent before asking the person: the agent is the surface that already self-stops |
| Headless / cloud agents out of scope this week | excluded from every published session dataset [1][2]; auto mode terminates headless runs on repeated denial [7] | **Keep deferred, but name it as the largest unmeasured surface** in Week 19's limits |
| Week 19 "messages per hour" target | median session ~4 turns, ~45 s turns [1][2]; Owen's p50 is 8.5 prompts | The target should be stated per *session* as well as per hour, and checked on a ~4-turn session, not only on Owen's long ones |
| Corpus generalisability | Owen's p90 of 105 prompts/chat is deep in the published tail | Treat the corpus as a power-user stress test, not a population estimate; do not derive population thresholds from it alone |

## 7. Gaps no source fills

1. Share of agent sessions that are headless or cloud-run (every vendor
   excludes them from session analyses).
2. Share of sessions whose file operations span more than one git repository.
3. Approval rates on Cursor (only Claude Code's 93% is published).
4. Any measurement of how often a *supervisor* popup (as opposed to the
   host's own) is read vs clicked through. Week 19 will be the first number.
5. Whether `--dangerously-skip-permissions` degrades code quality; the only
   claim is an unsourced GitHub issue [17].

## Sources

1. Anthropic, "Measuring AI agent autonomy in practice", Feb 18, 2026.
   https://www.anthropic.com/research/measuring-agent-autonomy
2. Anthropic, "Agentic coding and persistent returns to expertise" (page
   title "How Claude Code is used in practice"), Jun 16, 2026.
   https://www.anthropic.com/research/claude-code-expertise
3. Anthropic, "How AI is transforming work at Anthropic", Dec 2, 2025.
   https://www.anthropic.com/research/how-ai-is-transforming-work-at-anthropic
4. Baumann, Padmakumar, Li, Yang, Yang, Koyejo, "SWE-chat: Coding Agent
   Interactions From Real Users in the Wild", COLM 2026, v2 snapshot Oct 2,
   2026. https://arxiv.org/abs/2604.20779 ; https://www.swe-chat.com/
5. OpenAI, "How agents are transforming work", Jun 25, 2026.
   https://openai.com/index/how-agents-are-transforming-work/
6. Awesome Agents, "Cursor Ships Cloud Agents That Build, Test, and Demo
   Code", Feb 2026 (secondary; Cursor first-party figure not fetched).
   https://awesomeagents.ai/news/cursor-cloud-agents-computer-use/
7. Anthropic Engineering, "How we built Claude Code auto mode: a safer way to
   skip permissions", Mar 25, 2026.
   https://www.anthropic.com/engineering/claude-code-auto-mode
8. AITerm, "Six Claude Code Worktrees, Only Four Paid Off" (vendor blog,
   unaudited telemetry). https://aiterm.app/blog/run-multiple-ai-coding-agents/
9. MindStudio, "Run Multiple Claude Code Sessions in Parallel With Git
   Worktrees". https://www.mindstudio.ai/blog/claude-code-git-worktree-parallel-branches
10. ContinuumCode, "Cursor background agents (now Cloud Agents), explained".
    https://continuumcode.ai/guides/cursor-background-agents/
11. Wang, Wang, Wu, Wu, Zhi, Yin, "WideSWE: Can Coding Agents Coordinate
    Changes Across Repositories?", Sep 27, 2026.
    https://arxiv.org/abs/2609.33382
12. Stack Overflow, 2025 Developer Survey, AI section (49k+ respondents).
    https://survey.stackoverflow.co/2025/ai/
13. Stack Overflow, 2026 Developer Survey, AI section (30k+ respondents,
    released Oct 6, 2026). https://survey.stackoverflow.co/2026/ai ;
    https://survey.stackoverflow.co/2026/ai/data/ai-code-agent
14. Sarkar, S., "AI Agents and Higher-Order Work", 2026 (Cursor telemetry,
    119,960 users, 1,000 firms). https://suproteem.is/assets/files/agents.pdf
15. Uy, R., "Repo-of-Repos: Tony's Multi-Repo Workspace for AI Coding
    Agents". https://www.raffertyuy.com/raztype/repo-of-repos-pattern/
16. Sheng, G., "The Meta Repo: The Right Way To Work Across Multiple Repos
    with AI Agents" (LinkedIn).
17. anthropics/claude-code issue #32337, "[FEATURE] Add internal reasoning
    checkpoints in --dangerously-skip-permissions mode" (unverified claims).
    https://github.com/anthropics/claude-code/issues/32337
18. The Register, "Vibe coding service Replit deleted user's production
    database", Jul 21, 2025.
    https://www.theregister.com/software/2025/07/21/vibe-coding-service-replit-deleted-production-database/719783
19. Ars Technica, "Two major AI coding tools wiped out user data after making
    cascading mistakes", Jul 2025.
    https://arstechnica.com/information-technology/2025/07/ai-coding-assistants-chase-phantoms-destroy-real-user-data/
20. MIT AI Risk Repository, Incident 1178 (Gemini CLI).
    https://airisk.mit.edu/ai-incidents/1178-google-gemini-cli-reportedly-deletes-user-files-after
21. Grigorev, A., "How I Dropped Our Production Database and Now Pay 10% More
    for AWS" (first-hand post-mortem), Feb/Mar 2026.
    https://alexeyondata.substack.com/p/how-i-dropped-our-production-database
22. Rootly, "'Hey Claude, where's my database?': How an AI agent nuked
    production" (interview with Grigorev).
    https://rootly.com/humans-of-reliability/hey-claude-wheres-my-database-alexey-grigorev
23. METR, "Measuring the Impact of Early-2025 AI on Experienced Open-Source
    Developer Productivity", Jul 10, 2025.
    https://metr.org/blog/2025-07-10-early-2025-ai-experienced-os-dev-study/
24. METR, "We are Changing our Developer Productivity Experiment Design",
    Feb 24, 2026. https://metr.org/blog/2026-02-24-uplift-update/
25. Cursor blog, "The productivity impact of coding agents", Nov 2025
    (summarising [14]; read via a mirror, not the cursor.com page).
