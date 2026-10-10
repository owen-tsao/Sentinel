# Gate 2a results — target extraction on real agent shell commands

Run: 2026-10-09. Corpus: 18,551 unique `Shell` tool commands issued by Cursor
agents across 21 of the user's projects (recovered from local Cursor
transcripts; the roadmap asked for 200 from Claude Code sessions, but the
user does not use Claude Code, so the host was swapped, not the realism).
Parser: `bashlex` (isolated via `uv run --with bashlex`; not yet a project
dependency). Reproduce: `uv run --python 3.12 --with bashlex python run.py
<corpus.json>`. The raw corpus is not checked in (it contains real paths and
personal project detail); `summary.json` holds the numbers.

## Verdict: pass. Proceed to Gate 2b.

Kill condition was: more than 1 in 20 benign commands unclassifiable (fail
closed). Measured: **0.5% unparseable** (89 of 18,551), ten times under the
line. Every unparseable command is one of three `bashlex` gaps: `time cmd`
(bash keyword), `$((...))` arithmetic, or `$(...)` nested inside `[ ]`.

| Bucket | Count | Share | Meaning for the floor |
|---|---|---|---|
| benign | 14,549 | 78.4% | no destructive verb visible; observe and allow |
| opaque | 2,755 | 14.9% | real action is inside a string or stdin (`python3 -c`, `node -e`, heredoc program, `xargs`, `$VAR` executable); floor observes, cannot judge targets |
| destructive, target resolved | 1,158 | 6.2% | the floor can judge inside/outside |
| unparseable | 89 | 0.5% | parser gap; fail open with an `observe` audit row, not fail closed |

## What the corpus looks like (the shipped canonicalizer could not see it)

- 88% compound (`&&`, `;`, `|`); 19% multiline; 12% heredocs; 8% inline
  interpreter programs. The 14-command whitelist would have rejected roughly
  nine in ten real commands. The floor must be allow-by-default with a
  deny-list of destructive shapes, not a whitelist.
- Heredocs are the single biggest parser obstacle (2,190 of 2,277 raw
  `bashlex` failures). Stripping the body to `</dev/null` before parsing fixed
  all of them; the body is data, and the receiving command (`python3 -`,
  `psql`) is flagged opaque instead.
- Destructive verbs, by frequency: `> redirect` 785, `rm` 758, `mv` 150,
  `rmdir` 21, `git checkout --`/`restore` 31, `git reset --hard` 2,
  `git clean` 1, `git push --force` 1, `rsync --delete` 1.

## Where the destructive targets landed

| zone | delete | write |
|---|---|---|
| inside cwd | 518 | 347 |
| temp (`/tmp`, `/var/folders`) | 153 | 528 |
| outside cwd (same user) | 132 | 60 |
| dynamic (unresolvable) | 14 | 0 |
| home dir itself | 1 (cwd artifact) | 0 |
| root / system / protected config / credential | 0 | 0 |

**Would block: 2.** One is a corpus artifact (unknown project, cwd fell back
to `~`). The other is genuine: `rg aws_access_key_id ~/.aws/credentials | sed
's/=.*/= <redacted>/'`. The agent redacted the values, but the floor cannot
know that; reading the AWS key store is the right thing to stop and ask
about. Keep it as an eval case.

**Would confirm: 138** (132 deletes outside cwd + 6 remote file uploads).
Naively that is 138 interruptions over months of work, which fails the "not
louder than the host" rule. Two corrections, both from facts the hook already
has, bring it to **28 distinct questions**:

1. **Worktree-aware boundary (35 absorbed).** `clad-core-eng*` directories are
   `git worktree`s of `clad-core`. "The containing repository" must mean the
   worktree set. Read once at launch from `git worktree list`; no inference,
   no human input.
2. **Remember a confirm per (cwd, target) (64 collapsed to 1).** `rm -rf
   /Applications/briefly.app` appeared 64 times during one app's development.
   One question is right; 64 is Sentinel being the loudest thing in the room.

The 28 remaining are real cross-project edits (Sentinel session deleting
files in `clad-core`; `clad-core` session reshaping `buttercream-website`),
a LaunchAgent plist, a sibling-folder `rsync --delete`. Each deserves one
question.

## Findings that change the design

1. **Variables and globs are mostly recoverable.** Tracking `VAR=value` and
   judging a trailing glob by its directory cut unresolvable destructive
   targets from 77 to 14. The remaining 14 are all `$(mktemp -d)`; a tiny
   special case (`mktemp` → temp zone) would clear them.
2. **The floor cannot see inside `$(...)`.** `AK=$(aws configure get
   aws_secret_access_key); curl -X POST https://bedrock...` reads a secret and
   sends it, and the extractor saw neither, because the read lives in a
   command substitution `bashlex` treats as an opaque word. Fix: parse the
   contents of `$(...)` as a nested command list. Note for Gate 2b.
3. **Egress must mean "a local file leaves".** Treating any `-d` POST as
   egress flagged 37 commands, 31 of them inline-JSON job-board searches.
   Narrowing to `@file`, `-T`, `-F x=@`, `scp` left 6: PNG uploads to a GCS
   bucket. Correct to confirm; correct not to confirm the JSON.
4. **Project `.env` is not a credential store.** Agents copied, created, and
   deleted `.env` files constantly. The credential rule is for key stores
   (`~/.ssh`, `~/.aws`, `~/.gnupg`, `.netrc`, `.npmrc`, kube/gh/docker auth,
   `id_*`, `*.pem`) and tool-mediated reads (`aws configure get *secret*`,
   `security find-*-password`, `gh auth token`). `.example`/`.sample` are never
   secrets.
5. **Read-only use of a protected file is fine.** The Gate 1 false positive
   (`ls managed-settings.json` denied) is gone: protected-config is judged
   on the *operation* (write/delete/redirect) not on the name appearing.
6. **Opaque is a policy choice, not a parser bug.** 15% of real commands are
   `python3 -c`, `node -e`, heredoc programs, `xargs`, `osascript`. The floor
   should observe these (audit row, no interruption). Detectors in Week 17
   may look at them; the floor does not.
7. **The host gives the cwd for free.** Half the early noise was this spike
   guessing the launch directory from Cursor's flattened project names. A
   real hook receives `cwd` in the event payload.

## What bashlex still needs

`time` keyword, `$((...))`, `$(...)` inside `[ ]`, and parsing the inside
of command substitutions. Options for Week 16: patch around these four
shapes (pre-pass), or evaluate `tree-sitter-bash` which handles all of them.
Decision deferred to the adapter week; 0.5% does not block.
