"""The deterministic floor: facts in, one verdict out.

`extract` turns a shell command into the paths it touches and the zone each
path lands in. `rules` turns that report (plus the launch directory, the
environment, and server-owned session history) into a `Finding`. `paths`
judges a single absolute path for the file tools; `patch` judges every path
an `ApplyPatch` names the same way. `record` turns a finding into the typed
`DecisionRecord` the audit store persists.

Ported from the Week 15 gates (`spikes/week15/gate2a`, `gate2b`), which
measured these rules at 15/15 incidents, 26/26 held-out, 0/120 benign twins.
"""

from sentinel.floor.extract import Report, Target, analyze, zone_of
from sentinel.floor.patch import PatchFile, decide_patch, parse_patch
from sentinel.floor.paths import decide_path
from sentinel.floor.rules import Finding, History, decide_shell

__all__ = [
    "Finding",
    "History",
    "PatchFile",
    "Report",
    "Target",
    "analyze",
    "decide_patch",
    "decide_path",
    "decide_shell",
    "parse_patch",
    "zone_of",
]
