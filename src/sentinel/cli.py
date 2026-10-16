"""`sentinel` command line.

    sentinel serve [--state-db PATH] [--port N] [--environment DIR=ENV ...]
    sentinel claude-code install
    sentinel claude-code doctor
    sentinel claude-code launchd
    sentinel cursor install
    sentinel cursor doctor

`serve` runs the hook server: the floor policy is built from the flags,
bound to the state database, and the Claude Code routes are mounted on the
API. There is no form to fill before work starts.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from sentinel.supervision.floor_policy import FloorPolicy, FloorPolicyError, HookExpectations


def build_policy(args: argparse.Namespace) -> FloorPolicy:
    environments: dict[str, str] = {}
    for item in getattr(args, "environment", None) or []:
        directory, _, environment = item.partition("=")
        environments[os.path.normpath(os.path.expanduser(directory))] = environment
    hook = HookExpectations(server_url=f"http://127.0.0.1:{args.port}/hooks/claude-code/pre-tool-use")
    return FloorPolicy(
        environments=environments,
        log_only_rules=frozenset(getattr(args, "log_only", None) or []),
        ask_fallback_modes=frozenset(getattr(args, "ask_fallback_mode", None) or []),
        hook=hook,
        sentinel_port=args.port,
    )


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from sentinel.api.main import create_app
    from sentinel.audit import SQLiteAuditStore
    from sentinel.hosts.claude_code import ClaudeCodeHookService
    from sentinel.hosts.cursor.service import CursorHookService
    from sentinel.supervision.floor_policy import SQLiteFloorPolicyStore

    policy = build_policy(args)
    state_db = Path(args.state_db).expanduser()
    state_db.parent.mkdir(parents=True, exist_ok=True)
    try:
        SQLiteFloorPolicyStore(state_db).bind(policy)
    except FloorPolicyError as exc:
        print(f"refusing to start: {exc}", file=sys.stderr)
        return 2
    os.environ.setdefault("SENTINEL_STATE_DB", str(state_db))
    audit_store = SQLiteAuditStore(state_db)
    service = ClaudeCodeHookService(policy=policy, audit_store=audit_store)
    cursor = CursorHookService(policy=policy, audit_store=audit_store)
    app = create_app(audit_store=audit_store, claude_code_service=service, cursor_service=cursor,
                     hook_api_host=f"127.0.0.1:{args.port}", load_policy=False)
    print(f"sentinel: floor policy {policy.content_sha256[:12]} bound to {state_db}", file=sys.stderr)
    print(f"sentinel: Claude Code hooks at {policy.hook.server_url}", file=sys.stderr)
    print(f"sentinel: Cursor hooks at http://127.0.0.1:{args.port}/hooks/cursor/<event>", file=sys.stderr)
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
    return 0


def cmd_install(args: argparse.Namespace) -> int:
    from sentinel.hosts.claude_code.install import install_text

    print(install_text(build_policy(args), python=sys.executable), end="")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    from sentinel.hosts.claude_code.install import doctor

    result = doctor(build_policy(args), probe=not args.no_probe)
    print("\n".join(result.lines))
    return 0 if result.ok else 1


def cmd_launchd(args: argparse.Namespace) -> int:
    from sentinel.hosts.claude_code.install import LAUNCHD_LABEL, launchd_plist

    state_db = Path(args.state_db).expanduser()
    plist_path = Path.home() / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"
    print(launchd_plist(python=sys.executable, state_db=state_db, port=args.port, log_dir=state_db.parent))
    print(f"# Save as {plist_path} then: launchctl load -w \"{plist_path}\"", file=sys.stderr)
    return 0


def cmd_cursor_install(args: argparse.Namespace) -> int:
    from sentinel.hosts.cursor.install import InstallError, install, which_python

    try:
        result = install(port=args.port, python=which_python())
    except InstallError as exc:
        print(f"refusing to install: {exc}", file=sys.stderr)
        return 2
    print("\n".join(result.lines))
    return 0


def cmd_cursor_doctor(args: argparse.Namespace) -> int:
    from sentinel.hosts.cursor.install import doctor

    roots = [os.path.abspath(r) for r in (args.workspace_root or [])] or None
    result = doctor(port=args.port, probe=not args.no_probe, workspace_roots=roots)
    print("\n".join(result.lines))
    return 0 if result.ok else 1


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(name)s: %(message)s")
    parser = argparse.ArgumentParser(prog="sentinel")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--port", type=int, default=int(os.environ.get("SENTINEL_PORT", "8000")))
        p.add_argument("--state-db", default=os.environ.get("SENTINEL_STATE_DB") or str(Path.home() / ".sentinel" / "state.sqlite3"))
        p.add_argument("--environment", action="append", metavar="DIR=ENV",
                       help="treat launches under DIR as ENV (dev, sandbox, staging, production)")
        p.add_argument("--log-only", action="append", metavar="RULE_ID",
                       help="record but do not enforce this rule (F1-F4 and supervisor rules cannot be log-only)")
        p.add_argument("--ask-fallback-mode", action="append", metavar="PERMISSION_MODE",
                       help="permission modes where a confirm is delivered as a deny with guidance")

    serve = sub.add_parser("serve", help="run the hook server")
    common(serve)
    serve.set_defaults(func=cmd_serve)

    claude = sub.add_parser("claude-code", help="Claude Code hook adapter")
    claude_sub = claude.add_subparsers(dest="claude_command", required=True)
    install = claude_sub.add_parser("install", help="print the managed settings fragment and placement steps")
    common(install)
    install.set_defaults(func=cmd_install)
    doctor_p = claude_sub.add_parser("doctor", help="check whether the hook is locked (exit 0 only when mandatory)")
    common(doctor_p)
    doctor_p.add_argument("--no-probe", action="store_true", help="do not probe the Sentinel port")
    doctor_p.set_defaults(func=cmd_doctor)
    launchd = claude_sub.add_parser("launchd", help="print a launchd plist that keeps `sentinel serve` running")
    common(launchd)
    launchd.set_defaults(func=cmd_launchd)

    cursor = sub.add_parser("cursor", help="Cursor hook adapter")
    cursor_sub = cursor.add_subparsers(dest="cursor_command", required=True)
    c_install = cursor_sub.add_parser("install", help="write the forwarder script and merge the user-level Cursor hooks file")
    common(c_install)
    c_install.set_defaults(func=cmd_cursor_install)
    c_doctor = cursor_sub.add_parser("doctor", help="check the Cursor hook install (exits 1: Cursor enforcement is advisory by nature)")
    common(c_doctor)
    c_doctor.add_argument("--no-probe", action="store_true", help="do not probe the Sentinel port or run the synthetic event")
    c_doctor.add_argument("--workspace-root", action="append", metavar="DIR",
                          help="the folder(s) open in Cursor; given twice or more, doctor warns that only the first is used")
    c_doctor.set_defaults(func=cmd_cursor_doctor)

    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except FloorPolicyError as exc:
        print(f"invalid floor policy: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
