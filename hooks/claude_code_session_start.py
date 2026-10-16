#!/usr/bin/env python3
"""Shim: the SessionStart hook lives in the package so the installed Sentinel
and the hook never drift. Run with Sentinel's interpreter."""

import runpy

runpy.run_module("sentinel.hosts.claude_code.session_start_hook", run_name="__main__")
