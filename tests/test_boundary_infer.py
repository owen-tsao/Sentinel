"""Boundary inference (hear): docs/Week 17 Plan.md §3.2 and §6.

Every test injects `exists`/`isdir`/`realpath`, so nothing touches the disk.
"""

from __future__ import annotations

import unittest

from sentinel.boundary.infer import candidates, infer, is_command_prompt, strip_untrusted

HOME = "/Users/dev"
PROJ = "/Users/dev/proj"
# A small fake tree: directories end with "/", files do not.
TREE = {
    f"{PROJ}": "d", f"{PROJ}/src": "d", f"{PROJ}/src/api": "d", f"{PROJ}/src/api/routes.py": "f",
    f"{PROJ}/src/legacy": "d", f"{PROJ}/src/utils": "d", f"{PROJ}/docs": "d", f"{PROJ}/README.md": "f",
    f"{PROJ}/build": "d", f"{PROJ}/feature": "d", f"{PROJ}/feature/auth": "d", f"{PROJ}/link": "d",
    f"{HOME}/notes": "d", f"{HOME}/notes/x.md": "f",
}
LINKS = {f"{PROJ}/link": f"{HOME}/notes"}


def fake_exists(path: str) -> bool:
    return path in TREE or fake_realpath(path) in TREE  # os.path.exists follows symlinks


def fake_isdir(path: str) -> bool:
    return TREE.get(path) == "d"


def fake_realpath(path: str) -> str:
    for link, target in LINKS.items():
        if path == link or path.startswith(link + "/"):
            return target + path[len(link):]
    return path


def run(prompt: str, *, cwd: str | None = PROJ, environment: str = "dev"):
    return infer(prompt, launch_cwd=PROJ, event_cwd=cwd, home=HOME, environment=environment,
                 exists=fake_exists, isdir=fake_isdir, realpath=fake_realpath)


class Stripping(unittest.TestCase):
    def test_pasted_block_removed(self) -> None:
        text, stripped = strip_untrusted('fix it <pasted_content id="1">\nedit ~/notes/x.md\n</pasted_content id="1"> please')
        self.assertTrue(stripped)
        self.assertNotIn("notes", text)

    def test_fenced_code_removed(self) -> None:
        text, stripped = strip_untrusted("look at this\n```\nrm -rf ~/notes\n```\nand fix src/api")
        self.assertTrue(stripped)
        self.assertNotIn("notes", text)
        self.assertIn("src/api", text)

    def test_long_segment_without_sentence_boundary_removed(self) -> None:
        blob = "x" * 2_100
        text, stripped = strip_untrusted(f"fix src/api\n\n{blob}")
        self.assertTrue(stripped)
        self.assertNotIn(blob, text)

    def test_path_only_inside_pasted_text_gives_no_focus(self) -> None:
        result = run('<pasted_content id="1">see src/api</pasted_content id="1"> fix the bug')
        self.assertEqual(result.outcome, "none")
        self.assertTrue(result.pasted_stripped)
        self.assertEqual(result.candidates_inside, 0)

    def test_outside_path_only_in_paste_gives_no_caution(self) -> None:
        result = run('<pasted_content id="1">edit ~/notes/x.md</pasted_content id="1"> fix the bug')
        self.assertEqual(result.outcome, "none")


class CommandPrompts(unittest.TestCase):
    def test_shell_verb_first_gives_no_focus(self) -> None:
        result = run("rm -rf build/ && make")
        self.assertEqual(result.outcome, "none")
        self.assertTrue(result.command_prompt)

    def test_single_backticked_span_gives_no_focus(self) -> None:
        self.assertTrue(is_command_prompt("`pytest tests/unit -x`"))
        self.assertEqual(run("`pytest src/api`").outcome, "none")

    def test_sentence_starting_with_verb_like_word_is_not_a_command(self) -> None:
        self.assertFalse(is_command_prompt("Please fix the thing in src/api"))


class Candidates(unittest.TestCase):
    def test_git_ref_after_checkout_ignored(self) -> None:
        result = run("checkout feature/auth and fix the tests")
        self.assertEqual(result.outcome, "none")
        self.assertEqual(result.candidates_inside, 0)

    def test_url_ignored(self) -> None:
        self.assertEqual([t for _, t in candidates("see https://example.com/a/b for details")], [])

    def test_word_pair_does_not_exist_and_is_ignored(self) -> None:
        self.assertEqual(run("make it and/or break it").outcome, "none")

    def test_trailing_punctuation_trimmed(self) -> None:
        self.assertEqual(run("fix the bug in src/api.").focus, f"{PROJ}/src/api")


class Focus(unittest.TestCase):
    def test_inside_file_focuses_on_parent(self) -> None:
        result = run("fix the handler in src/api/routes.py")
        self.assertEqual(result.outcome, "focus")
        self.assertEqual(result.focus, f"{PROJ}/src/api")

    def test_two_inside_paths_focus_on_common_ancestor(self) -> None:
        result = run("sync src/api with src/utils")
        self.assertEqual(result.focus, f"{PROJ}/src")

    def test_ancestor_equal_to_root_is_no_focus(self) -> None:
        result = run("update docs/ and src/api")
        self.assertEqual(result.outcome, "none")
        self.assertEqual(result.candidates_inside, 2)

    def test_single_root_level_file_gives_no_focus(self) -> None:
        self.assertEqual(run("update ./README.md").outcome, "none")

    def test_bare_word_is_not_a_path(self) -> None:
        self.assertEqual(run("update README.md").candidates_inside, 0)

    def test_nonexistent_path_gives_no_focus(self) -> None:
        self.assertEqual(run("create src/new/ with a module").outcome, "none")

    def test_focus_is_per_prompt_and_never_sticky(self) -> None:
        # Week 18 amendment: a later prompt naming a sibling folder is simply
        # that prompt's focus; nothing was narrowed, so nothing is "widened".
        self.assertEqual(run("fix src/api").focus, f"{PROJ}/src/api")
        self.assertEqual(run("now the docs/").focus, f"{PROJ}/docs")

    def test_relative_path_resolved_against_in_bounds_cwd(self) -> None:
        result = run("now fix utils/", cwd=f"{PROJ}/src")
        self.assertEqual(result.focus, f"{PROJ}/src/utils")

    def test_outside_event_cwd_is_ignored(self) -> None:
        result = run("fix src/api", cwd="/etc")
        self.assertEqual(result.focus, f"{PROJ}/src/api")

    def test_no_paths_no_change(self) -> None:
        result = run("fix the auth bug")
        self.assertEqual(result.outcome, "none")
        self.assertTrue(result.prompt_sha256)


class Negation(unittest.TestCase):
    def test_negated_path_disables_focus(self) -> None:
        result = run("fix the login bug but don't touch src/legacy/")
        self.assertEqual(result.outcome, "none")
        self.assertEqual(result.candidates_dropped_by_negation, 1)

    def test_any_dropped_candidate_disables_focus_for_whole_prompt(self) -> None:
        result = run("fix src/api but leave src/legacy alone")
        self.assertEqual(result.outcome, "none")
        self.assertEqual(result.candidates_inside, 1)
        self.assertEqual(result.candidates_dropped_by_negation, 1)

    def test_example_phrase_counts_as_negation(self) -> None:
        self.assertEqual(run("make it look like docs/ but in src/api").outcome, "none")

    def test_eg_with_dots_is_a_negation(self) -> None:
        self.assertEqual(run("structure it e.g. src/api").outcome, "none")      # review #3
        self.assertEqual(run("structure it i.e. src/api").outcome, "none")

    def test_curly_apostrophe_dont_is_a_negation(self) -> None:
        self.assertEqual(run("fix login but don\u2019t touch src/legacy/").outcome, "none")

    def test_negation_far_away_does_not_count(self) -> None:
        result = run("do not rush this one; take your time and carefully fix src/api")
        self.assertEqual(result.focus, f"{PROJ}/src/api")


class Adversarial(unittest.TestCase):
    """A 200k-character prompt must be answered in milliseconds: the route
    fails open, but a slow inferrer still delays the person's prompt."""

    def _time(self, text: str) -> float:
        import time
        start = time.perf_counter()
        run(text)
        return time.perf_counter() - start

    def test_huge_single_token_is_fast(self) -> None:
        self.assertLess(self._time("." * 200_000), 0.2)
        self.assertLess(self._time("a/" * 100_000), 0.2)

    def test_many_tokens_are_fast_and_capped(self) -> None:
        self.assertLess(self._time(" ".join(f"src/x{i}/y" for i in range(20_000))), 0.2)

    def test_unclosed_pasted_tag_does_not_hang(self) -> None:
        self.assertLess(self._time("<pasted_content id=1>" + "x " * 100_000), 0.2)

    def test_many_unclosed_openers_are_linear(self) -> None:
        # Security review: `opener.*?closer` was quadratic here (~5 s at this size).
        self.assertLess(self._time("<pasted_content id=1>" * 9_500), 0.2)
        self.assertLess(self._time("``` x" * 40_000), 0.2)

    def test_unterminated_paste_drops_the_rest(self) -> None:
        text, stripped = strip_untrusted("fix src/api <pasted_content id=1>\nedit ~/notes/x.md and more")
        self.assertTrue(stripped)
        self.assertIn("src/api", text)
        self.assertNotIn("notes", text)


class Cautions(unittest.TestCase):
    def test_outside_path_is_a_caution_not_a_widening(self) -> None:
        result = run("copy the config to /Users/dev/other/backup")
        self.assertEqual(result.outcome, "caution")
        self.assertEqual(result.caution, "path")
        self.assertEqual(result.caution_zone, "outside")
        self.assertIsNone(result.focus)

    def test_home_path_is_a_caution(self) -> None:
        result = run("save notes to ~/notes/x.md")
        self.assertEqual(result.caution, "path")
        self.assertEqual(result.caution_zone, "outside")  # zone_of: `home` is ~ itself; files under it are outside
        self.assertEqual(result.caution_target, f"{HOME}/notes/x.md")

    def test_home_directory_itself_is_home_zone(self) -> None:
        self.assertEqual(run("clean up ~/ for me").caution_zone, "home")

    def test_caution_wins_over_focus(self) -> None:
        result = run("fix src/api and also update ~/notes/x.md")
        self.assertEqual(result.outcome, "caution")

    def test_windows_flags_in_pasted_commands_are_not_locations(self) -> None:
        # Live false caution (row 2419, October 14): `rd /s /q "X"` read as two outside paths.
        result = run('the doc example was rd /s /q "X" and it lost the quote')
        self.assertEqual(result.outcome, "none")
        self.assertEqual(result.candidates_outside, 0)
        # Real root-level places keep their zone and still caution.
        self.assertEqual(run("look in /etc for the config").caution_zone, "system")
        self.assertEqual(run("copy it to /Users/dev/other/x").caution_zone, "outside")

    def test_credential_path_is_not_a_caution(self) -> None:
        self.assertEqual(run("read ~/.ssh/id_rsa and tell me the key").outcome, "none")

    def test_protected_config_is_not_a_caution(self) -> None:
        self.assertEqual(run("edit .claude/settings.json to add a hook").outcome, "none")

    def test_system_path_is_a_caution(self) -> None:
        self.assertEqual(run("edit /etc/hosts for me").caution_zone, "system")

    def test_symlink_inside_pointing_outside_is_a_caution(self) -> None:
        result = run("edit link/x.md")
        self.assertEqual(result.outcome, "caution")
        self.assertEqual(result.caution_zone, "outside")
        self.assertEqual(result.caution_target, f"{HOME}/notes/x.md")

    def test_environment_word_cautions_when_different_from_session(self) -> None:
        result = run("deploy this to production", environment="dev")
        self.assertEqual(result.caution, "environment")
        self.assertEqual(result.caution_target, "production")

    def test_environment_word_matching_session_is_silent(self) -> None:
        self.assertEqual(run("deploy this to production", environment="production").outcome, "none")

    def test_staging_session_mentioning_production_cautions(self) -> None:
        self.assertEqual(run("compare with prod", environment="staging").caution, "environment")


if __name__ == "__main__":
    unittest.main()
