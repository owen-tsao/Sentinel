from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.control import DraftCompilationError, compile_task_prompt  # noqa: E402


class ControlDraftCompilerTests(unittest.TestCase):
    def test_extracts_only_reviewable_explicit_facts(self) -> None:
        raw = "Delete /workspace/build/old.txt in production."

        preview = compile_task_prompt(raw)
        suggestions = {
            suggestion.field: suggestion
            for suggestion in preview.suggestions
        }

        self.assertEqual(suggestions["operation"].value, "delete")
        self.assertEqual(
            suggestions["exact_targets"].value,
            ["/workspace/build/old.txt"],
        )
        self.assertEqual(suggestions["environment"].value, "production")
        self.assertTrue(
            all(suggestion.requires_review for suggestion in preview.suggestions)
        )
        self.assertEqual(
            preview.prompt_sha256,
            hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        )

    def test_conflicting_words_produce_questions_instead_of_guesses(self) -> None:
        preview = compile_task_prompt(
            "Read and delete /workspace/build/a.txt in dev and production."
        )

        suggested_fields = {
            suggestion.field for suggestion in preview.suggestions
        }
        question_fields = {question.field for question in preview.questions}

        self.assertNotIn("operation", suggested_fields)
        self.assertNotIn("environment", suggested_fields)
        self.assertIn("operation", question_fields)
        self.assertIn("environment", question_fields)

    def test_non_workspace_paths_are_not_promoted_to_targets(self) -> None:
        preview = compile_task_prompt("Read /etc/passwd in sandbox.")

        self.assertNotIn(
            "exact_targets",
            {suggestion.field for suggestion in preview.suggestions},
        )
        self.assertIn(
            "exact_targets",
            {question.field for question in preview.questions},
        )

    def test_hash_preserves_exact_utf8_bytes_without_normalization(self) -> None:
        composed = compile_task_prompt("Read café /workspace/a in sandbox.")
        decomposed = compile_task_prompt("Read cafe\u0301 /workspace/a in sandbox.")

        self.assertNotEqual(composed.prompt_sha256, decomposed.prompt_sha256)

    def test_rejects_empty_and_oversized_utf8_without_echoing_input(self) -> None:
        with self.assertRaisesRegex(
            DraftCompilationError,
            "draft:prompt_required",
        ):
            compile_task_prompt("  ")
        marker = "ø" * 16_001
        with self.assertRaises(DraftCompilationError) as raised:
            compile_task_prompt(marker)

        self.assertEqual(raised.exception.reason_code, "draft:prompt_too_large")
        self.assertNotIn(marker, str(raised.exception))


if __name__ == "__main__":
    unittest.main()
