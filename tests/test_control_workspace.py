from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.control import (  # noqa: E402
    SQLiteWorkspaceBindingStore,
    WorkspaceBindingError,
    resolve_workspace_target,
    review_workspace,
)


def make_repository(parent: Path, name: str) -> Path:
    repository = parent / name
    repository.mkdir()
    (repository / ".git").mkdir()
    return repository


class WorkspaceControlTests(unittest.TestCase):
    def test_review_workspace_resolves_a_symlink_to_one_canonical_identity(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = make_repository(root, "repository")
            alias = root / "alias"
            alias.symlink_to(repository)

            direct = review_workspace(repository)
            linked = review_workspace(alias)

        self.assertEqual(linked, direct)
        self.assertEqual(linked.path, repository.resolve())

    def test_review_workspace_requires_a_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                WorkspaceBindingError,
                "control:workspace_not_repository",
            ):
                review_workspace(directory)

    def test_sqlite_binding_resumes_the_same_server_owned_session(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = make_repository(root, "repository")
            database = root / "sentinel.sqlite3"
            workspace = review_workspace(repository)

            first_store = SQLiteWorkspaceBindingStore(database)
            first = first_store.bind(workspace)
            first_store.close()

            second_store = SQLiteWorkspaceBindingStore(database)
            second = second_store.bind(review_workspace(repository))
            second_store.close()

        self.assertEqual(second.session_id, first.session_id)
        self.assertEqual(second.workspace.identity_sha256, first.workspace.identity_sha256)

    def test_sqlite_binding_rejects_a_different_workspace_on_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first_repository = make_repository(root, "first")
            second_repository = make_repository(root, "second")
            database = root / "sentinel.sqlite3"

            first_store = SQLiteWorkspaceBindingStore(database)
            first_store.bind(review_workspace(first_repository))
            first_store.close()

            second_store = SQLiteWorkspaceBindingStore(database)
            try:
                with self.assertRaisesRegex(
                    WorkspaceBindingError,
                    "control:workspace_identity_mismatch",
                ):
                    second_store.bind(review_workspace(second_repository))
            finally:
                second_store.close()

    def test_target_resolution_rejects_parent_and_absolute_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = make_repository(Path(directory), "repository")
            workspace = review_workspace(repository)

            for target in ("../outside.txt", "/tmp/outside.txt"):
                with self.subTest(target=target), self.assertRaisesRegex(
                    WorkspaceBindingError,
                    "control:workspace_parent_traversal",
                ):
                    resolve_workspace_target(workspace, target)

    def test_target_resolution_rejects_symlinks_and_hardlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = make_repository(root, "repository")
            outside = root / "outside.txt"
            outside.write_text("outside", encoding="utf-8")
            (repository / "alias.txt").symlink_to(outside)
            hardlink = repository / "hardlink.txt"
            os.link(outside, hardlink)
            workspace = review_workspace(repository)

            with self.assertRaisesRegex(
                WorkspaceBindingError,
                "control:workspace_symlink_target",
            ):
                resolve_workspace_target(workspace, "alias.txt")
            with self.assertRaisesRegex(
                WorkspaceBindingError,
                "control:workspace_hardlink_target",
            ):
                resolve_workspace_target(workspace, "hardlink.txt")

    def test_target_resolution_allows_a_missing_confined_leaf(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = make_repository(Path(directory), "repository")
            (repository / "build").mkdir()
            workspace = review_workspace(repository)

            target = resolve_workspace_target(workspace, "build/marker.txt")

        self.assertEqual(target, repository.resolve() / "build" / "marker.txt")


if __name__ == "__main__":
    unittest.main()
