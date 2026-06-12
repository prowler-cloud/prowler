import importlib.util
import shutil
import sys
from pathlib import Path

MODULE_PATH = (
    Path(__file__).resolve().parents[2]
    / ".github"
    / "scripts"
    / "changelog_attribution.py"
)
SPEC = importlib.util.spec_from_file_location("changelog_attribution", MODULE_PATH)
changelog_attribution = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(changelog_attribution)


def make_component(tmp_path):
    component = tmp_path / "prowler"
    fragments_dir = component / "changelog.d"
    fragments_dir.mkdir(parents=True)
    return component, fragments_dir


def fake_git_mv(*args):
    if args[0] != "mv":
        raise AssertionError(f"Unexpected git command: {args}")
    shutil.move(args[1], args[2])
    return ""


def fail_git(*args):
    raise AssertionError(f"Unexpected git command: {args}")


def fail_api(*args):
    raise AssertionError(f"Unexpected GitHub API call: {args}")


def run_main(monkeypatch, component, *extra_args):
    monkeypatch.setattr(
        sys,
        "argv",
        ["changelog_attribution.py", str(component), *extra_args],
    )
    return changelog_attribution.main()


class TestChangelogAttribution:
    def test_renames_slug_fragment_to_resolved_pr_number(self, tmp_path, monkeypatch):
        component, fragments_dir = make_component(tmp_path)
        fragment = fragments_dir / "add-workflow.fixed.md"
        fragment.write_text("Fix changelog workflow.\n")

        monkeypatch.setattr(
            changelog_attribution, "find_adding_commit", lambda path: "abc123"
        )
        monkeypatch.setattr(
            changelog_attribution, "pr_from_api", lambda repo, sha: 11572
        )
        monkeypatch.setattr(changelog_attribution, "git", fake_git_mv)

        assert run_main(monkeypatch, component) == 0
        assert not fragment.exists()
        assert (fragments_dir / "11572.fixed.md").read_text() == (
            "Fix changelog workflow.\n"
        )

    def test_appends_counter_when_pr_fragment_already_exists(
        self, tmp_path, monkeypatch
    ):
        component, fragments_dir = make_component(tmp_path)
        (fragments_dir / "11572.fixed.md").write_text("Existing fix.\n")
        fragment = fragments_dir / "another-fix.fixed.md"
        fragment.write_text("Another fix.\n")

        monkeypatch.setattr(
            changelog_attribution, "find_adding_commit", lambda path: "abc123"
        )
        monkeypatch.setattr(
            changelog_attribution, "pr_from_api", lambda repo, sha: 11572
        )
        monkeypatch.setattr(changelog_attribution, "git", fake_git_mv)

        assert run_main(monkeypatch, component) == 0
        assert (fragments_dir / "11572.fixed.md").read_text() == "Existing fix.\n"
        assert (fragments_dir / "11572.fixed.1.md").read_text() == "Another fix.\n"

    def test_uses_subject_fallback_when_api_is_disabled(self, tmp_path, monkeypatch):
        component, fragments_dir = make_component(tmp_path)
        fragment = fragments_dir / "fallback.added.md"
        fragment.write_text("Add fallback behavior.\n")

        monkeypatch.setattr(
            changelog_attribution, "find_adding_commit", lambda path: "abc123"
        )
        monkeypatch.setattr(
            changelog_attribution,
            "pr_from_api",
            fail_api,
        )
        monkeypatch.setattr(changelog_attribution, "pr_from_subject", lambda sha: 42)
        monkeypatch.setattr(changelog_attribution, "git", fake_git_mv)

        assert run_main(monkeypatch, component, "--no-api") == 0
        assert not fragment.exists()
        assert (fragments_dir / "42.added.md").read_text() == "Add fallback behavior.\n"

    def test_renames_unresolved_fragment_to_orphan(self, tmp_path, monkeypatch, capsys):
        component, fragments_dir = make_component(tmp_path)
        fragment = fragments_dir / "manual.changed.md"
        fragment.write_text("Change manual entry.\n")

        monkeypatch.setattr(
            changelog_attribution, "find_adding_commit", lambda path: None
        )
        monkeypatch.setattr(changelog_attribution, "git", fake_git_mv)

        assert run_main(monkeypatch, component) == 0
        assert not fragment.exists()
        assert (fragments_dir / "+manual.changed.md").read_text() == (
            "Change manual entry.\n"
        )
        assert "Could not resolve a PR" in capsys.readouterr().out

    def test_rejects_malformed_fragment_names(self, tmp_path, monkeypatch, capsys):
        component, fragments_dir = make_component(tmp_path)
        fragment = fragments_dir / "bad.bugfix.md"
        fragment.write_text("Invalid type.\n")

        monkeypatch.setattr(
            changelog_attribution,
            "git",
            fail_git,
        )

        assert run_main(monkeypatch, component) == 1
        assert fragment.exists()
        assert "Malformed fragment filename" in capsys.readouterr().out

    def test_skips_fragments_that_already_start_with_pr_number(
        self, tmp_path, monkeypatch
    ):
        component, fragments_dir = make_component(tmp_path)
        fragment = fragments_dir / "11572.added.md"
        fragment.write_text("Already attributed.\n")

        monkeypatch.setattr(
            changelog_attribution,
            "git",
            fail_git,
        )

        assert run_main(monkeypatch, component) == 0
        assert fragment.read_text() == "Already attributed.\n"
