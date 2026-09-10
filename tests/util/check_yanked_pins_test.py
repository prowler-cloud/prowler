from pathlib import Path

import pytest

from util.check_yanked_pins import (
    Pin,
    collect_pins,
    evaluate,
    main,
    normalize,
    pins_from_pyproject,
    pins_from_uv_lock,
)

PYPROJECT = """
[project]
name = "demo"
dependencies = [
  "cryptography==48.0.1",
  "alibabacloud_tea_openapi==0.4.5",
  "Requests[security]==2.34.2 ; python_version >= '3.10'",
  "boto3>=1.40",
]

[project.optional-dependencies]
extra = ["okta==3.4.2"]

[dependency-groups]
dev = ["pytest==9.0.3", {include-group = "lint"}]
lint = ["flake8==7.1.2"]

[tool.uv]
constraint-dependencies = ["zstd==1.5.7.3"]
override-dependencies = ["okta==3.4.2"]
"""

UV_LOCK = """
version = 1

[[package]]
name = "zstd"
version = "1.5.7.3"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "Cryptography"
version = "48.0.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "prowler"
version = "5.40.0"
source = { git = "https://github.com/prowler-cloud/prowler.git?rev=master#abc" }

[[package]]
name = "demo"
version = "0.1.0"
source = { editable = "." }
"""


class TestNormalize:
    """normalize() applies PEP 503 so spellings of one project compare equal."""

    def test_pep503_equivalence(self):
        """Underscores, dots and case collapse to the canonical dashed lowercase form."""
        assert normalize("alibabacloud_tea_openapi") == "alibabacloud-tea-openapi"
        assert normalize("Requests") == "requests"
        assert normalize("zope.interface") == "zope-interface"


class TestPinsFromPyproject:
    """pins_from_pyproject() reads exact pins from every dependency-bearing table."""

    def test_collects_exact_pins_from_every_table(self):
        """Dependencies, extras, dependency groups and both [tool.uv] lists are covered."""
        pins = pins_from_pyproject(PYPROJECT, "")
        assert {(p.name, p.version) for p in pins} == {
            ("cryptography", "48.0.1"),
            ("alibabacloud-tea-openapi", "0.4.5"),
            ("requests", "2.34.2"),
            ("okta", "3.4.2"),
            ("pytest", "9.0.3"),
            ("flake8", "7.1.2"),
            ("zstd", "1.5.7.3"),
        }

    def test_ignores_ranges_and_records_source_table(self):
        """Non-exact specifiers are skipped and each pin remembers its table."""
        pins = pins_from_pyproject(PYPROJECT, "api/")
        names = {p.name for p in pins}
        assert "boto3" not in names
        zstd = next(p for p in pins if p.name == "zstd")
        assert zstd.source == "api/pyproject.toml [tool.uv.constraint-dependencies]"

    def test_same_pin_in_two_tables_keeps_both_sources(self):
        """The same version in two tables yields two pins, one per source."""
        okta = {
            p.source for p in pins_from_pyproject(PYPROJECT, "") if p.name == "okta"
        }
        assert okta == {
            "pyproject.toml [project.optional-dependencies.extra]",
            "pyproject.toml [tool.uv.override-dependencies]",
        }


class TestPinsFromUvLock:
    """pins_from_uv_lock() reads locked versions that live on a registry."""

    def test_only_registry_packages(self):
        """git, path and editable sources are not on PyPI and are skipped."""
        pins = pins_from_uv_lock(UV_LOCK, "")
        assert {(p.name, p.version) for p in pins} == {
            ("zstd", "1.5.7.3"),
            ("cryptography", "48.0.1"),
        }
        assert all(p.source == "uv.lock" for p in pins)


class TestCollectPins:
    """collect_pins() merges a project's pyproject.toml and uv.lock."""

    def test_missing_files_raise(self, tmp_path: Path):
        """A directory with neither file is a caller error, not an empty result."""
        with pytest.raises(FileNotFoundError):
            collect_pins(tmp_path)

    def test_merges_pyproject_and_lock(self, tmp_path: Path):
        """Pins from both files are returned with the directory as source prefix."""
        (tmp_path / "pyproject.toml").write_text(PYPROJECT)
        (tmp_path / "uv.lock").write_text(UV_LOCK)
        sources = {p.source for p in collect_pins(tmp_path)}
        prefix = f"{tmp_path.as_posix()}/"
        assert f"{prefix}uv.lock" in sources
        assert f"{prefix}pyproject.toml [project.dependencies]" in sources


class TestEvaluate:
    """evaluate() queries PyPI once per release and reports per pin."""

    def test_queries_each_release_once_and_fans_out_to_every_source(self):
        """One fetch per (name, version); its verdict reaches every source of that pin."""
        calls = []

        def fake_fetch(name, version):
            """Stand-in for fetch_release() that records calls and returns fixed verdicts."""
            calls.append((name, version))
            if (name, version) == ("zstd", "1.5.7.3"):
                return "yanked", "buggy - not thread safe"
            if (name, version) == ("gone", "0.0.1"):
                return "missing", "not found on PyPI"
            return "ok", ""

        pins = {
            Pin("zstd", "1.5.7.3", "pyproject.toml [tool.uv.constraint-dependencies]"),
            Pin("zstd", "1.5.7.3", "uv.lock"),
            Pin("cryptography", "48.0.1", "uv.lock"),
            Pin("gone", "0.0.1", "uv.lock"),
        }
        verdicts = evaluate(pins, fetch=fake_fetch, workers=2)

        assert sorted(calls) == [
            ("cryptography", "48.0.1"),
            ("gone", "0.0.1"),
            ("zstd", "1.5.7.3"),
        ]
        by_status = {}
        for verdict in verdicts:
            by_status.setdefault(verdict.status, []).append(verdict.pin)
        assert len(by_status["yanked"]) == 2
        assert {p.source for p in by_status["yanked"]} == {
            "pyproject.toml [tool.uv.constraint-dependencies]",
            "uv.lock",
        }
        assert by_status["missing"] == [Pin("gone", "0.0.1", "uv.lock")]
        assert by_status["ok"] == [Pin("cryptography", "48.0.1", "uv.lock")]


class TestMain:
    """main() turns verdicts into a process exit code and annotations."""

    def test_exit_code_reflects_verdicts(self, tmp_path: Path, monkeypatch, capsys):
        """0 when every pin is ok, 1 plus a ::error:: line when one is yanked."""
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["zstd==1.5.7.3"]\n'
        )

        monkeypatch.setattr(
            "util.check_yanked_pins.fetch_release",
            lambda name, version, retries=3: ("ok", ""),
        )
        assert main([str(tmp_path)]) == 0

        monkeypatch.setattr(
            "util.check_yanked_pins.fetch_release",
            lambda name, version, retries=3: ("yanked", "buggy - not thread safe"),
        )
        assert main([str(tmp_path)]) == 1
        assert (
            "::error::zstd==1.5.7.3 is yanked (buggy - not thread safe)"
            in capsys.readouterr().out
        )
