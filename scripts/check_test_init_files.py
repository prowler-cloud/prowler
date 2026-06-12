#!/usr/bin/env python3
"""Fail when __init__.py files are present inside test directories."""

from __future__ import annotations

import sys
from argparse import ArgumentParser
from pathlib import Path

EXCLUDED_TEST_INIT_ROOTS = {
    Path("tests/lib/check/fixtures/checks_folder"),
}


def is_test_init_file(path: Path) -> bool:
    """Return True when the file is a test __init__.py."""
    return path.name == "__init__.py" and "tests" in path.parts


def is_excluded_test_init_file(path: Path, root: Path) -> bool:
    """Return True when the file belongs to an allowed fixture directory."""
    relative_path = path.relative_to(root)
    return any(
        relative_path.is_relative_to(excluded) for excluded in EXCLUDED_TEST_INIT_ROOTS
    )


def find_test_init_files(root: Path) -> list[Path]:
    """Return sorted __init__.py files found under test directories."""
    return sorted(
        path
        for path in root.rglob("__init__.py")
        if is_test_init_file(path) and not is_excluded_test_init_file(path, root)
    )


def main(argv: list[str] | None = None) -> int:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument(
        "root",
        nargs="?",
        default=".",
        help="Repository root to scan. Defaults to the current directory.",
    )
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    matches = find_test_init_files(root)

    if not matches:
        print("No __init__.py files found in test directories.")
        return 0

    print("Remove __init__.py files from test directories:")
    for path in matches:
        print(path.relative_to(root))

    return 1


if __name__ == "__main__":
    sys.exit(main())
