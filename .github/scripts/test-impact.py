#!/usr/bin/env python3
"""
Test Impact Analysis Script

Analyzes changed files and determines which tests need to run.
Outputs GitHub Actions compatible outputs.

Usage:
    python test-impact.py <changed_files...>
    python test-impact.py --from-stdin  # Read files from stdin (one per line)

Outputs (for GitHub Actions):
    - run-all: "true" if critical paths changed
    - sdk-tests: Space-separated list of SDK test paths
    - api-tests: Space-separated list of API test paths
    - ui-e2e: Space-separated list of UI E2E test paths
    - modules: Comma-separated list of affected module names
"""

import fnmatch
import os
import sys
from pathlib import Path

import yaml


def load_config() -> dict:
    """Load test-impact.yml configuration."""
    config_path = Path(__file__).parent.parent / "test-impact.yml"
    with open(config_path) as f:
        return yaml.safe_load(f)


def matches_pattern(file_path: str, pattern: str) -> bool:
    """Check if file path matches a glob pattern."""
    # Normalize paths
    file_path = file_path.strip("/")
    pattern = pattern.strip("/")

    # Handle ** patterns
    if "**" in pattern:
        # Convert glob pattern to work with fnmatch
        # e.g., "prowler/lib/**" matches "prowler/lib/check/foo.py"
        base = pattern.replace("/**", "")
        if file_path.startswith(base):
            return True
        # Also try standard fnmatch
        return fnmatch.fnmatch(file_path, pattern)

    return fnmatch.fnmatch(file_path, pattern)


def filter_ignored_files(
    changed_files: list[str], ignored_paths: list[str]
) -> list[str]:
    """Filter out files that match ignored patterns."""
    filtered = []
    for file_path in changed_files:
        is_ignored = False
        for pattern in ignored_paths:
            if matches_pattern(file_path, pattern):
                print(f"  [IGNORED] {file_path} matches {pattern}", file=sys.stderr)
                is_ignored = True
                break
        if not is_ignored:
            filtered.append(file_path)
    return filtered


def check_critical_paths(changed_files: list[str], critical_paths: list[str]) -> bool:
    """Check if any changed file matches critical paths."""
    for file_path in changed_files:
        for pattern in critical_paths:
            if matches_pattern(file_path, pattern):
                print(f"  [CRITICAL] {file_path} matches {pattern}", file=sys.stderr)
                return True
    return False


def find_affected_modules(
    changed_files: list[str], modules: list[dict]
) -> dict[str, dict]:
    """Find which modules are affected by changed files."""
    affected = {}

    for file_path in changed_files:
        for module in modules:
            module_name = module["name"]
            match_patterns = module.get("match", [])

            for pattern in match_patterns:
                if matches_pattern(file_path, pattern):
                    if module_name not in affected:
                        affected[module_name] = {
                            "tests": set(),
                            "e2e": set(),
                            "matched_files": [],
                        }
                    affected[module_name]["matched_files"].append(file_path)

                    # Add test patterns
                    for test_pattern in module.get("tests", []):
                        affected[module_name]["tests"].add(test_pattern)

                    # Add E2E patterns
                    for e2e_pattern in module.get("e2e", []):
                        affected[module_name]["e2e"].add(e2e_pattern)

                    break  # File matched this module, move to next file

    return affected


def categorize_tests(
    affected_modules: dict[str, dict],
) -> tuple[set[str], set[str], set[str]]:
    """Categorize tests into SDK, API, and UI E2E."""
    sdk_tests = set()
    api_tests = set()
    ui_e2e = set()

    for module_name, data in affected_modules.items():
        for test_path in data["tests"]:
            if test_path.startswith("tests/"):
                sdk_tests.add(test_path)
            elif test_path.startswith("api/"):
                api_tests.add(test_path)

        for e2e_path in data["e2e"]:
            ui_e2e.add(e2e_path)

    return sdk_tests, api_tests, ui_e2e


def set_github_output(name: str, value: str):
    """Set GitHub Actions output."""
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            # Handle multiline values
            if "\n" in value:
                import uuid

                delimiter = uuid.uuid4().hex
                f.write(f"{name}<<{delimiter}\n{value}\n{delimiter}\n")
            else:
                f.write(f"{name}={value}\n")
    # Print for debugging (without deprecated format)
    print(f"  {name}={value}", file=sys.stderr)


def main():
    # Parse arguments
    if "--from-stdin" in sys.argv:
        changed_files = [line.strip() for line in sys.stdin if line.strip()]
    else:
        changed_files = [f for f in sys.argv[1:] if f and not f.startswith("-")]

    if not changed_files:
        print("No changed files provided", file=sys.stderr)
        set_github_output("run-all", "false")
        set_github_output("sdk-tests", "")
        set_github_output("api-tests", "")
        set_github_output("ui-e2e", "")
        set_github_output("modules", "")
        set_github_output("has-tests", "false")
        return

    print(f"Analyzing {len(changed_files)} changed files...", file=sys.stderr)
    for f in changed_files[:10]:  # Show first 10
        print(f"  - {f}", file=sys.stderr)
    if len(changed_files) > 10:
        print(f"  ... and {len(changed_files) - 10} more", file=sys.stderr)

    # Load configuration
    config = load_config()

    # Filter out ignored files (docs, configs, etc.)
    ignored_paths = config.get("ignored", {}).get("paths", [])
    changed_files = filter_ignored_files(changed_files, ignored_paths)

    if not changed_files:
        print("\nAll changed files are ignored (docs, configs, etc.)", file=sys.stderr)
        print("No tests needed.", file=sys.stderr)
        set_github_output("run-all", "false")
        set_github_output("sdk-tests", "")
        set_github_output("api-tests", "")
        set_github_output("ui-e2e", "")
        set_github_output("modules", "none-ignored")
        set_github_output("has-tests", "false")
        return

    print(
        f"\n{len(changed_files)} files remain after filtering ignored paths",
        file=sys.stderr,
    )

    # Check critical paths
    critical_paths = config.get("critical", {}).get("paths", [])
    if check_critical_paths(changed_files, critical_paths):
        print("\nCritical path changed - running ALL tests", file=sys.stderr)
        set_github_output("run-all", "true")
        set_github_output("sdk-tests", "tests/")
        set_github_output("api-tests", "api/src/backend/")
        set_github_output("ui-e2e", "ui/tests/")
        set_github_output("modules", "all")
        set_github_output("has-tests", "true")
        return

    # Find affected modules
    modules = config.get("modules", [])
    affected = find_affected_modules(changed_files, modules)

    if not affected:
        print("\nNo test-mapped modules affected", file=sys.stderr)
        set_github_output("run-all", "false")
        set_github_output("sdk-tests", "")
        set_github_output("api-tests", "")
        set_github_output("ui-e2e", "")
        set_github_output("modules", "")
        set_github_output("has-tests", "false")
        return

    # Report affected modules
    print(f"\nAffected modules: {len(affected)}", file=sys.stderr)
    for module_name, data in affected.items():
        print(f"  [{module_name}]", file=sys.stderr)
        for f in data["matched_files"][:3]:
            print(f"    - {f}", file=sys.stderr)
        if len(data["matched_files"]) > 3:
            print(
                f"    ... and {len(data['matched_files']) - 3} more files",
                file=sys.stderr,
            )

    # Categorize tests
    sdk_tests, api_tests, ui_e2e = categorize_tests(affected)

    # Output results
    print("\nTest paths to run:", file=sys.stderr)
    print(f"  SDK: {sdk_tests or 'none'}", file=sys.stderr)
    print(f"  API: {api_tests or 'none'}", file=sys.stderr)
    print(f"  E2E: {ui_e2e or 'none'}", file=sys.stderr)

    set_github_output("run-all", "false")
    set_github_output("sdk-tests", " ".join(sorted(sdk_tests)))
    set_github_output("api-tests", " ".join(sorted(api_tests)))
    set_github_output("ui-e2e", " ".join(sorted(ui_e2e)))
    set_github_output("modules", ",".join(sorted(affected.keys())))
    set_github_output(
        "has-tests", "true" if (sdk_tests or api_tests or ui_e2e) else "false"
    )


if __name__ == "__main__":
    main()
