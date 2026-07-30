#!/usr/bin/env python3
"""Rename changelog fragments to their PR number before running towncrier.

For every <slug>.<type>.md in <component_dir>/changelog.d/, find the commit that
added it, resolve its PR via the GitHub API (falling back to the squash-commit
subject), and `git mv` it to <PR>.<type>.md so towncrier renders the PR link.
Unresolvable fragments become +<slug>.<type>.md orphans (rendered without link).
"""

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

FRAGMENT_RE = re.compile(
    r"^(?P<slug>[A-Za-z0-9][A-Za-z0-9._-]*?)"
    r"\.(?P<type>added|changed|deprecated|removed|fixed|security)"
    r"(?:\.(?P<counter>[0-9]+))?\.md$"
)
SUBJECT_PR_RE = re.compile(r" \(#([0-9]+)\)$")
IGNORED_FILES = {".gitkeep", "README.md"}
API_TIMEOUT_SECONDS = 10


def git(*args: str) -> str:
    result = subprocess.run(["git", *args], check=True, capture_output=True, text=True)
    return result.stdout.strip()


def find_adding_commit(path: str) -> str | None:
    """Find the commit that added a file, following renames.

    Falls back to a plain (no --follow) lookup: rename detection can lose the
    add event for degenerate content (e.g. files identical to many others).
    """
    sha = git("log", "--follow", "--diff-filter=A", "--format=%H", "-1", "--", path)
    if not sha:
        sha = git("log", "--diff-filter=A", "--format=%H", "-1", "--", path)
    return sha or None


def pr_from_api(repo: str, sha: str) -> int | None:
    """Resolve the PR associated with a commit via the GitHub API.

    Returns None on any network/API failure so the caller can fall back to
    parsing the squash-commit subject.
    """
    url = f"https://api.github.com/repos/{repo}/commits/{sha}/pulls"
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "prowler-changelog-attribution",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=API_TIMEOUT_SECONDS) as response:
            pulls = json.load(response)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None
    if isinstance(pulls, list) and pulls:
        return pulls[0].get("number")
    return None


def pr_from_subject(sha: str) -> int | None:
    subject = git("log", "-1", "--format=%s", sha)
    match = SUBJECT_PR_RE.search(subject)
    return int(match.group(1)) if match else None


def unique_destination(directory: str, base_name: str, fragment_type: str) -> str:
    """Return a non-colliding fragment path, appending a numeric counter if needed."""
    candidate = os.path.join(directory, f"{base_name}.{fragment_type}.md")
    counter = 0
    while os.path.exists(candidate):
        counter += 1
        candidate = os.path.join(directory, f"{base_name}.{fragment_type}.{counter}.md")
    return candidate


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component_dir", help="Component directory, e.g. prowler")
    parser.add_argument("--repo", default="prowler-cloud/prowler")
    parser.add_argument(
        "--no-api",
        action="store_true",
        help="Skip the GitHub API and resolve PRs from commit subjects only",
    )
    args = parser.parse_args()

    fragments_dir = os.path.join(args.component_dir, "changelog.d")
    if not os.path.isdir(fragments_dir):
        print(f"::error::Fragments directory not found: {fragments_dir}")
        return 1

    malformed = []
    to_process = []
    for name in sorted(os.listdir(fragments_dir)):
        if name in IGNORED_FILES or name.startswith("+"):
            continue
        match = FRAGMENT_RE.match(name)
        if not match:
            malformed.append(name)
            continue
        if match.group("slug").isdigit():
            continue
        to_process.append((name, match))

    if malformed:
        for name in malformed:
            print(
                f"::error::Malformed fragment filename in {fragments_dir}: {name} "
                "(expected <slug>.<type>.md with type one of added|changed|"
                "deprecated|removed|fixed|security)"
            )
        return 1

    for name, match in to_process:
        slug, fragment_type = match.group("slug"), match.group("type")

        path = os.path.join(fragments_dir, name)
        sha = find_adding_commit(path)
        pr_number = None
        if sha:
            if not args.no_api:
                pr_number = pr_from_api(args.repo, sha)
            if pr_number is None:
                pr_number = pr_from_subject(sha)

        if pr_number is not None:
            destination = unique_destination(
                fragments_dir, str(pr_number), fragment_type
            )
        else:
            destination = unique_destination(fragments_dir, f"+{slug}", fragment_type)
            print(
                f"::warning::Could not resolve a PR for {path}; renamed to "
                f"{os.path.basename(destination)} (entry will render without a PR link)"
            )
        git("mv", path, destination)
        print(f"{path} -> {destination}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
