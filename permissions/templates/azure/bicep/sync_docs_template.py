import argparse
import json
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_SOURCE = Path(__file__).with_name("prowler-scan.json")
DEFAULT_ASSET = (
    REPOSITORY_ROOT / "docs/assets/templates/azure/prowler-scan.json"
)
DEFAULT_SNIPPET = REPOSITORY_ROOT / "docs/snippets/azure-prowler-scan-template.mdx"
SNIPPET_PREFIX = (
    b"{/* AUTO-GENERATED from permissions/templates/azure/bicep/"
    b"prowler-scan.json. Do not edit manually. */}\n\n```json\n"
)
SNIPPET_SUFFIX = b"\n```\n"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Synchronize the Azure ARM template with Prowler documentation."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--sync", action="store_true")
    mode.add_argument("--check", action="store_true")
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--asset", type=Path, default=DEFAULT_ASSET)
    parser.add_argument("--snippet", type=Path, default=DEFAULT_SNIPPET)
    return parser.parse_args()


def expected_snippet(source):
    return SNIPPET_PREFIX + source + SNIPPET_SUFFIX


def main():
    args = parse_args()
    source = args.source.read_bytes()
    json.loads(source)
    snippet = expected_snippet(source)

    if args.sync:
        args.asset.parent.mkdir(parents=True, exist_ok=True)
        args.snippet.parent.mkdir(parents=True, exist_ok=True)
        args.asset.write_bytes(source)
        args.snippet.write_bytes(snippet)
        return 0

    drifted = []
    if not args.asset.exists() or args.asset.read_bytes() != source:
        drifted.append(args.asset)
    if not args.snippet.exists() or args.snippet.read_bytes() != snippet:
        drifted.append(args.snippet)

    if drifted:
        paths = ", ".join(str(path) for path in drifted)
        print(
            f"Azure documentation template drift detected: {paths}",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
