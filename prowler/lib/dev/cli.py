"""Command-line entry point for Prowler's development commands.

Exposed as the ``prowler-dev`` console script. This is contributor tooling, so
it is deliberately separate from the ``prowler`` CLI: nothing here runs during a
scan.
"""

import sys
from argparse import ArgumentParser, Namespace, RawDescriptionHelpFormatter
from pathlib import Path
from typing import List, Optional

from prowler.lib.dev.provider_scaffold import (
    AUTH_MODES,
    KINDS,
    SCOPES,
    ProviderSpec,
    ScaffoldError,
    ScaffoldPlan,
    build_plan,
    write_plan,
)

PROVIDER_CREATE_EPILOG = """examples:
  # A built-in CLI/SDK provider that reads credentials from the environment
  prowler-dev provider create --name acmecloud --kind api --scope builtin

  # A provider the API and UI also list, authenticating with a token
  prowler-dev provider create --name acmecloud --kind api --scope full-stack \\
      --regional false --auth token

  # A provider distributed as its own package, discovered through entry points
  prowler-dev provider create --name acmecloud --kind api --scope external

The scaffold generates structure and TODO markers. It does not invent
authentication behavior, API semantics or security checks. It does not edit
the files shared by every provider either, and reports those as next steps
with a snippet to paste.
"""


def build_parser() -> ArgumentParser:
    """Build the prowler-dev argument parser."""
    parser = ArgumentParser(
        prog="prowler-dev",
        description="Development commands for contributing to Prowler.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    provider = commands.add_parser(
        "provider", help="Work on a Prowler provider"
    ).add_subparsers(dest="provider_command", required=True)

    create = provider.add_parser(
        "create",
        help="Scaffold the minimum consistent structure for a new provider",
        epilog=PROVIDER_CREATE_EPILOG,
        formatter_class=RawDescriptionHelpFormatter,
    )
    create.add_argument(
        "--name",
        required=True,
        help="Provider name, lowercase letters and digits only (e.g. acmecloud)",
    )
    create.add_argument(
        "--kind",
        required=True,
        choices=KINDS,
        help="Provider kind. A tool/wrapper provider gets no service layer.",
    )
    create.add_argument(
        "--scope",
        required=True,
        choices=SCOPES,
        help=(
            "How far the provider reaches: builtin is CLI/SDK only, full-stack "
            "is also listed by the API and UI, external is its own package."
        ),
    )
    create.add_argument(
        "--regional",
        choices=("true", "false"),
        default="false",
        help="Whether findings are scoped per region. Default: false",
    )
    create.add_argument(
        "--auth",
        choices=AUTH_MODES,
        default="env",
        help="Which credential source the arguments expose. Default: env",
    )
    create.add_argument(
        "--path",
        type=Path,
        default=None,
        help=(
            "Where to generate. For builtin and full-stack, the Prowler "
            "checkout to write into, auto-detected when omitted. For external, "
            "the directory to create, defaulting to ./prowler-provider-<name>."
        ),
    )
    create.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the files that would be written and exit",
    )
    create.add_argument(
        "--force",
        action="store_true",
        help="Overwrite files that already exist",
    )
    create.set_defaults(handler=provider_create)
    return parser


def _print_plan(plan: ScaffoldPlan, spec: ProviderSpec, dry_run: bool) -> None:
    """Print the files in a plan and what is left to do."""
    verb = "Would create" if dry_run else "Created"
    print(f"{verb} {len(plan.files)} files for provider '{spec.name}' in {plan.root}")
    print()
    for relative in plan.paths:
        print(f"  {relative}")
    print()
    print(
        f"Scope: {spec.scope}  Kind: {spec.kind}  "
        f"Regional: {str(spec.regional).lower()}  Auth: {spec.auth}  "
        f"sdk_only: {spec.sdk_only}"
    )
    print()
    print("Next steps:")
    for index, step in enumerate(plan.next_steps, start=1):
        print(f"  {index}. {step}")


def provider_create(arguments: Namespace) -> int:
    """Handle `prowler-dev provider create`."""
    spec = ProviderSpec(
        name=arguments.name,
        kind=arguments.kind,
        scope=arguments.scope,
        auth=arguments.auth,
        regional=arguments.regional == "true",
    )
    plan = build_plan(spec, arguments.path)
    if not arguments.dry_run:
        write_plan(plan, force=arguments.force)
    _print_plan(plan, spec, dry_run=arguments.dry_run)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """Run prowler-dev.

    Args:
        argv: Arguments to parse. Defaults to sys.argv[1:].

    Returns:
        The process exit code.
    """
    arguments = build_parser().parse_args(argv)
    try:
        return arguments.handler(arguments)
    except ScaffoldError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
