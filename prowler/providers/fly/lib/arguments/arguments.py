from argparse import Namespace


def init_parser(self):
    """Init the Fly.io provider CLI parser."""
    fly_parser = self.subparsers.add_parser(
        "fly",
        parents=[self.common_providers_parser],
        help="Fly.io Provider",
    )

    # Authentication
    auth_group = fly_parser.add_argument_group("Authentication Modes")
    auth_group.add_argument(
        "--organization",
        "--org",
        nargs="?",
        default=None,
        metavar="FLY_ORG",
        help="Fly.io organization slug to audit. Use the FLY_ORG env var instead of passing it directly. The token is read from FLY_API_TOKEN.",
    )

    # Scope
    scope_group = fly_parser.add_argument_group("Scope")
    scope_group.add_argument(
        "--app",
        "--apps",
        nargs="*",
        default=None,
        metavar="APP",
        help="Filter the scan to specific Fly.io app names.",
    )


def validate_arguments(arguments: Namespace) -> tuple[bool, str]:
    """Validate the Fly.io provider arguments.

    ``--app`` uses ``nargs="*"``, so argparse accepts the flag with no value
    and yields an empty list. That is rejected here with a usage error instead
    of silently scanning every app, and blank names are dropped.

    Args:
        arguments: The parsed CLI arguments.

    Returns:
        tuple[bool, str]: Whether the arguments are valid and the error message.
    """
    apps = getattr(arguments, "app", None)
    if apps is None:
        return (True, "")

    names = [name.strip() for name in apps if isinstance(name, str) and name.strip()]
    if not names:
        return (
            False,
            "--app/--apps requires at least one Fly.io app name, or omit the flag to scan every app in the organization",
        )

    arguments.app = names
    return (True, "")
