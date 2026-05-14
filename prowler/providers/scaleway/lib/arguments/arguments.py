SENSITIVE_ARGUMENTS = frozenset({"--access-key", "--secret-key"})


def init_parser(self):
    """Init the Scaleway provider CLI parser."""
    scaleway_parser = self.subparsers.add_parser(
        "scaleway",
        parents=[self.common_providers_parser],
        help="Scaleway Provider",
    )

    # Authentication
    auth_subparser = scaleway_parser.add_argument_group("Authentication")
    auth_subparser.add_argument(
        "--access-key",
        nargs="?",
        default=None,
        metavar="SCW_ACCESS_KEY",
        help=(
            "Scaleway API access key. Prefer the SCW_ACCESS_KEY env var "
            "instead of passing it on the command line."
        ),
    )
    auth_subparser.add_argument(
        "--secret-key",
        nargs="?",
        default=None,
        metavar="SCW_SECRET_KEY",
        help=(
            "Scaleway API secret key. Prefer the SCW_SECRET_KEY env var "
            "instead of passing it on the command line."
        ),
    )

    # Scope
    scope_subparser = scaleway_parser.add_argument_group("Scope")
    scope_subparser.add_argument(
        "--organization-id",
        nargs="?",
        default=None,
        metavar="SCW_DEFAULT_ORGANIZATION_ID",
        help="Scaleway organization ID to scope the audit.",
    )
    scope_subparser.add_argument(
        "--project-id",
        nargs="?",
        default=None,
        metavar="SCW_DEFAULT_PROJECT_ID",
        help="Default Scaleway project ID for project-scoped resources.",
    )
    scope_subparser.add_argument(
        "--region",
        nargs="?",
        default=None,
        metavar="SCW_DEFAULT_REGION",
        help="Default Scaleway region (fr-par, nl-ams, pl-waw).",
    )
