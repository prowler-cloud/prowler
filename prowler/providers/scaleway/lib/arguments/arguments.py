def init_parser(self):
    """Init the Scaleway provider CLI parser."""
    scaleway_parser = self.subparsers.add_parser(
        "scaleway",
        parents=[self.common_providers_parser],
        help="Scaleway Provider",
    )

    # Authentication
    # Credentials are read exclusively from the standard Scaleway environment
    # variables (SCW_ACCESS_KEY / SCW_SECRET_KEY) to avoid leaking secrets into
    # shell history and process listings. There are no credential CLI flags.

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
