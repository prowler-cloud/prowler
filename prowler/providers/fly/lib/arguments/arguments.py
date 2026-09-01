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
