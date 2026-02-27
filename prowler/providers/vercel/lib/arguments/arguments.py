def init_parser(self):
    """Init the Vercel provider CLI parser."""
    vercel_parser = self.subparsers.add_parser(
        "vercel",
        parents=[self.common_providers_parser],
        help="Vercel Provider",
    )

    # Authentication
    auth_group = vercel_parser.add_argument_group("Authentication")
    auth_group.add_argument(
        "--vercel-token",
        nargs="?",
        default=None,
        metavar="TOKEN",
        help="Vercel API Bearer Token. Falls back to VERCEL_TOKEN environment variable.",
    )

    # Scope
    scope_group = vercel_parser.add_argument_group("Scope")
    scope_group.add_argument(
        "--vercel-team",
        nargs="?",
        default=None,
        metavar="TEAM_ID",
        help="Vercel Team ID or slug to scope the scan. Falls back to VERCEL_TEAM environment variable.",
    )
    scope_group.add_argument(
        "--project",
        "--projects",
        nargs="*",
        default=None,
        metavar="PROJECT",
        help="Filter scan to specific Vercel project names or IDs.",
    )
