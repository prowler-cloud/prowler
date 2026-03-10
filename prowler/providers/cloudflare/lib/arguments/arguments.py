def init_parser(self):
    """Init the Cloudflare provider CLI parser."""
    cloudflare_parser = self.subparsers.add_parser(
        "cloudflare", parents=[self.common_providers_parser], help="Cloudflare Provider"
    )

    scope_group = cloudflare_parser.add_argument_group("Scope")
    scope_group.add_argument(
        "--account-id",
        nargs="+",
        default=None,
        metavar="ACCOUNT_ID",
        help="Filter scan to specific Cloudflare account IDs. Only zones belonging to these accounts will be scanned.",
    )
    scope_group.add_argument(
        "--region",
        "--filter-region",
        "-f",
        nargs="+",
        default=None,
        metavar="ZONE",
        help="Filter scan to specific Cloudflare zones (name or ID).",
    )
