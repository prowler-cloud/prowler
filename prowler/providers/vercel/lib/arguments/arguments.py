def init_parser(self):
    """Init the Vercel provider CLI parser."""
    vercel_parser = self.subparsers.add_parser(
        "vercel",
        parents=[self.common_providers_parser],
        help="Vercel Provider",
    )

    # Scope
    scope_group = vercel_parser.add_argument_group("Scope")
    scope_group.add_argument(
        "--project",
        "--projects",
        nargs="*",
        default=None,
        metavar="PROJECT",
        help="Filter scan to specific Vercel project names or IDs.",
    )
