def init_parser(self):
    """Initialize the Supabase provider CLI parser."""
    supabase_parser = self.subparsers.add_parser(
        "supabase",
        parents=[self.common_providers_parser],
        help="Supabase Provider",
    )

    # Scope
    scope_group = supabase_parser.add_argument_group("Scope")
    scope_group.add_argument(
        "--project",
        "--projects",
        nargs="*",
        default=None,
        metavar="PROJECT",
        help="Filter the scan to specific Supabase project refs or names.",
    )
