def init_parser(self):
    """Initialize the Supabase provider CLI parser."""
    self.subparsers.add_parser(
        "supabase",
        parents=[self.common_providers_parser],
        help="Supabase Provider (PoC)",
    )
