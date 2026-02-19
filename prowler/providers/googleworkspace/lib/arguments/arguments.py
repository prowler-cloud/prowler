def init_parser(self):
    """Init the Google Workspace Provider CLI parser"""
    googleworkspace_parser = self.subparsers.add_parser(
        "googleworkspace",
        parents=[self.common_providers_parser],
        help="Google Workspace Provider",
    )

    # Domain-Wide Delegation
    googleworkspace_delegation_subparser = googleworkspace_parser.add_argument_group(
        "Domain-Wide Delegation"
    )
    googleworkspace_delegation_subparser.add_argument(
        "--delegated-user",
        nargs="?",
        metavar="EMAIL",
        help="Email address of the user to impersonate for Domain-Wide Delegation (required)",
        default=None,
        required=False,  # Made optional here to allow environment variable fallback
    )
