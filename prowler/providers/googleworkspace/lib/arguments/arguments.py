def init_parser(self):
    """Init the Google Workspace Provider CLI parser"""
    googleworkspace_parser = self.subparsers.add_parser(
        "googleworkspace",
        parents=[self.common_providers_parser],
        help="Google Workspace Provider",
    )

    # Authentication Modes
    googleworkspace_auth_subparser = googleworkspace_parser.add_argument_group(
        "Authentication"
    )
    googleworkspace_auth_modes_group = (
        googleworkspace_auth_subparser.add_mutually_exclusive_group()
    )
    googleworkspace_auth_modes_group.add_argument(
        "--credentials-file",
        nargs="?",
        metavar="FILE_PATH",
        help="Path to Service Account JSON credentials file for Domain-Wide Delegation",
        default=None,
    )
    googleworkspace_auth_modes_group.add_argument(
        "--credentials-content",
        nargs="?",
        metavar="JSON_STRING",
        help="Service Account JSON credentials as a string for Domain-Wide Delegation",
        default=None,
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
