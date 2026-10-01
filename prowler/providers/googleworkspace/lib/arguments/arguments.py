def init_parser(self):
    """Init the Google Workspace Provider CLI parser"""
    googleworkspace_parser = self.subparsers.add_parser(
        "googleworkspace",
        parents=[self.common_providers_parser],
        help="Google Workspace Provider",
    )
    # Authentication Modes
    googleworkspace_auth_subparser = googleworkspace_parser.add_argument_group(
        "Authentication Modes"
    )
    googleworkspace_auth_subparser.add_argument(
        "--impersonate-service-account",
        metavar="SERVICE_ACCOUNT",
        help="Impersonate a Google Service Account through Application Default Credentials and use it for Domain-Wide Delegation without a Service Account key (same as the GOOGLEWORKSPACE_IMPERSONATE_SERVICE_ACCOUNT environment variable)",
    )
