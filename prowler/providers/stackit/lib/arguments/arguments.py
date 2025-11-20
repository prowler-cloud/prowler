def init_parser(self):
    """Init the StackIT Provider CLI parser"""
    stackit_parser = self.subparsers.add_parser(
        "stackit", parents=[self.common_providers_parser], help="StackIT Provider"
    )

    # Authentication
    stackit_auth_subparser = stackit_parser.add_argument_group("Authentication")
    stackit_auth_subparser.add_argument(
        "--stackit-api-token",
        nargs="?",
        default=None,
        help="StackIT API Token for authentication (alternatively set via STACKIT_API_TOKEN environment variable)",
    )
    stackit_auth_subparser.add_argument(
        "--stackit-project-id",
        nargs="?",
        default=None,
        help="StackIT Project ID to audit (alternatively set via STACKIT_PROJECT_ID environment variable)",
    )
