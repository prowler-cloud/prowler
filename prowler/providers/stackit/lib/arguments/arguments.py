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

    # Object Storage credentials
    stackit_objstorage_subparser = stackit_parser.add_argument_group("Object Storage Credentials")
    stackit_objstorage_subparser.add_argument(
        "--stackit-objectstorage-access-key",
        nargs="?",
        default=None,
        help="StackIT Object Storage Access Key (generate in STACKIT Portal under Object Storage > Credentials, alternatively set via STACKIT_OBJECTSTORAGE_ACCESS_KEY environment variable)",
    )
    stackit_objstorage_subparser.add_argument(
        "--stackit-objectstorage-secret-key",
        nargs="?",
        default=None,
        help="StackIT Object Storage Secret Key (generate in STACKIT Portal under Object Storage > Credentials, alternatively set via STACKIT_OBJECTSTORAGE_SECRET_KEY environment variable)",
    )
