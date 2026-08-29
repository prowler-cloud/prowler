def init_parser(self):
    """Init the Snowflake provider CLI parser."""
    snowflake_parser = self.subparsers.add_parser(
        "snowflake", parents=[self.common_providers_parser], help="Snowflake Provider"
    )

    # Authentication
    #
    # Snowflake key-pair authentication is used rather than a password: the service
    # user is created with TYPE = SERVICE and cannot sign in interactively.
    #
    # The private key and its passphrase are read exclusively from the environment.
    # They are never accepted as CLI flags, because a key passed on the command line
    # lands in shell history and in the process list, and the private key is the whole
    # credential -- there is no token to rotate separately.
    snowflake_auth_subparser = snowflake_parser.add_argument_group("Authentication")
    snowflake_auth_subparser.add_argument(
        "--account",
        nargs="?",
        default=None,
        metavar="ACCOUNT",
        help="Snowflake account identifier, e.g. myorg-myaccount. A full "
        "https://<account>.snowflakecomputing.com URL is also accepted. Falls back to "
        "the SNOWFLAKE_ACCOUNT environment variable.",
    )
    snowflake_auth_subparser.add_argument(
        "--user",
        nargs="?",
        default=None,
        metavar="USER",
        help="Snowflake user to authenticate as. Falls back to the SNOWFLAKE_USER "
        "environment variable.",
    )
    snowflake_auth_subparser.add_argument(
        "--private-key-path",
        nargs="?",
        default=None,
        metavar="PATH",
        help="Path to the PEM-encoded RSA private key. Falls back to the "
        "SNOWFLAKE_PRIVATE_KEY_PATH environment variable, or to the key content in "
        "SNOWFLAKE_PRIVATE_KEY. An encrypted key additionally needs "
        "SNOWFLAKE_PRIVATE_KEY_PASSPHRASE.",
    )

    # Session context
    snowflake_session_subparser = snowflake_parser.add_argument_group("Session")
    snowflake_session_subparser.add_argument(
        "--role",
        nargs="?",
        default=None,
        metavar="ROLE",
        help="Role to assume for the scan. Falls back to SNOWFLAKE_ROLE, then to the "
        "user's default role.",
    )
    snowflake_session_subparser.add_argument(
        "--warehouse",
        nargs="?",
        default=None,
        metavar="WAREHOUSE",
        help="Warehouse used to run the queries. Falls back to SNOWFLAKE_WAREHOUSE, "
        "then to the user's default warehouse.",
    )


def validate_arguments(arguments):
    """Validate the Snowflake provider arguments.

    Args:
        arguments: The parsed CLI arguments.

    Returns:
        tuple[bool, str]: Whether the combination is valid, and the reason if not.
    """
    return True, ""
