SENSITIVE_ARGUMENTS = frozenset({"--oracledb-password"})


def init_parser(self):
    """Init the Oracle Database Provider CLI parser.

    The provider authenticates with a database user and password over a
    python-oracledb thin-mode connection. The password should be supplied
    via the `ORACLEDB_PASSWORD` environment variable; the flag accepts a
    value only for backward compatibility and its value is redacted in
    outputs.
    """
    oracledb_parser = self.subparsers.add_parser(
        "oracledb",
        parents=[self.common_providers_parser],
        help="Oracle Database Provider",
    )
    oracledb_auth_subparser = oracledb_parser.add_argument_group("Authentication")
    oracledb_auth_subparser.add_argument(
        "--oracledb-user",
        nargs="?",
        default=None,
        metavar="ORACLEDB_USER",
        help=(
            "Oracle Database user to connect with. Needs read access to the "
            "data dictionary (SELECT ANY DICTIONARY or SELECT_CATALOG_ROLE)."
        ),
    )
    oracledb_auth_subparser.add_argument(
        "--oracledb-password",
        nargs="?",
        default=None,
        metavar="ORACLEDB_PASSWORD",
        help=(
            "Password for the Oracle Database user. Use the ORACLEDB_PASSWORD "
            "environment variable instead of passing the value directly."
        ),
    )
    oracledb_connection_subparser = oracledb_parser.add_argument_group("Connection")
    oracledb_connection_subparser.add_argument(
        "--oracledb-dsn",
        nargs="?",
        default=None,
        metavar="ORACLEDB_DSN",
        help=(
            "Connect string, e.g. host:1521/service_name or a full Easy "
            "Connect string. Takes precedence over --oracledb-host/"
            "--oracledb-port/--oracledb-service-name."
        ),
    )
    oracledb_connection_subparser.add_argument(
        "--oracledb-host",
        nargs="?",
        default=None,
        metavar="ORACLEDB_HOST",
        help="Database listener host, used with --oracledb-service-name.",
    )
    oracledb_connection_subparser.add_argument(
        "--oracledb-port",
        type=int,
        default=None,
        metavar="ORACLEDB_PORT",
        help="Database listener port. Default: 1521.",
    )
    oracledb_connection_subparser.add_argument(
        "--oracledb-service-name",
        nargs="?",
        default=None,
        metavar="ORACLEDB_SERVICE_NAME",
        help="Database service name, used with --oracledb-host.",
    )
