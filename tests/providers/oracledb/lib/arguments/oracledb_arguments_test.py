from unittest.mock import MagicMock

from prowler.providers.oracledb.lib.arguments import arguments


class TestOracledbArguments:
    def setup_method(self):
        self.mock_subparsers = MagicMock()
        self.mock_oracledb_parser = MagicMock()
        self.mock_subparsers.add_parser.return_value = self.mock_oracledb_parser

    def test_init_parser_creates_subparser(self):
        mock_args = MagicMock()
        mock_args.subparsers = self.mock_subparsers
        mock_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_args)

        self.mock_subparsers.add_parser.assert_called_once_with(
            "oracledb",
            parents=[mock_args.common_providers_parser],
            help="Oracle Database Provider",
        )

    def test_init_parser_registers_flags(self):
        mock_args = MagicMock()
        mock_args.subparsers = self.mock_subparsers
        mock_args.common_providers_parser = MagicMock()

        group = MagicMock()
        self.mock_oracledb_parser.add_argument_group.return_value = group

        arguments.init_parser(mock_args)

        registered = {call.args[0] for call in group.add_argument.call_args_list}
        assert registered == {
            "--oracledb-user",
            "--oracledb-password",
            "--oracledb-dsn",
            "--oracledb-host",
            "--oracledb-port",
            "--oracledb-service-name",
        }

    def test_password_flag_is_sensitive(self):
        """The password flag must be redacted in outputs and warned about."""
        assert "--oracledb-password" in arguments.SENSITIVE_ARGUMENTS
