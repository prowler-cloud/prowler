from unittest.mock import MagicMock

from prowler.providers.okta.lib.arguments import arguments


class TestOktaArguments:
    def setup_method(self):
        self.mock_parser = MagicMock()
        self.mock_subparsers = MagicMock()
        self.mock_okta_parser = MagicMock()

        self.mock_parser.add_subparsers.return_value = self.mock_subparsers
        self.mock_subparsers.add_parser.return_value = self.mock_okta_parser

    def test_init_parser_creates_subparser(self):
        mock_args = MagicMock()
        mock_args.subparsers = self.mock_subparsers
        mock_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_args)

        self.mock_subparsers.add_parser.assert_called_once_with(
            "okta",
            parents=[mock_args.common_providers_parser],
            help="Okta Provider",
        )

    def test_init_parser_registers_non_secret_flags(self):
        mock_args = MagicMock()
        mock_args.subparsers = self.mock_subparsers
        mock_args.common_providers_parser = MagicMock()

        auth_group = MagicMock()
        self.mock_okta_parser.add_argument_group.return_value = auth_group

        arguments.init_parser(mock_args)

        registered = {call.args[0] for call in auth_group.add_argument.call_args_list}
        assert registered == {
            "--okta-org-url",
            "--okta-client-id",
            "--okta-scopes",
        }

    def test_secret_flags_not_registered(self):
        """Private key material must never be a CLI flag — env-only."""
        mock_args = MagicMock()
        mock_args.subparsers = self.mock_subparsers
        mock_args.common_providers_parser = MagicMock()

        auth_group = MagicMock()
        self.mock_okta_parser.add_argument_group.return_value = auth_group

        arguments.init_parser(mock_args)

        registered = {call.args[0] for call in auth_group.add_argument.call_args_list}
        assert "--okta-private-key" not in registered
        assert "--okta-private-key-file" not in registered

    def test_no_sensitive_arguments_constant(self):
        """No SENSITIVE_ARGUMENTS frozenset needed — no secret flags exist."""
        assert not hasattr(arguments, "SENSITIVE_ARGUMENTS")
