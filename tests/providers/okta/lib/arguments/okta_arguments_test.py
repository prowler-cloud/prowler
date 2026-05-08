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

    def test_init_parser_registers_oauth_flags(self):
        mock_args = MagicMock()
        mock_args.subparsers = self.mock_subparsers
        mock_args.common_providers_parser = MagicMock()

        auth_group = MagicMock()
        self.mock_okta_parser.add_argument_group.return_value = auth_group

        arguments.init_parser(mock_args)

        registered = {call.args[0] for call in auth_group.add_argument.call_args_list}
        assert {
            "--okta-org-url",
            "--okta-client-id",
            "--okta-private-key-file",
            "--okta-scopes",
            "--okta-kid",
        }.issubset(registered)

    def test_sensitive_arguments_set(self):
        assert "--okta-private-key-file" in arguments.SENSITIVE_ARGUMENTS
