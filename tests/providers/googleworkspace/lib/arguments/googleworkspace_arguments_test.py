import argparse
from unittest.mock import MagicMock

from prowler.providers.googleworkspace.lib.arguments import arguments


class TestGoogleWorkspaceArguments:
    def setup_method(self):
        """Setup mock ArgumentParser for testing"""
        self.mock_parser = MagicMock()
        self.mock_subparsers = MagicMock()
        self.mock_googleworkspace_parser = MagicMock()
        self.mock_delegation_group = MagicMock()

        self.mock_parser.add_subparsers.return_value = self.mock_subparsers
        self.mock_subparsers.add_parser.return_value = self.mock_googleworkspace_parser
        self.mock_googleworkspace_parser.add_argument_group.return_value = (
            self.mock_delegation_group
        )

    def test_init_parser_creates_subparser(self):
        """Test that init_parser creates the googleworkspace subparser correctly"""
        mock_args = MagicMock()
        mock_args.subparsers = self.mock_subparsers
        mock_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_args)

        self.mock_subparsers.add_parser.assert_called_once_with(
            "googleworkspace",
            parents=[mock_args.common_providers_parser],
            help="Google Workspace Provider",
        )

    def test_init_parser_creates_argument_groups(self):
        """Test that init_parser creates the correct argument groups"""
        mock_args = MagicMock()
        mock_args.subparsers = self.mock_subparsers
        mock_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_args)

        assert self.mock_googleworkspace_parser.add_argument_group.call_count == 1
        calls = self.mock_googleworkspace_parser.add_argument_group.call_args_list
        assert calls[0][0][0] == "Domain-Wide Delegation"

    def test_init_parser_adds_delegated_user_argument(self):
        """Test that init_parser adds the --delegated-user argument"""
        mock_args = MagicMock()
        mock_args.subparsers = self.mock_subparsers
        mock_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_args)

        assert self.mock_delegation_group.add_argument.call_count == 1
        calls = self.mock_delegation_group.add_argument.call_args_list
        assert calls[0][0][0] == "--delegated-user"

    def test_delegated_user_argument_configuration(self):
        """Test that --delegated-user argument is configured correctly"""
        mock_args = MagicMock()
        mock_args.subparsers = self.mock_subparsers
        mock_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_args)

        calls = self.mock_delegation_group.add_argument.call_args_list
        delegated_user_call = calls[0]
        kwargs = delegated_user_call[1]

        assert kwargs["nargs"] == "?"
        assert kwargs["metavar"] == "EMAIL"
        assert kwargs["default"] is None


class TestGoogleWorkspaceArgumentsIntegration:
    def test_real_argument_parsing_with_delegated_user(self):
        """Test parsing arguments with --delegated-user"""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        common_parser = argparse.ArgumentParser(add_help=False)

        mock_args = MagicMock()
        mock_args.subparsers = subparsers
        mock_args.common_providers_parser = common_parser

        arguments.init_parser(mock_args)

        args = parser.parse_args(
            ["googleworkspace", "--delegated-user", "admin@example.com"]
        )

        assert args.delegated_user == "admin@example.com"

    def test_real_argument_parsing_without_delegated_user(self):
        """Test parsing arguments without --delegated-user defaults to None"""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        common_parser = argparse.ArgumentParser(add_help=False)

        mock_args = MagicMock()
        mock_args.subparsers = subparsers
        mock_args.common_providers_parser = common_parser

        arguments.init_parser(mock_args)

        args = parser.parse_args(["googleworkspace"])

        assert args.delegated_user is None
