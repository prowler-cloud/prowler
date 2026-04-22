from unittest.mock import MagicMock

from prowler.providers.googleworkspace.lib.arguments import arguments


class TestGoogleWorkspaceArguments:
    def setup_method(self):
        """Setup mock ArgumentParser for testing"""
        self.mock_parser = MagicMock()
        self.mock_subparsers = MagicMock()
        self.mock_googleworkspace_parser = MagicMock()

        self.mock_parser.add_subparsers.return_value = self.mock_subparsers
        self.mock_subparsers.add_parser.return_value = self.mock_googleworkspace_parser

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
