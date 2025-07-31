import argparse
from unittest.mock import MagicMock

from prowler.providers.github.lib.arguments import arguments


class Test_GitHubArguments:
    def setup_method(self):
        """Setup mock ArgumentParser for testing"""
        self.mock_parser = MagicMock()
        self.mock_subparsers = MagicMock()
        self.mock_github_parser = MagicMock()
        self.mock_auth_group = MagicMock()
        self.mock_scoping_group = MagicMock()

        # Setup the mock chain
        self.mock_parser.add_subparsers.return_value = self.mock_subparsers
        self.mock_subparsers.add_parser.return_value = self.mock_github_parser
        self.mock_github_parser.add_argument_group.side_effect = [
            self.mock_auth_group,
            self.mock_scoping_group,
        ]

    def test_init_parser_creates_subparser(self):
        """Test that init_parser creates the GitHub subparser correctly"""
        # Create a mock object that has the necessary attributes
        mock_github_args = MagicMock()
        mock_github_args.subparsers = self.mock_subparsers
        mock_github_args.common_providers_parser = MagicMock()

        # Call init_parser
        arguments.init_parser(mock_github_args)

        # Verify subparser was created
        self.mock_subparsers.add_parser.assert_called_once_with(
            "github",
            parents=[mock_github_args.common_providers_parser],
            help="GitHub Provider",
        )

    def test_init_parser_creates_argument_groups(self):
        """Test that init_parser creates the correct argument groups"""
        mock_github_args = MagicMock()
        mock_github_args.subparsers = self.mock_subparsers
        mock_github_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_github_args)

        # Verify argument groups were created
        assert self.mock_github_parser.add_argument_group.call_count == 2
        calls = self.mock_github_parser.add_argument_group.call_args_list
        assert calls[0][0][0] == "Authentication Modes"
        assert calls[1][0][0] == "Scan Scoping"

    def test_init_parser_adds_authentication_arguments(self):
        """Test that init_parser adds all authentication arguments"""
        mock_github_args = MagicMock()
        mock_github_args.subparsers = self.mock_subparsers
        mock_github_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_github_args)

        # Verify authentication arguments were added
        assert self.mock_auth_group.add_argument.call_count == 5

        # Check that all authentication arguments are present
        calls = self.mock_auth_group.add_argument.call_args_list
        auth_args = [call[0][0] for call in calls]

        assert "--personal-access-token" in auth_args
        assert "--oauth-app-token" in auth_args
        assert "--github-app-id" in auth_args
        assert "--github-app-key-path" in auth_args
        assert "--github-app-key" in auth_args

    def test_init_parser_adds_scoping_arguments(self):
        """Test that init_parser adds all scoping arguments"""
        mock_github_args = MagicMock()
        mock_github_args.subparsers = self.mock_subparsers
        mock_github_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_github_args)

        # Verify scoping arguments were added
        assert self.mock_scoping_group.add_argument.call_count == 2

        # Check that all scoping arguments are present
        calls = self.mock_scoping_group.add_argument.call_args_list
        scoping_args = [call[0][0] for call in calls]

        assert "--repository" in scoping_args
        assert "--organization" in scoping_args

    def test_repository_argument_configuration(self):
        """Test that repository argument is configured correctly"""
        mock_github_args = MagicMock()
        mock_github_args.subparsers = self.mock_subparsers
        mock_github_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_github_args)

        # Find the repository argument call
        calls = self.mock_scoping_group.add_argument.call_args_list
        repo_call = None
        for call in calls:
            if call[0][0] == "--repository":
                repo_call = call
                break

        assert repo_call is not None

        # Check argument configuration
        kwargs = repo_call[1]
        assert kwargs["nargs"] == "*"
        assert kwargs["default"] is None
        assert kwargs["metavar"] == "REPOSITORY"
        assert "owner/repo-name" in kwargs["help"]

    def test_organization_argument_configuration(self):
        """Test that organization argument is configured correctly"""
        mock_github_args = MagicMock()
        mock_github_args.subparsers = self.mock_subparsers
        mock_github_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_github_args)

        # Find the organization argument call
        calls = self.mock_scoping_group.add_argument.call_args_list
        org_call = None
        for call in calls:
            if call[0][0] == "--organization":
                org_call = call
                break

        assert org_call is not None

        # Check argument configuration
        kwargs = org_call[1]
        assert kwargs["nargs"] == "*"
        assert kwargs["default"] is None
        assert kwargs["metavar"] == "ORGANIZATION"
        assert "Organization or user name" in kwargs["help"]


class Test_GitHubArguments_Integration:
    def test_real_argument_parsing_no_scoping(self):
        """Test parsing arguments without scoping parameters"""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        common_parser = argparse.ArgumentParser(add_help=False)

        # Create a mock object that mimics the structure used by the init_parser function
        mock_github_args = MagicMock()
        mock_github_args.subparsers = subparsers
        mock_github_args.common_providers_parser = common_parser

        arguments.init_parser(mock_github_args)

        # Parse arguments without scoping
        args = parser.parse_args(["github", "--personal-access-token", "test-token"])

        assert args.personal_access_token == "test-token"
        assert args.repository is None
        assert args.organization is None

    def test_real_argument_parsing_with_repository(self):
        """Test parsing arguments with repository scoping"""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        common_parser = argparse.ArgumentParser(add_help=False)

        mock_github_args = MagicMock()
        mock_github_args.subparsers = subparsers
        mock_github_args.common_providers_parser = common_parser

        arguments.init_parser(mock_github_args)

        # Parse arguments with repository scoping
        args = parser.parse_args(
            [
                "github",
                "--personal-access-token",
                "test-token",
                "--repository",
                "owner1/repo1",
                "owner2/repo2",
            ]
        )

        assert args.personal_access_token == "test-token"
        assert args.repository == ["owner1/repo1", "owner2/repo2"]
        assert args.organization is None

    def test_real_argument_parsing_with_organization(self):
        """Test parsing arguments with organization scoping"""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        common_parser = argparse.ArgumentParser(add_help=False)

        mock_github_args = MagicMock()
        mock_github_args.subparsers = subparsers
        mock_github_args.common_providers_parser = common_parser

        arguments.init_parser(mock_github_args)

        # Parse arguments with organization scoping
        args = parser.parse_args(
            [
                "github",
                "--personal-access-token",
                "test-token",
                "--organization",
                "org1",
                "org2",
            ]
        )

        assert args.personal_access_token == "test-token"
        assert args.repository is None
        assert args.organization == ["org1", "org2"]

    def test_real_argument_parsing_with_both_scoping(self):
        """Test parsing arguments with both repository and organization scoping"""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        common_parser = argparse.ArgumentParser(add_help=False)

        mock_github_args = MagicMock()
        mock_github_args.subparsers = subparsers
        mock_github_args.common_providers_parser = common_parser

        arguments.init_parser(mock_github_args)

        # Parse arguments with both scoping types
        args = parser.parse_args(
            [
                "github",
                "--personal-access-token",
                "test-token",
                "--repository",
                "owner1/repo1",
                "--organization",
                "org1",
            ]
        )

        assert args.personal_access_token == "test-token"
        assert args.repository == ["owner1/repo1"]
        assert args.organization == ["org1"]

    def test_real_argument_parsing_single_values(self):
        """Test parsing arguments with single repository and organization values"""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        common_parser = argparse.ArgumentParser(add_help=False)

        mock_github_args = MagicMock()
        mock_github_args.subparsers = subparsers
        mock_github_args.common_providers_parser = common_parser

        arguments.init_parser(mock_github_args)

        # Parse arguments with single values
        args = parser.parse_args(
            [
                "github",
                "--personal-access-token",
                "test-token",
                "--repository",
                "owner1/repo1",
                "--organization",
                "org1",
            ]
        )

        assert args.personal_access_token == "test-token"
        assert args.repository == ["owner1/repo1"]
        assert args.organization == ["org1"]

    def test_real_argument_parsing_empty_scoping(self):
        """Test parsing arguments with empty scoping values"""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        common_parser = argparse.ArgumentParser(add_help=False)

        mock_github_args = MagicMock()
        mock_github_args.subparsers = subparsers
        mock_github_args.common_providers_parser = common_parser

        arguments.init_parser(mock_github_args)

        # Parse arguments with empty scoping flags
        args = parser.parse_args(
            [
                "github",
                "--personal-access-token",
                "test-token",
                "--repository",
                "--organization",
            ]
        )

        assert args.personal_access_token == "test-token"
        assert args.repository == []
        assert args.organization == []
