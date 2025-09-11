import argparse
from unittest.mock import MagicMock

from prowler.providers.mongodbatlas.lib.arguments import arguments


class TestMongoDBAtlasArguments:
    def setup_method(self):
        """Setup mock ArgumentParser for testing"""
        self.mock_parser = MagicMock()
        self.mock_subparsers = MagicMock()
        self.mock_mongodbatlas_parser = MagicMock()
        self.mock_auth_group = MagicMock()
        self.mock_filters_group = MagicMock()

        # Setup the mock chain
        self.mock_parser.add_subparsers.return_value = self.mock_subparsers
        self.mock_subparsers.add_parser.return_value = self.mock_mongodbatlas_parser
        self.mock_mongodbatlas_parser.add_argument_group.side_effect = [
            self.mock_auth_group,
            self.mock_filters_group,
        ]

    def test_init_parser_creates_subparser(self):
        """Test that init_parser creates the MongoDB Atlas subparser correctly"""
        # Create a mock object that has the necessary attributes
        mock_mongodbatlas_args = MagicMock()
        mock_mongodbatlas_args.subparsers = self.mock_subparsers
        mock_mongodbatlas_args.common_providers_parser = MagicMock()

        # Call init_parser
        arguments.init_parser(mock_mongodbatlas_args)

        # Verify subparser was created
        self.mock_subparsers.add_parser.assert_called_once_with(
            "mongodbatlas",
            parents=[mock_mongodbatlas_args.common_providers_parser],
            help="MongoDB Atlas Provider",
        )

    def test_init_parser_creates_argument_groups(self):
        """Test that init_parser creates the correct argument groups"""
        mock_mongodbatlas_args = MagicMock()
        mock_mongodbatlas_args.subparsers = self.mock_subparsers
        mock_mongodbatlas_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_mongodbatlas_args)

        # Verify argument groups were created
        assert self.mock_mongodbatlas_parser.add_argument_group.call_count == 2
        calls = self.mock_mongodbatlas_parser.add_argument_group.call_args_list
        assert calls[0][0][0] == "Authentication Modes"
        assert calls[1][0][0] == "Optional Filters"

    def test_init_parser_adds_authentication_arguments(self):
        """Test that init_parser adds all authentication arguments"""
        mock_mongodbatlas_args = MagicMock()
        mock_mongodbatlas_args.subparsers = self.mock_subparsers
        mock_mongodbatlas_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_mongodbatlas_args)

        # Verify authentication arguments were added
        assert self.mock_auth_group.add_argument.call_count == 2

        # Check that all authentication arguments are present
        calls = self.mock_auth_group.add_argument.call_args_list
        auth_args = [call[0][0] for call in calls]

        assert "--atlas-public-key" in auth_args
        assert "--atlas-private-key" in auth_args

    def test_init_parser_adds_filter_arguments(self):
        """Test that init_parser adds all filter arguments"""
        mock_mongodbatlas_args = MagicMock()
        mock_mongodbatlas_args.subparsers = self.mock_subparsers
        mock_mongodbatlas_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_mongodbatlas_args)

        # Verify filter arguments were added
        assert self.mock_filters_group.add_argument.call_count == 1

        # Check that all filter arguments are present
        calls = self.mock_filters_group.add_argument.call_args_list
        filter_args = [call[0][0] for call in calls]

        assert "--atlas-project-id" in filter_args

    def test_atlas_public_key_argument_configuration(self):
        """Test that atlas-public-key argument is configured correctly"""
        mock_mongodbatlas_args = MagicMock()
        mock_mongodbatlas_args.subparsers = self.mock_subparsers
        mock_mongodbatlas_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_mongodbatlas_args)

        # Find the atlas-public-key argument call
        calls = self.mock_auth_group.add_argument.call_args_list
        public_key_call = None
        for call in calls:
            if call[0][0] == "--atlas-public-key":
                public_key_call = call
                break

        assert public_key_call is not None

        # Check argument configuration
        kwargs = public_key_call[1]
        assert kwargs["nargs"] == "?"
        assert kwargs["default"] is None
        assert kwargs["metavar"] == "ATLAS_PUBLIC_KEY"
        assert "MongoDB Atlas API public key" in kwargs["help"]

    def test_atlas_private_key_argument_configuration(self):
        """Test that atlas-private-key argument is configured correctly"""
        mock_mongodbatlas_args = MagicMock()
        mock_mongodbatlas_args.subparsers = self.mock_subparsers
        mock_mongodbatlas_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_mongodbatlas_args)

        # Find the atlas-private-key argument call
        calls = self.mock_auth_group.add_argument.call_args_list
        private_key_call = None
        for call in calls:
            if call[0][0] == "--atlas-private-key":
                private_key_call = call
                break

        assert private_key_call is not None

        # Check argument configuration
        kwargs = private_key_call[1]
        assert kwargs["nargs"] == "?"
        assert kwargs["default"] is None
        assert kwargs["metavar"] == "ATLAS_PRIVATE_KEY"
        assert "MongoDB Atlas API private key" in kwargs["help"]

    def test_atlas_project_id_argument_configuration(self):
        """Test that atlas-project-id argument is configured correctly"""
        mock_mongodbatlas_args = MagicMock()
        mock_mongodbatlas_args.subparsers = self.mock_subparsers
        mock_mongodbatlas_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_mongodbatlas_args)

        # Find the atlas-project-id argument call
        calls = self.mock_filters_group.add_argument.call_args_list
        project_id_call = None
        for call in calls:
            if call[0][0] == "--atlas-project-id":
                project_id_call = call
                break

        assert project_id_call is not None

        # Check argument configuration
        kwargs = project_id_call[1]
        assert kwargs["nargs"] == "?"
        assert kwargs["default"] is None
        assert kwargs["metavar"] == "ATLAS_PROJECT_ID"
        assert (
            "MongoDB Atlas Project ID to filter scans to a specific project"
            in kwargs["help"]
        )


class TestMongoDBAtlasArgumentsIntegration:
    def test_real_argument_parsing_with_credentials(self):
        """Test parsing arguments with MongoDB Atlas credentials"""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        common_parser = argparse.ArgumentParser(add_help=False)

        # Create a mock object that mimics the structure used by the init_parser function
        mock_mongodbatlas_args = MagicMock()
        mock_mongodbatlas_args.subparsers = subparsers
        mock_mongodbatlas_args.common_providers_parser = common_parser

        arguments.init_parser(mock_mongodbatlas_args)

        # Parse arguments with credentials
        args = parser.parse_args(
            [
                "mongodbatlas",
                "--atlas-public-key",
                "test-public-key",
                "--atlas-private-key",
                "test-private-key",
            ]
        )

        assert args.atlas_public_key == "test-public-key"
        assert args.atlas_private_key == "test-private-key"
        assert args.atlas_project_id is None

    def test_real_argument_parsing_with_project_filter(self):
        """Test parsing arguments with project ID filter"""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        common_parser = argparse.ArgumentParser(add_help=False)

        mock_mongodbatlas_args = MagicMock()
        mock_mongodbatlas_args.subparsers = subparsers
        mock_mongodbatlas_args.common_providers_parser = common_parser

        arguments.init_parser(mock_mongodbatlas_args)

        # Parse arguments with project filter
        args = parser.parse_args(
            [
                "mongodbatlas",
                "--atlas-public-key",
                "test-public-key",
                "--atlas-private-key",
                "test-private-key",
                "--atlas-project-id",
                "68b188eb2c7c3f24d41bf0d8",
            ]
        )

        assert args.atlas_public_key == "test-public-key"
        assert args.atlas_private_key == "test-private-key"
        assert args.atlas_project_id == "68b188eb2c7c3f24d41bf0d8"

    def test_real_argument_parsing_without_credentials(self):
        """Test parsing arguments without credentials (should be None)"""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        common_parser = argparse.ArgumentParser(add_help=False)

        mock_mongodbatlas_args = MagicMock()
        mock_mongodbatlas_args.subparsers = subparsers
        mock_mongodbatlas_args.common_providers_parser = common_parser

        arguments.init_parser(mock_mongodbatlas_args)

        # Parse arguments without credentials
        args = parser.parse_args(["mongodbatlas"])

        assert args.atlas_public_key is None
        assert args.atlas_private_key is None
        assert args.atlas_project_id is None

    def test_real_argument_parsing_with_optional_values(self):
        """Test parsing arguments with optional values (nargs='?')"""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        common_parser = argparse.ArgumentParser(add_help=False)

        mock_mongodbatlas_args = MagicMock()
        mock_mongodbatlas_args.subparsers = subparsers
        mock_mongodbatlas_args.common_providers_parser = common_parser

        arguments.init_parser(mock_mongodbatlas_args)

        # Parse arguments with flags but no values (should be None due to nargs="?")
        args = parser.parse_args(
            [
                "mongodbatlas",
                "--atlas-public-key",
                "--atlas-private-key",
                "--atlas-project-id",
            ]
        )

        assert args.atlas_public_key is None
        assert args.atlas_private_key is None
        assert args.atlas_project_id is None

    def test_real_argument_parsing_mixed_optional_values(self):
        """Test parsing arguments with some values and some without"""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        common_parser = argparse.ArgumentParser(add_help=False)

        mock_mongodbatlas_args = MagicMock()
        mock_mongodbatlas_args.subparsers = subparsers
        mock_mongodbatlas_args.common_providers_parser = common_parser

        arguments.init_parser(mock_mongodbatlas_args)

        # Parse arguments with mixed values
        args = parser.parse_args(
            [
                "mongodbatlas",
                "--atlas-public-key",
                "test-public-key",
                "--atlas-private-key",  # No value provided
                "--atlas-project-id",
                "68b188eb2c7c3f24d41bf0d8",
            ]
        )

        assert args.atlas_public_key == "test-public-key"
        assert args.atlas_private_key is None
        assert args.atlas_project_id == "68b188eb2c7c3f24d41bf0d8"

    def test_validate_arguments_function(self):
        """Test that validate_arguments function works correctly"""
        # Test with valid arguments
        valid_args = MagicMock()
        valid_args.atlas_public_key = "test-public-key"
        valid_args.atlas_private_key = "test-private-key"
        valid_args.atlas_project_id = "68b188eb2c7c3f24d41bf0d8"

        is_valid, message = arguments.validate_arguments(valid_args)
        assert is_valid is True
        assert message == ""

        # Test with None values (should still be valid)
        none_args = MagicMock()
        none_args.atlas_public_key = None
        none_args.atlas_private_key = None
        none_args.atlas_project_id = None

        is_valid, message = arguments.validate_arguments(none_args)
        assert is_valid is True
        assert message == ""

    def test_real_argument_parsing_complete_configuration(self):
        """Test parsing arguments with complete configuration"""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        common_parser = argparse.ArgumentParser(add_help=False)

        mock_mongodbatlas_args = MagicMock()
        mock_mongodbatlas_args.subparsers = subparsers
        mock_mongodbatlas_args.common_providers_parser = common_parser

        arguments.init_parser(mock_mongodbatlas_args)

        # Parse arguments with complete configuration
        args = parser.parse_args(
            [
                "mongodbatlas",
                "--atlas-public-key",
                "test-public-key-123",
                "--atlas-private-key",
                "test-private-key-456",
                "--atlas-project-id",
                "68b188eb2c7c3f24d41bf0d8",
            ]
        )

        assert args.atlas_public_key == "test-public-key-123"
        assert args.atlas_private_key == "test-private-key-456"
        assert args.atlas_project_id == "68b188eb2c7c3f24d41bf0d8"
