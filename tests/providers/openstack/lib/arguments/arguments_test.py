"""Tests for OpenStack Provider CLI arguments."""

from argparse import ArgumentParser, Namespace

import pytest

from prowler.providers.openstack.lib.arguments.arguments import (
    init_parser,
    validate_arguments,
)


class TestOpenstackArguments:
    """Test suite for OpenStack Provider CLI arguments."""

    @pytest.fixture
    def parser(self):
        """Create a basic argument parser for testing."""
        parser = ArgumentParser()
        parser.common_providers_parser = ArgumentParser(add_help=False)
        parser.subparsers = parser.add_subparsers(dest="provider")
        init_parser(parser)
        return parser

    def test_init_parser_creates_openstack_subparser(self, parser):
        """Test that init_parser creates the OpenStack subparser."""
        args = parser.parse_args(["openstack"])
        assert args.provider == "openstack"

    def test_clouds_yaml_file_argument(self, parser):
        """Test that --clouds-yaml-file argument is parsed correctly."""
        args = parser.parse_args(
            ["openstack", "--clouds-yaml-file", "/path/to/clouds.yaml"]
        )
        assert args.clouds_yaml_file == "/path/to/clouds.yaml"

    def test_clouds_yaml_cloud_argument(self, parser):
        """Test that --clouds-yaml-cloud argument is parsed correctly."""
        args = parser.parse_args(["openstack", "--clouds-yaml-cloud", "production"])
        assert args.clouds_yaml_cloud == "production"

    def test_os_auth_url_argument(self, parser):
        """Test that --os-auth-url argument is parsed correctly."""
        args = parser.parse_args(
            ["openstack", "--os-auth-url", "https://openstack.example.com:5000/v3"]
        )
        assert args.os_auth_url == "https://openstack.example.com:5000/v3"

    def test_os_username_argument(self, parser):
        """Test that --os-username argument is parsed correctly."""
        args = parser.parse_args(["openstack", "--os-username", "test-user"])
        assert args.os_username == "test-user"

    def test_os_password_argument(self, parser):
        """Test that --os-password argument is parsed correctly."""
        args = parser.parse_args(["openstack", "--os-password", "test-password"])
        assert args.os_password == "test-password"

    def test_os_project_id_argument(self, parser):
        """Test that --os-project-id argument is parsed correctly."""
        args = parser.parse_args(["openstack", "--os-project-id", "test-project-id"])
        assert args.os_project_id == "test-project-id"

    def test_os_region_name_argument(self, parser):
        """Test that --os-region-name argument is parsed correctly."""
        args = parser.parse_args(["openstack", "--os-region-name", "RegionOne"])
        assert args.os_region_name == "RegionOne"

    def test_os_user_domain_name_argument(self, parser):
        """Test that --os-user-domain-name argument is parsed correctly."""
        args = parser.parse_args(["openstack", "--os-user-domain-name", "CustomDomain"])
        assert args.os_user_domain_name == "CustomDomain"

    def test_os_project_domain_name_argument(self, parser):
        """Test that --os-project-domain-name argument is parsed correctly."""
        args = parser.parse_args(
            ["openstack", "--os-project-domain-name", "CustomProjectDomain"]
        )
        assert args.os_project_domain_name == "CustomProjectDomain"

    def test_os_identity_api_version_argument(self, parser):
        """Test that --os-identity-api-version argument is parsed correctly."""
        args = parser.parse_args(["openstack", "--os-identity-api-version", "3"])
        assert args.os_identity_api_version == "3"


class TestOpenstackArgumentsValidation:
    """Test suite for OpenStack Provider CLI arguments validation."""

    def test_validate_arguments_with_no_options(self):
        """Test validation with no authentication options (should pass - env vars will be used)."""
        args = Namespace(
            clouds_yaml_file=None,
            clouds_yaml_cloud=None,
            os_auth_url=None,
            os_username=None,
            os_password=None,
            os_project_id=None,
            os_user_domain_name=None,
            os_project_domain_name=None,
        )

        is_valid, error_message = validate_arguments(args)
        assert is_valid is True
        assert error_message == ""

    def test_validate_arguments_with_clouds_yaml_only(self):
        """Test validation with only clouds.yaml options (should pass)."""
        args = Namespace(
            clouds_yaml_file="/path/to/clouds.yaml",
            clouds_yaml_cloud="production",
            os_auth_url=None,
            os_username=None,
            os_password=None,
            os_project_id=None,
            os_user_domain_name=None,
            os_project_domain_name=None,
        )

        is_valid, error_message = validate_arguments(args)
        assert is_valid is True
        assert error_message == ""

    def test_validate_arguments_with_explicit_credentials_only(self):
        """Test validation with only explicit credentials (should pass)."""
        args = Namespace(
            clouds_yaml_file=None,
            clouds_yaml_cloud=None,
            os_auth_url="https://openstack.example.com:5000/v3",
            os_username="test-user",
            os_password="test-password",
            os_project_id="test-project-id",
            os_user_domain_name="Default",
            os_project_domain_name="Default",
        )

        is_valid, error_message = validate_arguments(args)
        assert is_valid is True
        assert error_message == ""

    def test_validate_arguments_mutual_exclusivity_clouds_yaml_file_and_explicit(self):
        """Test validation fails when both clouds_yaml_file and explicit credentials are provided."""
        args = Namespace(
            clouds_yaml_file="/path/to/clouds.yaml",
            clouds_yaml_cloud="production",
            os_auth_url="https://openstack.example.com:5000/v3",
            os_username="test-user",
            os_password="test-password",
            os_project_id="test-project-id",
            os_user_domain_name=None,
            os_project_domain_name=None,
        )

        is_valid, error_message = validate_arguments(args)
        assert is_valid is False
        assert "Cannot use clouds.yaml options" in error_message
        assert "together with explicit credential parameters" in error_message

    def test_validate_arguments_mutual_exclusivity_clouds_yaml_cloud_and_explicit(self):
        """Test validation fails when both clouds_yaml_cloud and explicit credentials are provided."""
        args = Namespace(
            clouds_yaml_file=None,
            clouds_yaml_cloud="production",
            os_auth_url="https://openstack.example.com:5000/v3",
            os_username="test-user",
            os_password=None,
            os_project_id=None,
            os_user_domain_name=None,
            os_project_domain_name=None,
        )

        is_valid, error_message = validate_arguments(args)
        assert is_valid is False
        assert "Cannot use clouds.yaml options" in error_message

    def test_validate_arguments_mutual_exclusivity_with_partial_explicit_credentials(
        self,
    ):
        """Test validation fails when clouds.yaml and partial explicit credentials are provided."""
        args = Namespace(
            clouds_yaml_file="/path/to/clouds.yaml",
            clouds_yaml_cloud=None,
            os_auth_url=None,
            os_username="test-user",  # Only one explicit credential
            os_password=None,
            os_project_id=None,
            os_user_domain_name=None,
            os_project_domain_name=None,
        )

        is_valid, error_message = validate_arguments(args)
        assert is_valid is False
        assert "Cannot use clouds.yaml options" in error_message

    def test_validate_arguments_clouds_yaml_file_only(self):
        """Test validation passes with only clouds_yaml_file (cloud name defaults to 'envvars')."""
        args = Namespace(
            clouds_yaml_file="/path/to/clouds.yaml",
            clouds_yaml_cloud=None,
            os_auth_url=None,
            os_username=None,
            os_password=None,
            os_project_id=None,
            os_user_domain_name=None,
            os_project_domain_name=None,
        )

        is_valid, error_message = validate_arguments(args)
        assert is_valid is True
        assert error_message == ""

    def test_validate_arguments_clouds_yaml_cloud_only(self):
        """Test validation passes with only clouds_yaml_cloud (file searched in standard locations)."""
        args = Namespace(
            clouds_yaml_file=None,
            clouds_yaml_cloud="production",
            os_auth_url=None,
            os_username=None,
            os_password=None,
            os_project_id=None,
            os_user_domain_name=None,
            os_project_domain_name=None,
        )

        is_valid, error_message = validate_arguments(args)
        assert is_valid is True
        assert error_message == ""

    def test_validate_arguments_with_domain_names_only(self):
        """Test validation passes with only domain names (not considered explicit credentials)."""
        args = Namespace(
            clouds_yaml_file=None,
            clouds_yaml_cloud=None,
            os_auth_url=None,
            os_username=None,
            os_password=None,
            os_project_id=None,
            os_user_domain_name="CustomUserDomain",
            os_project_domain_name="CustomProjectDomain",
        )

        # Domain names alone don't trigger mutual exclusivity
        is_valid, error_message = validate_arguments(args)
        assert is_valid is True
        assert error_message == ""
