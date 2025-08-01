import argparse
from unittest.mock import MagicMock

from prowler.providers.m365.lib.arguments import arguments


class TestM365Arguments:
    def setup_method(self):
        """Setup mock ArgumentParser for testing"""
        self.mock_parser = MagicMock()
        self.mock_subparsers = MagicMock()
        self.mock_m365_parser = MagicMock()
        self.mock_auth_group = MagicMock()
        self.mock_auth_modes_group = MagicMock()
        self.mock_regions_group = MagicMock()

        # Setup the mock chain
        self.mock_parser.add_subparsers.return_value = self.mock_subparsers
        self.mock_subparsers.add_parser.return_value = self.mock_m365_parser
        self.mock_m365_parser.add_argument_group.side_effect = [
            self.mock_auth_group,
            self.mock_regions_group,
        ]
        self.mock_auth_group.add_mutually_exclusive_group.return_value = (
            self.mock_auth_modes_group
        )

    def test_init_parser_creates_subparser(self):
        """Test that init_parser creates the M365 subparser correctly"""
        # Create a mock object that has the necessary attributes
        mock_m365_args = MagicMock()
        mock_m365_args.subparsers = self.mock_subparsers
        mock_m365_args.common_providers_parser = MagicMock()

        # Call init_parser
        arguments.init_parser(mock_m365_args)

        # Verify subparser was created
        self.mock_subparsers.add_parser.assert_called_once_with(
            "m365",
            parents=[mock_m365_args.common_providers_parser],
            help="M365 Provider",
        )

    def test_init_parser_creates_argument_groups(self):
        """Test that init_parser creates the correct argument groups"""
        mock_m365_args = MagicMock()
        mock_m365_args.subparsers = self.mock_subparsers
        mock_m365_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_m365_args)

        # Verify argument groups were created
        assert self.mock_m365_parser.add_argument_group.call_count == 2
        calls = self.mock_m365_parser.add_argument_group.call_args_list
        assert calls[0][0][0] == "Authentication Modes"
        assert calls[1][0][0] == "Regions"

    def test_init_parser_creates_mutually_exclusive_auth_group(self):
        """Test that init_parser creates mutually exclusive authentication group"""
        mock_m365_args = MagicMock()
        mock_m365_args.subparsers = self.mock_subparsers
        mock_m365_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_m365_args)

        # Verify mutually exclusive group was created for authentication modes
        self.mock_auth_group.add_mutually_exclusive_group.assert_called_once()

    def test_init_parser_adds_authentication_arguments(self):
        """Test that init_parser adds all authentication arguments"""
        mock_m365_args = MagicMock()
        mock_m365_args.subparsers = self.mock_subparsers
        mock_m365_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_m365_args)

        # Verify authentication arguments were added to the mutually exclusive group
        assert self.mock_auth_modes_group.add_argument.call_count == 5

        # Check that all authentication arguments are present
        calls = self.mock_auth_modes_group.add_argument.call_args_list
        auth_args = [call[0][0] for call in calls]

        assert "--az-cli-auth" in auth_args
        assert "--env-auth" in auth_args
        assert "--sp-env-auth" in auth_args
        assert "--browser-auth" in auth_args
        assert "--certificate-auth" in auth_args

    def test_init_parser_adds_non_exclusive_arguments(self):
        """Test that init_parser adds non-exclusive arguments directly to parser"""
        mock_m365_args = MagicMock()
        mock_m365_args.subparsers = self.mock_subparsers
        mock_m365_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_m365_args)

        # Verify non-exclusive arguments were added to main parser
        assert self.mock_m365_parser.add_argument.call_count == 2

        # Check that non-exclusive arguments are present
        calls = self.mock_m365_parser.add_argument.call_args_list
        non_exclusive_args = [call[0][0] for call in calls]

        assert "--tenant-id" in non_exclusive_args
        assert "--init-modules" in non_exclusive_args

    def test_init_parser_adds_region_arguments(self):
        """Test that init_parser adds region arguments"""
        mock_m365_args = MagicMock()
        mock_m365_args.subparsers = self.mock_subparsers
        mock_m365_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_m365_args)

        # Verify region arguments were added to regions group
        assert self.mock_regions_group.add_argument.call_count == 1

        # Check that region argument is present
        calls = self.mock_regions_group.add_argument.call_args_list
        region_args = [call[0][0] for call in calls]

        assert "--region" in region_args

    def test_az_cli_auth_argument_configuration(self):
        """Test that az-cli-auth argument is configured correctly"""
        mock_m365_args = MagicMock()
        mock_m365_args.subparsers = self.mock_subparsers
        mock_m365_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_m365_args)

        # Find the az-cli-auth argument call
        calls = self.mock_auth_modes_group.add_argument.call_args_list
        az_cli_call = None
        for call in calls:
            if call[0][0] == "--az-cli-auth":
                az_cli_call = call
                break

        assert az_cli_call is not None

        # Check argument configuration
        kwargs = az_cli_call[1]
        assert kwargs["action"] == "store_true"
        assert "Azure CLI authentication" in kwargs["help"]

    def test_env_auth_argument_configuration(self):
        """Test that env-auth argument is configured correctly"""
        mock_m365_args = MagicMock()
        mock_m365_args.subparsers = self.mock_subparsers
        mock_m365_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_m365_args)

        # Find the env-auth argument call
        calls = self.mock_auth_modes_group.add_argument.call_args_list
        env_auth_call = None
        for call in calls:
            if call[0][0] == "--env-auth":
                env_auth_call = call
                break

        assert env_auth_call is not None

        # Check argument configuration
        kwargs = env_auth_call[1]
        assert kwargs["action"] == "store_true"
        assert "User and Password environment variables" in kwargs["help"]

    def test_sp_env_auth_argument_configuration(self):
        """Test that sp-env-auth argument is configured correctly"""
        mock_m365_args = MagicMock()
        mock_m365_args.subparsers = self.mock_subparsers
        mock_m365_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_m365_args)

        # Find the sp-env-auth argument call
        calls = self.mock_auth_modes_group.add_argument.call_args_list
        sp_env_call = None
        for call in calls:
            if call[0][0] == "--sp-env-auth":
                sp_env_call = call
                break

        assert sp_env_call is not None

        # Check argument configuration
        kwargs = sp_env_call[1]
        assert kwargs["action"] == "store_true"
        assert "Azure Service Principal environment variables" in kwargs["help"]

    def test_browser_auth_argument_configuration(self):
        """Test that browser-auth argument is configured correctly"""
        mock_m365_args = MagicMock()
        mock_m365_args.subparsers = self.mock_subparsers
        mock_m365_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_m365_args)

        # Find the browser-auth argument call
        calls = self.mock_auth_modes_group.add_argument.call_args_list
        browser_auth_call = None
        for call in calls:
            if call[0][0] == "--browser-auth":
                browser_auth_call = call
                break

        assert browser_auth_call is not None

        # Check argument configuration
        kwargs = browser_auth_call[1]
        assert kwargs["action"] == "store_true"
        assert "Azure interactive browser authentication" in kwargs["help"]

    def test_certificate_auth_argument_configuration(self):
        """Test that certificate-auth argument is configured correctly"""
        mock_m365_args = MagicMock()
        mock_m365_args.subparsers = self.mock_subparsers
        mock_m365_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_m365_args)

        # Find the certificate-auth argument call
        calls = self.mock_auth_modes_group.add_argument.call_args_list
        cert_auth_call = None
        for call in calls:
            if call[0][0] == "--certificate-auth":
                cert_auth_call = call
                break

        assert cert_auth_call is not None

        # Check argument configuration
        kwargs = cert_auth_call[1]
        assert kwargs["action"] == "store_true"
        assert "Certificate authentication" in kwargs["help"]

    def test_tenant_id_argument_configuration(self):
        """Test that tenant-id argument is configured correctly"""
        mock_m365_args = MagicMock()
        mock_m365_args.subparsers = self.mock_subparsers
        mock_m365_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_m365_args)

        # Find the tenant-id argument call
        calls = self.mock_m365_parser.add_argument.call_args_list
        tenant_id_call = None
        for call in calls:
            if call[0][0] == "--tenant-id":
                tenant_id_call = call
                break

        assert tenant_id_call is not None

        # Check argument configuration
        kwargs = tenant_id_call[1]
        assert kwargs["nargs"] == "?"
        assert kwargs["default"] is None
        assert "Microsoft 365 Tenant ID" in kwargs["help"]
        assert "--browser-auth" in kwargs["help"]

    def test_init_modules_argument_configuration(self):
        """Test that init-modules argument is configured correctly"""
        mock_m365_args = MagicMock()
        mock_m365_args.subparsers = self.mock_subparsers
        mock_m365_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_m365_args)

        # Find the init-modules argument call
        calls = self.mock_m365_parser.add_argument.call_args_list
        init_modules_call = None
        for call in calls:
            if call[0][0] == "--init-modules":
                init_modules_call = call
                break

        assert init_modules_call is not None

        # Check argument configuration
        kwargs = init_modules_call[1]
        assert kwargs["action"] == "store_true"
        assert "Initialize Microsoft 365 PowerShell modules" in kwargs["help"]

    def test_region_argument_configuration(self):
        """Test that region argument is configured correctly"""
        mock_m365_args = MagicMock()
        mock_m365_args.subparsers = self.mock_subparsers
        mock_m365_args.common_providers_parser = MagicMock()

        arguments.init_parser(mock_m365_args)

        # Find the region argument call
        calls = self.mock_regions_group.add_argument.call_args_list
        region_call = None
        for call in calls:
            if call[0][0] == "--region":
                region_call = call
                break

        assert region_call is not None

        # Check argument configuration
        kwargs = region_call[1]
        assert kwargs["nargs"] == "?"
        assert kwargs["default"] == "M365Global"
        assert kwargs["choices"] == [
            "M365Global",
            "M365GlobalChina",
            "M365USGovernment",
        ]
        assert "Microsoft 365 region" in kwargs["help"]
        assert "M365Global" in kwargs["help"]


class TestM365ArgumentsIntegration:
    def test_real_argument_parsing_az_cli_auth(self):
        """Test parsing arguments with Azure CLI authentication"""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        common_parser = argparse.ArgumentParser(add_help=False)

        # Create a mock object that mimics the structure used by the init_parser function
        mock_m365_args = MagicMock()
        mock_m365_args.subparsers = subparsers
        mock_m365_args.common_providers_parser = common_parser

        arguments.init_parser(mock_m365_args)

        # Parse arguments with Azure CLI auth
        args = parser.parse_args(["m365", "--az-cli-auth"])

        assert args.az_cli_auth is True
        assert args.env_auth is False
        assert args.sp_env_auth is False
        assert args.browser_auth is False
        assert args.certificate_auth is False

    def test_real_argument_parsing_env_auth(self):
        """Test parsing arguments with environment authentication"""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        common_parser = argparse.ArgumentParser(add_help=False)

        mock_m365_args = MagicMock()
        mock_m365_args.subparsers = subparsers
        mock_m365_args.common_providers_parser = common_parser

        arguments.init_parser(mock_m365_args)

        # Parse arguments with environment auth
        args = parser.parse_args(["m365", "--env-auth"])

        assert args.az_cli_auth is False
        assert args.env_auth is True
        assert args.sp_env_auth is False
        assert args.browser_auth is False
        assert args.certificate_auth is False

    def test_real_argument_parsing_sp_env_auth(self):
        """Test parsing arguments with service principal environment authentication"""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        common_parser = argparse.ArgumentParser(add_help=False)

        mock_m365_args = MagicMock()
        mock_m365_args.subparsers = subparsers
        mock_m365_args.common_providers_parser = common_parser

        arguments.init_parser(mock_m365_args)

        # Parse arguments with service principal environment auth
        args = parser.parse_args(["m365", "--sp-env-auth"])

        assert args.az_cli_auth is False
        assert args.env_auth is False
        assert args.sp_env_auth is True
        assert args.browser_auth is False
        assert args.certificate_auth is False

    def test_real_argument_parsing_browser_auth_with_tenant_id(self):
        """Test parsing arguments with browser authentication and tenant ID"""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        common_parser = argparse.ArgumentParser(add_help=False)

        mock_m365_args = MagicMock()
        mock_m365_args.subparsers = subparsers
        mock_m365_args.common_providers_parser = common_parser

        arguments.init_parser(mock_m365_args)

        # Parse arguments with browser auth and tenant ID
        args = parser.parse_args(
            [
                "m365",
                "--browser-auth",
                "--tenant-id",
                "12345678-1234-5678-abcd-123456789012",
            ]
        )

        assert args.az_cli_auth is False
        assert args.env_auth is False
        assert args.sp_env_auth is False
        assert args.browser_auth is True
        assert args.certificate_auth is False
        assert args.tenant_id == "12345678-1234-5678-abcd-123456789012"

    def test_real_argument_parsing_certificate_auth(self):
        """Test parsing arguments with certificate authentication"""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        common_parser = argparse.ArgumentParser(add_help=False)

        mock_m365_args = MagicMock()
        mock_m365_args.subparsers = subparsers
        mock_m365_args.common_providers_parser = common_parser

        arguments.init_parser(mock_m365_args)

        # Parse arguments with certificate auth
        args = parser.parse_args(["m365", "--certificate-auth"])

        assert args.az_cli_auth is False
        assert args.env_auth is False
        assert args.sp_env_auth is False
        assert args.browser_auth is False
        assert args.certificate_auth is True

    def test_real_argument_parsing_with_init_modules(self):
        """Test parsing arguments with init modules flag"""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        common_parser = argparse.ArgumentParser(add_help=False)

        mock_m365_args = MagicMock()
        mock_m365_args.subparsers = subparsers
        mock_m365_args.common_providers_parser = common_parser

        arguments.init_parser(mock_m365_args)

        # Parse arguments with init modules
        args = parser.parse_args(["m365", "--az-cli-auth", "--init-modules"])

        assert args.az_cli_auth is True
        assert args.init_modules is True

    def test_real_argument_parsing_with_different_regions(self):
        """Test parsing arguments with different region options"""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        common_parser = argparse.ArgumentParser(add_help=False)

        mock_m365_args = MagicMock()
        mock_m365_args.subparsers = subparsers
        mock_m365_args.common_providers_parser = common_parser

        arguments.init_parser(mock_m365_args)

        # Test M365Global (default)
        args = parser.parse_args(["m365", "--az-cli-auth"])
        assert args.region == "M365Global"

        # Test M365GlobalChina
        args = parser.parse_args(
            ["m365", "--az-cli-auth", "--region", "M365GlobalChina"]
        )
        assert args.region == "M365GlobalChina"

        # Test M365USGovernment
        args = parser.parse_args(
            ["m365", "--az-cli-auth", "--region", "M365USGovernment"]
        )
        assert args.region == "M365USGovernment"

    def test_real_argument_parsing_no_authentication_defaults(self):
        """Test parsing arguments without any authentication flags (should have defaults)"""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        common_parser = argparse.ArgumentParser(add_help=False)

        mock_m365_args = MagicMock()
        mock_m365_args.subparsers = subparsers
        mock_m365_args.common_providers_parser = common_parser

        arguments.init_parser(mock_m365_args)

        # Parse arguments without explicit auth (defaults should apply)
        args = parser.parse_args(["m365"])

        assert args.az_cli_auth is False
        assert args.env_auth is False
        assert args.sp_env_auth is False
        assert args.browser_auth is False
        assert args.certificate_auth is False
        assert args.tenant_id is None
        assert args.init_modules is False
        assert args.region == "M365Global"

    def test_real_argument_parsing_complete_configuration(self):
        """Test parsing arguments with all non-exclusive options"""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        common_parser = argparse.ArgumentParser(add_help=False)

        mock_m365_args = MagicMock()
        mock_m365_args.subparsers = subparsers
        mock_m365_args.common_providers_parser = common_parser

        arguments.init_parser(mock_m365_args)

        # Parse arguments with complete configuration
        args = parser.parse_args(
            [
                "m365",
                "--browser-auth",
                "--tenant-id",
                "12345678-1234-5678-abcd-123456789012",
                "--init-modules",
                "--region",
                "M365USGovernment",
            ]
        )

        assert args.browser_auth is True
        assert args.tenant_id == "12345678-1234-5678-abcd-123456789012"
        assert args.init_modules is True
        assert args.region == "M365USGovernment"

    def test_mutually_exclusive_authentication_enforcement(self):
        """Test that authentication methods are mutually exclusive"""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        common_parser = argparse.ArgumentParser(add_help=False)

        mock_m365_args = MagicMock()
        mock_m365_args.subparsers = subparsers
        mock_m365_args.common_providers_parser = common_parser

        arguments.init_parser(mock_m365_args)

        # This should raise SystemExit due to mutually exclusive group
        try:
            parser.parse_args(["m365", "--az-cli-auth", "--env-auth"])
            assert False, "Expected SystemExit due to mutually exclusive arguments"
        except SystemExit:
            # This is expected
            pass

    def test_tenant_id_without_arguments(self):
        """Test that tenant-id can be specified without an argument (optional value)"""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        common_parser = argparse.ArgumentParser(add_help=False)

        mock_m365_args = MagicMock()
        mock_m365_args.subparsers = subparsers
        mock_m365_args.common_providers_parser = common_parser

        arguments.init_parser(mock_m365_args)

        # Parse arguments with tenant-id but no value (should be None due to nargs="?")
        args = parser.parse_args(["m365", "--az-cli-auth", "--tenant-id"])

        assert args.tenant_id is None
