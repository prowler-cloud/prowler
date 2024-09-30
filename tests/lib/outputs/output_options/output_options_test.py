from argparse import Namespace
from datetime import datetime
from os import rmdir
from unittest import mock

from freezegun import freeze_time

from prowler.config.config import output_file_timestamp
from prowler.providers.aws.models import AWSOutputOptions
from prowler.providers.azure.models import AzureOutputOptions
from prowler.providers.gcp.models import GCPOutputOptions
from prowler.providers.kubernetes.models import KubernetesOutputOptions


class Test_Output_Options:
    @freeze_time(datetime.today())
    def test_set_output_options_aws_no_output_filename(self):
        arguments = Namespace()
        arguments.status = ["FAIL"]
        arguments.output_formats = ["csv"]
        arguments.output_directory = "output_test_directory"
        arguments.verbose = True
        arguments.security_hub = True
        arguments.shodan = None
        arguments.only_logs = False
        arguments.unix_timestamp = False
        arguments.send_sh_only_fails = True

        identity = mock.MagicMock()
        identity.account = "123456789012"

        output_options = AWSOutputOptions(arguments, {}, identity)

        assert output_options.status == ["FAIL"]
        assert output_options.output_modes == ["csv", "json-asff"]
        assert output_options.output_directory == "output_test_directory"
        assert output_options.verbose
        assert output_options.security_hub_enabled
        assert not output_options.shodan_api_key
        assert not output_options.only_logs
        assert not output_options.unix_timestamp
        assert output_options.send_sh_only_fails
        assert (
            output_options.output_filename
            == f"prowler-output-{identity.account}-{output_file_timestamp}"
        )
        assert output_options.bulk_checks_metadata == {}

        rmdir(f"{arguments.output_directory}/compliance")
        rmdir(arguments.output_directory)

    @freeze_time(datetime.today())
    def test_set_output_options_aws(self):
        arguments = Namespace()
        arguments.status = []
        arguments.output_formats = ["csv"]
        arguments.output_directory = "output_test_directory"
        arguments.verbose = True
        arguments.output_filename = "output_test_filename"
        arguments.security_hub = True
        arguments.shodan = None
        arguments.only_logs = False
        arguments.unix_timestamp = False
        arguments.send_sh_only_fails = True

        identity = mock.MagicMock()
        identity.account = "123456789012"

        output_options = AWSOutputOptions(arguments, {}, identity)

        assert isinstance(output_options, AWSOutputOptions)
        assert output_options.security_hub_enabled
        assert output_options.send_sh_only_fails
        assert output_options.status == []
        assert output_options.output_modes == ["csv", "json-asff"]
        assert output_options.output_directory == arguments.output_directory
        assert output_options.bulk_checks_metadata == {}
        assert output_options.verbose
        assert output_options.output_filename == arguments.output_filename

        rmdir(f"{arguments.output_directory}/compliance")
        rmdir(arguments.output_directory)

    @freeze_time(datetime.today())
    def test_azure_provider_output_options_with_domain(self):
        arguments = Namespace()
        # Output Options
        arguments.output_formats = ["csv"]
        arguments.output_directory = "output_test_directory"
        output_directory = arguments.output_directory
        arguments.status = []
        arguments.verbose = True
        arguments.only_logs = False
        arguments.unix_timestamp = False
        arguments.shodan = None

        identity = mock.MagicMock()
        identity.tenant_domain = "test-domain"

        output_options = AzureOutputOptions(
            arguments,
            {},
            identity,
        )

        assert isinstance(output_options, AzureOutputOptions)
        assert output_options.status == []
        assert output_options.output_modes == [
            "csv",
        ]
        assert output_options.output_directory == output_directory
        assert output_options.bulk_checks_metadata == {}
        assert output_options.verbose
        assert (
            output_options.output_filename
            == f"prowler-output-{identity.tenant_domain}-{output_file_timestamp}"
        )

        rmdir(f"{arguments.output_directory}/compliance")
        rmdir(arguments.output_directory)

    @freeze_time(datetime.today())
    def test_gcp_output_options(self):
        arguments = Namespace()
        # Output options
        arguments.status = []
        arguments.output_formats = ["csv"]
        arguments.output_directory = "output_test_directory"
        arguments.verbose = True
        arguments.only_logs = False
        arguments.unix_timestamp = False
        arguments.shodan = None

        identity = mock.MagicMock()
        identity.profile = "test-profile"

        output_optionss = GCPOutputOptions(
            arguments,
            {},
            identity,
        )

        assert isinstance(output_optionss, GCPOutputOptions)
        assert output_optionss.status == []
        assert output_optionss.output_modes == [
            "csv",
        ]
        assert output_optionss.output_directory == arguments.output_directory
        assert output_optionss.bulk_checks_metadata == {}
        assert output_optionss.verbose
        assert f"prowler-output-{identity.profile}" in output_optionss.output_filename

        rmdir(f"{arguments.output_directory}/compliance")
        rmdir(arguments.output_directory)

    def test_set_output_options_kubernetes(self):
        arguments = Namespace()
        arguments.status = []
        arguments.output_formats = ["csv"]
        arguments.output_directory = "output_test_directory"
        arguments.verbose = True
        arguments.output_filename = "output_test_filename"
        arguments.only_logs = False
        arguments.unix_timestamp = False
        arguments.shodan = None

        identity = mock.MagicMock()
        identity.context = "test-context"

        output_options = KubernetesOutputOptions(
            arguments,
            {},
            identity,
        )

        assert isinstance(output_options, KubernetesOutputOptions)
        assert output_options.status == []
        assert output_options.output_modes == ["csv"]
        assert output_options.output_directory == arguments.output_directory
        assert output_options.bulk_checks_metadata == {}
        assert output_options.verbose
        assert output_options.output_filename == arguments.output_filename

        rmdir(f"{arguments.output_directory}/compliance")
        rmdir(arguments.output_directory)
