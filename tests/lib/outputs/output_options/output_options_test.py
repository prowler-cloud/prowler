from argparse import Namespace
from datetime import datetime
from unittest import mock

from freezegun import freeze_time

from prowler.config.config import output_file_timestamp
from prowler.providers.aws.models import AWSOutputOptions


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

        output_options = AWSOutputOptions(arguments, None, identity)

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
        assert not output_options.bulk_checks_metadata
