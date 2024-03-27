from argparse import Namespace
from datetime import datetime
from os import rmdir

from freezegun import freeze_time
from mock import patch

from prowler.config.config import default_config_file_path
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.models import GCPIdentityInfo, GCPOutputOptions, GCPProject


class TestGCPProvider:
    def test_gcp_provider(self):
        arguments = Namespace()
        arguments.project_ids = []
        arguments.credentials_file = ""
        arguments.config_file = default_config_file_path

        projects = {
            "test-project": GCPProject(
                number="55555555",
                id="project/55555555",
                name="test-project",
                labels="",
                lifecycle_state="",
            )
        }
        with patch(
            "prowler.providers.gcp.gcp_provider.GcpProvider.setup_session",
            return_value=None,
        ), patch(
            "prowler.providers.gcp.gcp_provider.GcpProvider.get_projects",
            return_value=projects,
        ), patch(
            "prowler.providers.gcp.gcp_provider.GcpProvider.update_projects_with_organizations",
            return_value=None,
        ):
            gcp_provider = GcpProvider(arguments)
            assert gcp_provider.session is None
            assert gcp_provider.project_ids == ["test-project"]
            assert gcp_provider.projects == projects
            assert gcp_provider.identity == GCPIdentityInfo(profile="default")
            assert gcp_provider.audit_config == {"shodan_api_key": None}

    @freeze_time(datetime.today())
    def test_gcp_provider_output_options(self):
        arguments = Namespace()
        arguments.project_ids = []
        arguments.credentials_file = ""
        arguments.config_file = default_config_file_path

        # Output options
        arguments.status = []
        arguments.output_modes = ["csv"]
        arguments.output_directory = "output_test_directory"
        arguments.verbose = True
        arguments.only_logs = False
        arguments.unix_timestamp = False
        arguments.shodan = "test-api-key"

        projects = {
            "test-project": GCPProject(
                number="55555555",
                id="project/55555555",
                name="test-project",
                labels="",
                lifecycle_state="",
            )
        }
        with patch(
            "prowler.providers.gcp.gcp_provider.GcpProvider.setup_session",
            return_value=None,
        ), patch(
            "prowler.providers.gcp.gcp_provider.GcpProvider.get_projects",
            return_value=projects,
        ), patch(
            "prowler.providers.gcp.gcp_provider.GcpProvider.update_projects_with_organizations",
            return_value=None,
        ):
            gcp_provider = GcpProvider(arguments)
            gcp_provider.output_options = arguments, {}

            assert isinstance(gcp_provider.output_options, GCPOutputOptions)
            assert gcp_provider.output_options.status == []
            assert gcp_provider.output_options.output_modes == [
                "csv",
            ]
            assert (
                gcp_provider.output_options.output_directory
                == arguments.output_directory
            )
            assert gcp_provider.output_options.bulk_checks_metadata == {}
            assert gcp_provider.output_options.verbose
            assert (
                f"prowler-output-{gcp_provider.identity.profile}"
                in gcp_provider.output_options.output_filename
            )
            # Flaky due to the millisecond part of the timestamp
            # assert (
            #     gcp_provider.output_options.output_filename
            #     == f"prowler-output-{gcp_provider.identity.profile}-{datetime.today().strftime('%Y%m%d%H%M%S')}"
            # )

            # Delete testing directory
            # TODO: move this to a fixtures file
            rmdir(f"{arguments.output_directory}/compliance")
            rmdir(arguments.output_directory)
