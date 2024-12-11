from argparse import Namespace
from datetime import datetime
from os import environ

import pytest
from freezegun import freeze_time
from mock import MagicMock, patch

from prowler.config.config import (
    default_config_file_path,
    default_fixer_config_file_path,
    load_and_validate_config_file,
)
from prowler.providers.common.models import Connection
from prowler.providers.gcp.exceptions.exceptions import (
    GCPInvalidProviderIdError,
    GCPNoAccesibleProjectsError,
    GCPTestConnectionError,
)
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.models import GCPIdentityInfo, GCPOrganization, GCPProject


class TestGCPProvider:
    def test_gcp_provider(self):
        project_id = []
        excluded_project_id = []
        list_project_id = False
        credentials_file = ""
        impersonate_service_account = ""
        fixer_config = load_and_validate_config_file(
            "gcp", default_fixer_config_file_path
        )
        client_id = "test-client-id"
        client_secret = "test-client-secret"
        refresh_token = "test-refresh-token"

        projects = {
            "test-project": GCPProject(
                number="55555555",
                id="project/55555555",
                name="test-project",
                labels={"test": "value"},
                lifecycle_state="ACTIVE",
            )
        }

        mocked_service = MagicMock()

        mocked_service.projects.list.return_value = MagicMock(
            execute=MagicMock(return_value={"projects": projects})
        )

        with (
            patch(
                "prowler.providers.gcp.gcp_provider.GcpProvider.setup_session",
                return_value=(None, "test-project"),
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.GcpProvider.get_projects",
                return_value=projects,
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.GcpProvider.update_projects_with_organizations",
                return_value=None,
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.discovery.build",
                return_value=mocked_service,
            ),
        ):
            gcp_provider = GcpProvider(
                project_id,
                excluded_project_id,
                credentials_file,
                impersonate_service_account,
                list_project_id,
                config_path=default_config_file_path,
                fixer_config=fixer_config,
                client_id=client_id,
                client_secret=client_secret,
                refresh_token=refresh_token,
            )
            assert gcp_provider.session is None
            assert gcp_provider.project_ids == ["test-project"]
            assert gcp_provider.projects == projects
            assert gcp_provider.default_project_id == "test-project"
            assert gcp_provider.identity == GCPIdentityInfo(profile="default")
            assert gcp_provider.audit_config == {"shodan_api_key": None}

    @freeze_time(datetime.today())
    def test_is_project_matching(self):
        arguments = Namespace()
        arguments.project_id = []
        arguments.excluded_project_id = []
        arguments.organization_id = None
        arguments.list_project_id = False
        arguments.credentials_file = ""
        arguments.impersonate_service_account = ""
        arguments.config_file = default_config_file_path
        arguments.fixer_config = default_fixer_config_file_path

        # Output options
        arguments.status = []
        arguments.output_formats = ["csv"]
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
                labels={"test": "value"},
                lifecycle_state="ACTIVE",
            )
        }

        mocked_service = MagicMock()

        mocked_service.projects.list.return_value = MagicMock(
            execute=MagicMock(return_value={"projects": projects})
        )
        with (
            patch(
                "prowler.providers.gcp.gcp_provider.GcpProvider.setup_session",
                return_value=(None, None),
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.GcpProvider.get_projects",
                return_value=projects,
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.GcpProvider.update_projects_with_organizations",
                return_value=None,
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.discovery.build",
                return_value=mocked_service,
            ),
        ):
            gcp_provider = GcpProvider(
                arguments.organization_id,
                arguments.project_id,
                arguments.excluded_project_id,
                arguments.credentials_file,
                arguments.impersonate_service_account,
                arguments.list_project_id,
                arguments.config_file,
                arguments.fixer_config,
                client_id="test-client-id",
                client_secret="test-client-secret",
                refresh_token="test-refresh-token",
            )

            input_project = "sys-*"
            project_to_match = "sys-12345678"
            assert gcp_provider.is_project_matching(input_project, project_to_match)
            input_project = "*prowler"
            project_to_match = "test-prowler"
            assert gcp_provider.is_project_matching(input_project, project_to_match)
            input_project = "test-project"
            project_to_match = "test-project"
            assert gcp_provider.is_project_matching(input_project, project_to_match)
            input_project = "*test*"
            project_to_match = "prowler-test-project"
            assert gcp_provider.is_project_matching(input_project, project_to_match)
            input_project = "prowler-test-project"
            project_to_match = "prowler-test"
            assert not gcp_provider.is_project_matching(input_project, project_to_match)

    def test_setup_session_with_credentials_file_no_impersonate(self):
        mocked_credentials = MagicMock()

        mocked_credentials.refresh.return_value = None
        mocked_credentials._service_account_email = "test-service-account-email"

        arguments = Namespace()
        arguments.project_id = []
        arguments.excluded_project_id = []
        arguments.organization_id = None
        arguments.list_project_id = False
        arguments.credentials_file = "test_credentials_file"
        arguments.impersonate_service_account = ""
        arguments.config_file = default_config_file_path
        arguments.fixer_config = default_fixer_config_file_path

        projects = {
            "test-project": GCPProject(
                number="55555555",
                id="project/55555555",
                name="test-project",
                labels={"test": "value"},
                lifecycle_state="ACTIVE",
            )
        }

        mocked_service = MagicMock()

        mocked_service.projects.list.return_value = MagicMock(
            execute=MagicMock(return_value={"projects": projects})
        )
        with (
            patch(
                "prowler.providers.gcp.gcp_provider.GcpProvider.get_projects",
                return_value=projects,
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.GcpProvider.update_projects_with_organizations",
                return_value=None,
            ),
            patch(
                "os.path.abspath",
                return_value="test_credentials_file",
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.default",
                return_value=(mocked_credentials, MagicMock()),
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.discovery.build",
                return_value=mocked_service,
            ),
        ):
            gcp_provider = GcpProvider(
                arguments.organization_id,
                arguments.project_id,
                arguments.excluded_project_id,
                arguments.credentials_file,
                arguments.impersonate_service_account,
                arguments.list_project_id,
                arguments.config_file,
                arguments.fixer_config,
                client_id=None,
                client_secret=None,
                refresh_token=None,
            )
            assert environ["GOOGLE_APPLICATION_CREDENTIALS"] == "test_credentials_file"
            assert gcp_provider.session is not None
            assert gcp_provider.identity.profile == "test-service-account-email"

    def test_setup_session_with_credentials_file_and_impersonate(self):
        mocked_credentials = MagicMock()

        mocked_credentials.refresh.return_value = None
        mocked_credentials._service_account_email = "test-service-account-email"

        arguments = Namespace()
        arguments.project_id = []
        arguments.excluded_project_id = []
        arguments.organization_id = None
        arguments.list_project_id = False
        arguments.credentials_file = "test_credentials_file"
        arguments.impersonate_service_account = "test-impersonate-service-account"
        arguments.config_file = default_config_file_path
        arguments.fixer_config = default_fixer_config_file_path

        projects = {
            "test-project": GCPProject(
                number="55555555",
                id="project/55555555",
                name="test-project",
                labels={"test": "value"},
                lifecycle_state="ACTIVE",
            )
        }

        mocked_service = MagicMock()

        mocked_service.projects.list.return_value = MagicMock(
            execute=MagicMock(return_value={"projects": projects})
        )
        with (
            patch(
                "prowler.providers.gcp.gcp_provider.GcpProvider.get_projects",
                return_value=projects,
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.GcpProvider.update_projects_with_organizations",
                return_value=None,
            ),
            patch(
                "os.path.abspath",
                return_value="test_credentials_file",
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.default",
                return_value=(mocked_credentials, MagicMock()),
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.discovery.build",
                return_value=mocked_service,
            ),
        ):
            gcp_provider = GcpProvider(
                arguments.organization_id,
                arguments.project_id,
                arguments.excluded_project_id,
                arguments.credentials_file,
                arguments.impersonate_service_account,
                arguments.list_project_id,
                arguments.config_file,
                arguments.fixer_config,
                client_id=None,
                client_secret=None,
                refresh_token=None,
            )
            assert environ["GOOGLE_APPLICATION_CREDENTIALS"] == "test_credentials_file"
            assert gcp_provider.session is not None
            assert (
                gcp_provider.session.service_account_email
                == "test-impersonate-service-account"
            )
            assert gcp_provider.identity.profile == "default"
            assert (
                gcp_provider.impersonated_service_account
                == "test-impersonate-service-account"
            )

    def test_setup_session_with_organization_id(self):
        mocked_credentials = MagicMock()

        mocked_credentials.refresh.return_value = None
        mocked_credentials._service_account_email = "test-service-account-email"

        arguments = Namespace()
        arguments.project_id = []
        arguments.excluded_project_id = []
        arguments.organization_id = "test-organization-id"
        arguments.list_project_id = False
        arguments.credentials_file = "test_credentials_file"
        arguments.impersonate_service_account = ""
        arguments.config_file = default_config_file_path
        arguments.fixer_config = default_fixer_config_file_path

        projects = {
            "test-project": GCPProject(
                number="55555555",
                id="project/55555555",
                name="test-project",
                labels={"test": "value"},
                lifecycle_state="ACTIVE",
                organization=GCPOrganization(
                    id="test-organization-id",
                    name="test-organization",
                    display_name="Test Organization",
                ),
            )
        }

        mocked_service = MagicMock()

        mocked_service.projects.list.return_value = MagicMock(
            execute=MagicMock(return_value={"projects": projects})
        )
        with (
            patch(
                "prowler.providers.gcp.gcp_provider.GcpProvider.get_projects",
                return_value=projects,
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.GcpProvider.update_projects_with_organizations",
                return_value=None,
            ),
            patch(
                "os.path.abspath",
                return_value="test_credentials_file",
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.default",
                return_value=(mocked_credentials, MagicMock()),
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.discovery.build",
                return_value=mocked_service,
            ),
        ):
            gcp_provider = GcpProvider(
                arguments.organization_id,
                arguments.project_id,
                arguments.excluded_project_id,
                arguments.credentials_file,
                arguments.impersonate_service_account,
                arguments.list_project_id,
                arguments.config_file,
                arguments.fixer_config,
                client_id=None,
                client_secret=None,
                refresh_token=None,
            )
            assert environ["GOOGLE_APPLICATION_CREDENTIALS"] == "test_credentials_file"
            assert gcp_provider.session is not None
            assert (
                gcp_provider.projects["test-project"].organization.id
                == "test-organization-id"
            )

    def test_setup_session_with_inactive_project(self):
        mocked_credentials = MagicMock()

        mocked_credentials.refresh.return_value = None
        mocked_credentials._service_account_email = "test-service-account-email"

        arguments = Namespace()
        arguments.project_id = ["project/55555555"]
        arguments.excluded_project_id = []
        arguments.organization_id = None
        arguments.list_project_id = False
        arguments.credentials_file = "test_credentials_file"
        arguments.impersonate_service_account = ""
        arguments.config_file = default_config_file_path
        arguments.fixer_config = default_fixer_config_file_path

        projects = {
            "test-project": GCPProject(
                number="55555555",
                id="project/55555555",
                name="test-project",
                labels={"test": "value"},
                lifecycle_state="DELETE_REQUESTED",
            )
        }

        mocked_service = MagicMock()

        mocked_service.projects.list.return_value = MagicMock(
            execute=MagicMock(return_value={"projects": projects})
        )
        with (
            patch(
                "prowler.providers.gcp.gcp_provider.GcpProvider.get_projects",
                return_value=projects,
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.GcpProvider.update_projects_with_organizations",
                return_value=None,
            ),
            patch(
                "os.path.abspath",
                return_value="test_credentials_file",
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.default",
                return_value=(mocked_credentials, MagicMock()),
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.discovery.build",
                return_value=mocked_service,
            ),
        ):
            with pytest.raises(Exception) as e:
                GcpProvider(
                    arguments.organization_id,
                    arguments.project_id,
                    arguments.excluded_project_id,
                    arguments.credentials_file,
                    arguments.impersonate_service_account,
                    arguments.list_project_id,
                    arguments.config_file,
                    arguments.fixer_config,
                    client_id=None,
                    client_secret=None,
                    refresh_token=None,
                )
            assert e.type == GCPNoAccesibleProjectsError

    def test_setup_session_with_inactive_default_project(self):
        mocked_credentials = MagicMock()

        mocked_credentials.refresh.return_value = None
        mocked_credentials._service_account_email = "test-service-account-email"

        arguments = Namespace()
        arguments.project_id = ["default_project", "active_project"]
        arguments.excluded_project_id = []
        arguments.organization_id = None
        arguments.list_project_id = False
        arguments.credentials_file = "test_credentials_file"
        arguments.impersonate_service_account = ""
        arguments.config_file = default_config_file_path
        arguments.fixer_config = default_fixer_config_file_path

        projects = {
            "default_project": GCPProject(
                number="55555555",
                id="default_project",
                name="default_project",
                labels={"test": "value"},
                lifecycle_state="DELETE_REQUESTED",
            ),
            "active_project": GCPProject(
                number="12345678",
                id="active_project",
                name="active_project",
                labels={"test": "value"},
                lifecycle_state="ACTIVE",
            ),
        }

        mocked_service = MagicMock()

        mocked_service.projects.list.return_value = MagicMock(
            execute=MagicMock(return_value={"projects": projects})
        )
        with (
            patch(
                "prowler.providers.gcp.gcp_provider.GcpProvider.get_projects",
                return_value=projects,
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.GcpProvider.update_projects_with_organizations",
                return_value=None,
            ),
            patch(
                "os.path.abspath",
                return_value="test_credentials_file",
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.default",
                return_value=(mocked_credentials, "default_project"),
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.discovery.build",
                return_value=mocked_service,
            ),
        ):
            gcp_provider = GcpProvider(
                arguments.organization_id,
                arguments.project_id,
                arguments.excluded_project_id,
                arguments.credentials_file,
                arguments.impersonate_service_account,
                arguments.list_project_id,
                arguments.config_file,
                arguments.fixer_config,
                client_id=None,
                client_secret=None,
                refresh_token=None,
            )
            assert gcp_provider.default_project_id == "active_project"

    def test_print_credentials_default_options(self, capsys):
        mocked_credentials = MagicMock()

        mocked_credentials.refresh.return_value = None
        mocked_credentials._service_account_email = "test-service-account-email"

        arguments = Namespace()
        arguments.project_id = []
        arguments.excluded_project_id = []
        arguments.organization_id = None
        arguments.list_project_id = False
        arguments.credentials_file = "test_credentials_file"
        arguments.impersonate_service_account = ""
        arguments.config_file = default_config_file_path
        arguments.fixer_config = default_fixer_config_file_path

        projects = {
            "test-project": GCPProject(
                number="55555555",
                id="project/55555555",
                name="test-project",
                labels={"test": "value"},
                lifecycle_state="ACTIVE",
            )
        }

        mocked_service = MagicMock()

        mocked_service.projects.list.return_value = MagicMock(
            execute=MagicMock(return_value={"projects": projects})
        )
        with (
            patch(
                "prowler.providers.gcp.gcp_provider.GcpProvider.get_projects",
                return_value=projects,
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.GcpProvider.update_projects_with_organizations",
                return_value=None,
            ),
            patch(
                "os.path.abspath",
                return_value="test_credentials_file",
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.default",
                return_value=(mocked_credentials, MagicMock()),
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.discovery.build",
                return_value=mocked_service,
            ),
        ):
            gcp_provider = GcpProvider(
                arguments.organization_id,
                arguments.project_id,
                arguments.excluded_project_id,
                arguments.credentials_file,
                arguments.impersonate_service_account,
                arguments.list_project_id,
                arguments.config_file,
                arguments.fixer_config,
                client_id=None,
                client_secret=None,
                refresh_token=None,
            )
            gcp_provider.print_credentials()
            captured = capsys.readouterr()
            assert "Using the GCP credentials below:" in captured.out
            assert (
                "GCP Account:" in captured.out
                and "test-service-account-email" in captured.out
            )
            assert "GCP Project IDs:" in captured.out and "test-project" in captured.out
            assert "Impersonated Service Account" not in captured.out
            assert "Excluded GCP Project IDs" not in captured.out

    def test_print_credentials_impersonated_service_account(self, capsys):
        mocked_credentials = MagicMock()

        mocked_credentials.refresh.return_value = None
        mocked_credentials._service_account_email = "test-service-account-email"

        arguments = Namespace()
        arguments.project_id = []
        arguments.excluded_project_id = []
        arguments.organization_id = None
        arguments.list_project_id = False
        arguments.credentials_file = "test_credentials_file"
        arguments.impersonate_service_account = "test-impersonate-service-account"
        arguments.config_file = default_config_file_path
        arguments.fixer_config = default_fixer_config_file_path

        projects = {
            "test-project": GCPProject(
                number="55555555",
                id="project/55555555",
                name="test-project",
                labels={"test": "value"},
                lifecycle_state="ACTIVE",
            )
        }

        mocked_service = MagicMock()

        mocked_service.projects.list.return_value = MagicMock(
            execute=MagicMock(return_value={"projects": projects})
        )
        with (
            patch(
                "prowler.providers.gcp.gcp_provider.GcpProvider.get_projects",
                return_value=projects,
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.GcpProvider.update_projects_with_organizations",
                return_value=None,
            ),
            patch(
                "os.path.abspath",
                return_value="test_credentials_file",
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.default",
                return_value=(mocked_credentials, MagicMock()),
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.discovery.build",
                return_value=mocked_service,
            ),
        ):
            gcp_provider = GcpProvider(
                arguments.organization_id,
                arguments.project_id,
                arguments.excluded_project_id,
                arguments.credentials_file,
                arguments.impersonate_service_account,
                arguments.list_project_id,
                arguments.config_file,
                arguments.fixer_config,
                client_id=None,
                client_secret=None,
                refresh_token=None,
            )
            gcp_provider.print_credentials()
            captured = capsys.readouterr()
            assert "Using the GCP credentials below:" in captured.out
            assert "GCP Account:" in captured.out and "default" in captured.out
            assert "GCP Project IDs:" in captured.out and "test-project" in captured.out
            assert (
                "Impersonated Service Account:" in captured.out
                and "test-impersonate-service-account" in captured.out
            )
            assert "Excluded GCP Project IDs" not in captured.out

    def test_print_credentials_excluded_project_ids(self, capsys):
        mocked_credentials = MagicMock()

        mocked_credentials.refresh.return_value = None
        mocked_credentials._service_account_email = "test-service-account-email"

        arguments = Namespace()
        arguments.project_id = []
        arguments.excluded_project_id = ["test-excluded-project"]
        arguments.organization_id = None
        arguments.list_project_id = False
        arguments.credentials_file = "test_credentials_file"
        arguments.impersonate_service_account = ""
        arguments.config_file = default_config_file_path
        arguments.fixer_config = default_fixer_config_file_path

        projects = {
            "test-project": GCPProject(
                number="55555555",
                id="project/55555555",
                name="test-project",
                labels={"test": "value"},
                lifecycle_state="ACTIVE",
            ),
            "test-excluded-project": GCPProject(
                number="12345678",
                id="project/12345678",
                name="test-excluded-project",
                labels={"test": "value"},
                lifecycle_state="ACTIVE",
            ),
        }

        mocked_service = MagicMock()

        mocked_service.projects.list.return_value = MagicMock(
            execute=MagicMock(return_value={"projects": projects})
        )

        with (
            patch(
                "prowler.providers.gcp.gcp_provider.GcpProvider.get_projects",
                return_value=projects,
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.GcpProvider.update_projects_with_organizations",
                return_value=None,
            ),
            patch(
                "os.path.abspath",
                return_value="test_credentials_file",
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.default",
                return_value=(mocked_credentials, MagicMock()),
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.discovery.build",
                return_value=mocked_service,
            ),
        ):
            gcp_provider = GcpProvider(
                arguments.organization_id,
                arguments.project_id,
                arguments.excluded_project_id,
                arguments.credentials_file,
                arguments.impersonate_service_account,
                arguments.list_project_id,
                arguments.config_file,
                arguments.fixer_config,
                client_id=None,
                client_secret=None,
                refresh_token=None,
            )
            gcp_provider.print_credentials()
            captured = capsys.readouterr()
            assert "Using the GCP credentials below:" in captured.out
            assert (
                "GCP Account:" in captured.out
                and "test-service-account-email" in captured.out
            )
            assert "GCP Project IDs:" in captured.out and "test-project" in captured.out
            assert "Impersonated Service Account" not in captured.out
            assert (
                "Excluded GCP Project IDs:" in captured.out
                and "test-excluded-project" in captured.out
            )

    def test_init_only_client_id(self):
        with pytest.raises(Exception) as e:
            GcpProvider(client_id="test-client-id")
        assert "client_secret and refresh_token are required" in e.value.args[0]

    def test_validate_static_arguments(self):
        output = GcpProvider.validate_static_arguments(
            client_id="test-client-id",
            client_secret="test-client-secret",
            refresh_token="test-refresh-token",
        )

        assert output == {
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "refresh_token": "test-refresh-token",
            "type": "authorized_user",
        }

    def test_test_connection_with_exception(self):
        with patch(
            "prowler.providers.gcp.gcp_provider.GcpProvider.setup_session",
            side_effect=Exception("Test exception"),
        ):
            with pytest.raises(Exception) as e:
                GcpProvider.test_connection(
                    client_id="test-client-id",
                    client_secret="test-client-secret",
                    refresh_token="test-refresh-token",
                )
            assert e.type == GCPTestConnectionError
            assert "Test exception" in e.value.args[0]

    def test_test_connection_valid_project_id(self):
        project_id = "test-project-id"
        mocked_service = MagicMock()

        mocked_service.projects.get.return_value = MagicMock(
            execute=MagicMock(return_value={"projectId": project_id})
        )

        with (
            patch(
                "prowler.providers.gcp.gcp_provider.GcpProvider.setup_session",
                return_value=(None, project_id),
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.discovery.build",
                return_value=mocked_service,
            ),
        ):
            output = GcpProvider.test_connection(
                client_id="test-client-id",
                client_secret="test-client-secret",
                refresh_token="test-refresh-token",
                provider_id=project_id,
            )
            assert Connection(is_connected=True, error=None) == output

    def test_test_connection_invalid_project_id(self):
        mocked_service = MagicMock()

        projects = {
            "test-valid-project": GCPProject(
                number="55555555",
                id="project/55555555",
                name="test-project",
                labels={"test": "value"},
                lifecycle_state="ACTIVE",
            ),
        }

        mocked_service.projects.get.return_value = MagicMock(
            execute=MagicMock(return_value={"projects": projects})
        )

        with (
            patch(
                "prowler.providers.gcp.gcp_provider.GcpProvider.setup_session",
                return_value=(None, "test-valid-project"),
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.discovery.build",
                return_value=mocked_service,
            ),
            patch(
                "prowler.providers.gcp.gcp_provider.GcpProvider.validate_project_id"
            ) as mock_validate_project_id,
        ):
            mock_validate_project_id.side_effect = GCPInvalidProviderIdError(
                "Invalid project ID"
            )

            with pytest.raises(Exception) as e:
                GcpProvider.test_connection(
                    client_id="test-client-id",
                    client_secret="test-client-secret",
                    refresh_token="test-refresh-token",
                    provider_id="test-invalid-project",
                )

            assert e.type == GCPInvalidProviderIdError
