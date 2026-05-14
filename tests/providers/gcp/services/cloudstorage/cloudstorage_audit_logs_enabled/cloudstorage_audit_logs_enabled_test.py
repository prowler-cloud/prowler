from unittest import mock

from prowler.providers.gcp.models import GCPProject
from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    GCP_US_CENTER1_LOCATION,
    set_mocked_gcp_provider,
)


class TestCloudStorageAuditLogsEnabled:
    def test_no_projects(self):
        cloudresourcemanager_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage."
                "cloudstorage_audit_logs_enabled."
                "cloudstorage_audit_logs_enabled."
                "cloudresourcemanager_client",
                new=cloudresourcemanager_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_audit_logs_enabled.cloudstorage_audit_logs_enabled import (
                cloudstorage_audit_logs_enabled,
            )

            cloudresourcemanager_client.cloud_resource_manager_projects = []
            cloudresourcemanager_client.region = GCP_US_CENTER1_LOCATION

            check = cloudstorage_audit_logs_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_project_with_storage_audit_logs_enabled(self):
        cloudresourcemanager_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage."
                "cloudstorage_audit_logs_enabled."
                "cloudstorage_audit_logs_enabled."
                "cloudresourcemanager_client",
                new=cloudresourcemanager_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
                AuditConfig,
                Project,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_audit_logs_enabled.cloudstorage_audit_logs_enabled import (
                cloudstorage_audit_logs_enabled,
            )

            project = Project(
                id=GCP_PROJECT_ID,
                audit_logging=True,
                audit_configs=[
                    AuditConfig(
                        service="storage.googleapis.com",
                        log_types=["DATA_READ", "DATA_WRITE"],
                    )
                ],
            )

            cloudresourcemanager_client.cloud_resource_manager_projects = [project]
            cloudresourcemanager_client.region = GCP_US_CENTER1_LOCATION
            cloudresourcemanager_client.projects = {
                GCP_PROJECT_ID: GCPProject(
                    id=GCP_PROJECT_ID,
                    number="123456789012",
                    name="test-project",
                    labels={},
                    lifecycle_state="ACTIVE",
                )
            }

            check = cloudstorage_audit_logs_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"Project {GCP_PROJECT_ID} has Data Access audit logs "
                f"(DATA_READ and DATA_WRITE) enabled for Cloud Storage."
            )
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].resource_name == "test-project"

    def test_project_with_audit_logs_but_no_storage_config(self):
        cloudresourcemanager_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage."
                "cloudstorage_audit_logs_enabled."
                "cloudstorage_audit_logs_enabled."
                "cloudresourcemanager_client",
                new=cloudresourcemanager_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
                AuditConfig,
                Project,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_audit_logs_enabled.cloudstorage_audit_logs_enabled import (
                cloudstorage_audit_logs_enabled,
            )

            # Project has audit logs enabled but for a different service (not Cloud Storage)
            project = Project(
                id=GCP_PROJECT_ID,
                audit_logging=True,
                audit_configs=[
                    AuditConfig(
                        service="compute.googleapis.com",
                        log_types=["DATA_READ", "DATA_WRITE"],
                    )
                ],
            )

            cloudresourcemanager_client.cloud_resource_manager_projects = [project]
            cloudresourcemanager_client.region = GCP_US_CENTER1_LOCATION
            cloudresourcemanager_client.projects = {
                GCP_PROJECT_ID: GCPProject(
                    id=GCP_PROJECT_ID,
                    number="123456789012",
                    name="test-project",
                    labels={},
                    lifecycle_state="ACTIVE",
                )
            }

            check = cloudstorage_audit_logs_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"Project {GCP_PROJECT_ID} has Audit Logs enabled for other services but not for Cloud Storage."
            )
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].resource_name == "test-project"

    def test_project_without_audit_logs(self):
        cloudresourcemanager_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage."
                "cloudstorage_audit_logs_enabled."
                "cloudstorage_audit_logs_enabled."
                "cloudresourcemanager_client",
                new=cloudresourcemanager_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
                Project,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_audit_logs_enabled.cloudstorage_audit_logs_enabled import (
                cloudstorage_audit_logs_enabled,
            )

            project = Project(
                id=GCP_PROJECT_ID,
                audit_logging=False,
                audit_configs=[],
            )

            cloudresourcemanager_client.cloud_resource_manager_projects = [project]
            cloudresourcemanager_client.region = GCP_US_CENTER1_LOCATION
            cloudresourcemanager_client.projects = {
                GCP_PROJECT_ID: GCPProject(
                    id=GCP_PROJECT_ID,
                    number="123456789012",
                    name="test-project",
                    labels={},
                    lifecycle_state="ACTIVE",
                )
            }

            check = cloudstorage_audit_logs_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"Project {GCP_PROJECT_ID} does not have Audit Logs enabled."
            )
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].resource_name == "test-project"

    def test_project_with_missing_log_types(self):
        cloudresourcemanager_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage."
                "cloudstorage_audit_logs_enabled."
                "cloudstorage_audit_logs_enabled."
                "cloudresourcemanager_client",
                new=cloudresourcemanager_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
                AuditConfig,
                Project,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_audit_logs_enabled.cloudstorage_audit_logs_enabled import (
                cloudstorage_audit_logs_enabled,
            )

            project = Project(
                id=GCP_PROJECT_ID,
                audit_logging=True,
                audit_configs=[
                    AuditConfig(
                        service="storage.googleapis.com",
                        log_types=["DATA_WRITE"],
                    )
                ],
            )

            cloudresourcemanager_client.cloud_resource_manager_projects = [project]
            cloudresourcemanager_client.region = GCP_US_CENTER1_LOCATION
            cloudresourcemanager_client.projects = {
                GCP_PROJECT_ID: GCPProject(
                    id=GCP_PROJECT_ID,
                    number="123456789012",
                    name="test-project",
                    labels={},
                    lifecycle_state="ACTIVE",
                )
            }

            check = cloudstorage_audit_logs_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"Project {GCP_PROJECT_ID} has Audit Logs enabled for Cloud Storage but is missing some required log types"
                f"(missing: DATA_READ)."
            )
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].resource_name == "test-project"

    def test_project_with_combined_audit_configs(self):
        cloudresourcemanager_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage."
                "cloudstorage_audit_logs_enabled."
                "cloudstorage_audit_logs_enabled."
                "cloudresourcemanager_client",
                new=cloudresourcemanager_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
                AuditConfig,
                Project,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_audit_logs_enabled.cloudstorage_audit_logs_enabled import (
                cloudstorage_audit_logs_enabled,
            )

            # Project has both allServices (with DATA_READ)
            # and storage.googleapis.com (with DATA_WRITE)
            project = Project(
                id=GCP_PROJECT_ID,
                audit_logging=True,
                audit_configs=[
                    AuditConfig(
                        service="allServices",
                        log_types=["DATA_READ"],
                    ),
                    AuditConfig(
                        service="storage.googleapis.com",
                        log_types=["DATA_WRITE"],
                    ),
                ],
            )

            cloudresourcemanager_client.cloud_resource_manager_projects = [project]
            cloudresourcemanager_client.region = GCP_US_CENTER1_LOCATION
            cloudresourcemanager_client.projects = {
                GCP_PROJECT_ID: GCPProject(
                    id=GCP_PROJECT_ID,
                    number="123456789012",
                    name="test-project",
                    labels={},
                    lifecycle_state="ACTIVE",
                )
            }

            check = cloudstorage_audit_logs_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"Project {GCP_PROJECT_ID} has Data Access audit logs "
                f"(DATA_READ and DATA_WRITE) enabled for Cloud Storage."
            )
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].resource_name == "test-project"

    def test_project_with_allservices_audit_config(self):
        cloudresourcemanager_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage."
                "cloudstorage_audit_logs_enabled."
                "cloudstorage_audit_logs_enabled."
                "cloudresourcemanager_client",
                new=cloudresourcemanager_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
                AuditConfig,
                Project,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_audit_logs_enabled.cloudstorage_audit_logs_enabled import (
                cloudstorage_audit_logs_enabled,
            )

            # Project has allServices with both log types
            project = Project(
                id=GCP_PROJECT_ID,
                audit_logging=True,
                audit_configs=[
                    AuditConfig(
                        service="allServices",
                        log_types=["DATA_READ", "DATA_WRITE"],
                    )
                ],
            )

            cloudresourcemanager_client.cloud_resource_manager_projects = [project]
            cloudresourcemanager_client.region = GCP_US_CENTER1_LOCATION
            cloudresourcemanager_client.projects = {
                GCP_PROJECT_ID: GCPProject(
                    id=GCP_PROJECT_ID,
                    number="123456789012",
                    name="test-project",
                    labels={},
                    lifecycle_state="ACTIVE",
                )
            }

            check = cloudstorage_audit_logs_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"Project {GCP_PROJECT_ID} has Data Access audit logs "
                f"(DATA_READ and DATA_WRITE) enabled for Cloud Storage."
            )
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].resource_name == "test-project"
