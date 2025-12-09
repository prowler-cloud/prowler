from unittest import mock

from prowler.providers.gcp.models import GCPProject
from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    GCP_US_CENTER1_LOCATION,
    set_mocked_gcp_provider,
)


class TestCloudStorageUsesVPCServiceControls:
    def test_project_protected_by_vpc_sc(self):
        cloudresourcemanager_client = mock.MagicMock()
        accesscontextmanager_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_uses_vpc_service_controls.cloudstorage_uses_vpc_service_controls.cloudresourcemanager_client",
                new=cloudresourcemanager_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_uses_vpc_service_controls.cloudstorage_uses_vpc_service_controls.accesscontextmanager_client",
                new=accesscontextmanager_client,
            ),
        ):
            from prowler.providers.gcp.services.accesscontextmanager.accesscontextmanager_service import (
                ServicePerimeter,
            )
            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
                Project,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_uses_vpc_service_controls.cloudstorage_uses_vpc_service_controls import (
                cloudstorage_uses_vpc_service_controls,
            )

            project1 = Project(
                id=GCP_PROJECT_ID, number="123456789012", audit_logging=True
            )

            cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
            cloudresourcemanager_client.cloud_resource_manager_projects = [project1]
            cloudresourcemanager_client.projects = {
                GCP_PROJECT_ID: GCPProject(
                    id=GCP_PROJECT_ID,
                    number="123456789012",
                    name="test-project",
                    labels={},
                    lifecycle_state="ACTIVE",
                )
            }
            cloudresourcemanager_client.region = GCP_US_CENTER1_LOCATION

            accesscontextmanager_client.service_perimeters = [
                ServicePerimeter(
                    name="accessPolicies/123456/servicePerimeters/test_perimeter",
                    title="Test Perimeter",
                    perimeter_type="PERIMETER_TYPE_REGULAR",
                    resources=["projects/123456789012"],
                    restricted_services=[
                        "storage.googleapis.com",
                        "bigquery.googleapis.com",
                    ],
                    policy_name="accessPolicies/123456",
                )
            ]

            check = cloudstorage_uses_vpc_service_controls()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Project {GCP_PROJECT_ID} has VPC Service Controls enabled for Cloud Storage in perimeter Test Perimeter."
            )
            assert result[0].resource_id == GCP_PROJECT_ID
            assert result[0].resource_name == "test-project"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_project_not_protected_no_perimeters(self):
        cloudresourcemanager_client = mock.MagicMock()
        accesscontextmanager_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_uses_vpc_service_controls.cloudstorage_uses_vpc_service_controls.cloudresourcemanager_client",
                new=cloudresourcemanager_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_uses_vpc_service_controls.cloudstorage_uses_vpc_service_controls.accesscontextmanager_client",
                new=accesscontextmanager_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
                Project,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_uses_vpc_service_controls.cloudstorage_uses_vpc_service_controls import (
                cloudstorage_uses_vpc_service_controls,
            )

            project1 = Project(
                id=GCP_PROJECT_ID, number="123456789012", audit_logging=True
            )

            cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
            cloudresourcemanager_client.cloud_resource_manager_projects = [project1]
            cloudresourcemanager_client.projects = {
                GCP_PROJECT_ID: GCPProject(
                    id=GCP_PROJECT_ID,
                    number="123456789012",
                    name="test-project",
                    labels={},
                    lifecycle_state="ACTIVE",
                )
            }
            cloudresourcemanager_client.region = GCP_US_CENTER1_LOCATION

            # No service perimeters configured
            accesscontextmanager_client.service_perimeters = []

            check = cloudstorage_uses_vpc_service_controls()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Project {GCP_PROJECT_ID} does not have VPC Service Controls enabled for Cloud Storage."
            )
            assert result[0].resource_id == GCP_PROJECT_ID
            assert result[0].resource_name == "test-project"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_project_in_perimeter_but_storage_not_restricted(self):
        cloudresourcemanager_client = mock.MagicMock()
        accesscontextmanager_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_uses_vpc_service_controls.cloudstorage_uses_vpc_service_controls.cloudresourcemanager_client",
                new=cloudresourcemanager_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_uses_vpc_service_controls.cloudstorage_uses_vpc_service_controls.accesscontextmanager_client",
                new=accesscontextmanager_client,
            ),
        ):
            from prowler.providers.gcp.services.accesscontextmanager.accesscontextmanager_service import (
                ServicePerimeter,
            )
            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
                Project,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_uses_vpc_service_controls.cloudstorage_uses_vpc_service_controls import (
                cloudstorage_uses_vpc_service_controls,
            )

            project1 = Project(
                id=GCP_PROJECT_ID, number="123456789012", audit_logging=True
            )

            cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
            cloudresourcemanager_client.cloud_resource_manager_projects = [project1]
            cloudresourcemanager_client.projects = {
                GCP_PROJECT_ID: GCPProject(
                    id=GCP_PROJECT_ID,
                    number="123456789012",
                    name="test-project",
                    labels={},
                    lifecycle_state="ACTIVE",
                )
            }
            cloudresourcemanager_client.region = GCP_US_CENTER1_LOCATION

            # Perimeter exists but storage.googleapis.com is NOT in restricted services
            accesscontextmanager_client.service_perimeters = [
                ServicePerimeter(
                    name="accessPolicies/123456/servicePerimeters/test_perimeter",
                    title="Test Perimeter",
                    perimeter_type="PERIMETER_TYPE_REGULAR",
                    resources=["projects/123456789012"],
                    restricted_services=[
                        "bigquery.googleapis.com",
                        "compute.googleapis.com",
                    ],
                    policy_name="accessPolicies/123456",
                )
            ]

            check = cloudstorage_uses_vpc_service_controls()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Project {GCP_PROJECT_ID} does not have VPC Service Controls enabled for Cloud Storage."
            )
            assert result[0].resource_id == GCP_PROJECT_ID
            assert result[0].resource_name == "test-project"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_project_not_in_perimeter(self):
        cloudresourcemanager_client = mock.MagicMock()
        accesscontextmanager_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_uses_vpc_service_controls.cloudstorage_uses_vpc_service_controls.cloudresourcemanager_client",
                new=cloudresourcemanager_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_uses_vpc_service_controls.cloudstorage_uses_vpc_service_controls.accesscontextmanager_client",
                new=accesscontextmanager_client,
            ),
        ):
            from prowler.providers.gcp.services.accesscontextmanager.accesscontextmanager_service import (
                ServicePerimeter,
            )
            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
                Project,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_uses_vpc_service_controls.cloudstorage_uses_vpc_service_controls import (
                cloudstorage_uses_vpc_service_controls,
            )

            project1 = Project(
                id=GCP_PROJECT_ID, number="123456789012", audit_logging=True
            )

            cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
            cloudresourcemanager_client.cloud_resource_manager_projects = [project1]
            cloudresourcemanager_client.projects = {
                GCP_PROJECT_ID: GCPProject(
                    id=GCP_PROJECT_ID,
                    number="123456789012",
                    name="test-project",
                    labels={},
                    lifecycle_state="ACTIVE",
                )
            }
            cloudresourcemanager_client.region = GCP_US_CENTER1_LOCATION

            # Perimeter exists with storage restricted, but different project
            accesscontextmanager_client.service_perimeters = [
                ServicePerimeter(
                    name="accessPolicies/123456/servicePerimeters/test_perimeter",
                    title="Test Perimeter",
                    perimeter_type="PERIMETER_TYPE_REGULAR",
                    resources=["projects/999999999999"],
                    restricted_services=["storage.googleapis.com"],
                    policy_name="accessPolicies/123456",
                )
            ]

            check = cloudstorage_uses_vpc_service_controls()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Project {GCP_PROJECT_ID} does not have VPC Service Controls enabled for Cloud Storage."
            )
            assert result[0].resource_id == GCP_PROJECT_ID
            assert result[0].resource_name == "test-project"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_no_projects(self):
        cloudresourcemanager_client = mock.MagicMock()
        accesscontextmanager_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_uses_vpc_service_controls.cloudstorage_uses_vpc_service_controls.cloudresourcemanager_client",
                new=cloudresourcemanager_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_uses_vpc_service_controls.cloudstorage_uses_vpc_service_controls.accesscontextmanager_client",
                new=accesscontextmanager_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_uses_vpc_service_controls.cloudstorage_uses_vpc_service_controls import (
                cloudstorage_uses_vpc_service_controls,
            )

            cloudresourcemanager_client.cloud_resource_manager_projects = []
            cloudresourcemanager_client.region = GCP_US_CENTER1_LOCATION

            check = cloudstorage_uses_vpc_service_controls()
            result = check.execute()

            assert len(result) == 0

    def test_project_protected_by_vpc_sc_api_blocked(self):
        cloudresourcemanager_client = mock.MagicMock()
        accesscontextmanager_client = mock.MagicMock()
        cloudstorage_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_uses_vpc_service_controls.cloudstorage_uses_vpc_service_controls.cloudresourcemanager_client",
                new=cloudresourcemanager_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_uses_vpc_service_controls.cloudstorage_uses_vpc_service_controls.accesscontextmanager_client",
                new=accesscontextmanager_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_uses_vpc_service_controls.cloudstorage_uses_vpc_service_controls.cloudstorage_client",
                new=cloudstorage_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
                Project,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_uses_vpc_service_controls.cloudstorage_uses_vpc_service_controls import (
                cloudstorage_uses_vpc_service_controls,
            )

            project1 = Project(
                id=GCP_PROJECT_ID, number="123456789012", audit_logging=True
            )

            cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
            cloudresourcemanager_client.cloud_resource_manager_projects = [project1]
            cloudresourcemanager_client.projects = {
                GCP_PROJECT_ID: GCPProject(
                    id=GCP_PROJECT_ID,
                    number="123456789012",
                    name="test-project",
                    labels={},
                    lifecycle_state="ACTIVE",
                )
            }
            cloudresourcemanager_client.region = GCP_US_CENTER1_LOCATION

            # No service perimeters configured, but API access is blocked by VPC SC
            accesscontextmanager_client.service_perimeters = []
            cloudstorage_client.vpc_service_controls_protected_projects = {
                GCP_PROJECT_ID
            }

            check = cloudstorage_uses_vpc_service_controls()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Project {GCP_PROJECT_ID} has VPC Service Controls enabled for Cloud Storage in undetermined perimeter (verified by API access restriction)."
            )
            assert result[0].resource_id == GCP_PROJECT_ID
            assert result[0].resource_name == "test-project"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID
