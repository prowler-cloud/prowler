from unittest import mock

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    GCP_US_CENTER1_LOCATION,
    set_mocked_gcp_provider,
)


class TestCloudStorageBucketUsesVPCServiceControls:
    def test_bucket_protected_by_vpc_sc(self):
        cloudstorage_client = mock.MagicMock()
        accesscontextmanager_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_uses_vpc_service_controls.cloudstorage_bucket_uses_vpc_service_controls.cloudstorage_client",
                new=cloudstorage_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_uses_vpc_service_controls.cloudstorage_bucket_uses_vpc_service_controls.accesscontextmanager_client",
                new=accesscontextmanager_client,
            ),
        ):
            from prowler.providers.gcp.services.accesscontextmanager.accesscontextmanager_service import (
                ServicePerimeter,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_uses_vpc_service_controls.cloudstorage_bucket_uses_vpc_service_controls import (
                cloudstorage_bucket_uses_vpc_service_controls,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
                Bucket,
            )

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION

            cloudstorage_client.buckets = [
                Bucket(
                    name="protected-bucket",
                    id="protected-bucket",
                    region=GCP_US_CENTER1_LOCATION,
                    uniform_bucket_level_access=True,
                    public=False,
                    project_id=GCP_PROJECT_ID,
                )
            ]

            accesscontextmanager_client.service_perimeters = [
                ServicePerimeter(
                    name="accessPolicies/123456/servicePerimeters/test_perimeter",
                    title="Test Perimeter",
                    perimeter_type="PERIMETER_TYPE_REGULAR",
                    resources=[f"projects/{GCP_PROJECT_ID}"],
                    restricted_services=[
                        "storage.googleapis.com",
                        "bigquery.googleapis.com",
                    ],
                    policy_name="accessPolicies/123456",
                )
            ]

            check = cloudstorage_bucket_uses_vpc_service_controls()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Bucket {cloudstorage_client.buckets[0].name} is protected by VPC Service Controls perimeter Test Perimeter."
            )
            assert result[0].resource_id == "protected-bucket"
            assert result[0].resource_name == "protected-bucket"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_bucket_not_protected_no_perimeters(self):
        cloudstorage_client = mock.MagicMock()
        accesscontextmanager_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_uses_vpc_service_controls.cloudstorage_bucket_uses_vpc_service_controls.cloudstorage_client",
                new=cloudstorage_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_uses_vpc_service_controls.cloudstorage_bucket_uses_vpc_service_controls.accesscontextmanager_client",
                new=accesscontextmanager_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_uses_vpc_service_controls.cloudstorage_bucket_uses_vpc_service_controls import (
                cloudstorage_bucket_uses_vpc_service_controls,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
                Bucket,
            )

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION

            cloudstorage_client.buckets = [
                Bucket(
                    name="unprotected-bucket",
                    id="unprotected-bucket",
                    region=GCP_US_CENTER1_LOCATION,
                    uniform_bucket_level_access=True,
                    public=False,
                    project_id=GCP_PROJECT_ID,
                )
            ]

            # No service perimeters configured
            accesscontextmanager_client.service_perimeters = []

            check = cloudstorage_bucket_uses_vpc_service_controls()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Bucket {cloudstorage_client.buckets[0].name} is not protected by VPC Service Controls."
            )
            assert result[0].resource_id == "unprotected-bucket"
            assert result[0].resource_name == "unprotected-bucket"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_bucket_in_perimeter_but_storage_not_restricted(self):
        cloudstorage_client = mock.MagicMock()
        accesscontextmanager_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_uses_vpc_service_controls.cloudstorage_bucket_uses_vpc_service_controls.cloudstorage_client",
                new=cloudstorage_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_uses_vpc_service_controls.cloudstorage_bucket_uses_vpc_service_controls.accesscontextmanager_client",
                new=accesscontextmanager_client,
            ),
        ):
            from prowler.providers.gcp.services.accesscontextmanager.accesscontextmanager_service import (
                ServicePerimeter,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_uses_vpc_service_controls.cloudstorage_bucket_uses_vpc_service_controls import (
                cloudstorage_bucket_uses_vpc_service_controls,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
                Bucket,
            )

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION

            cloudstorage_client.buckets = [
                Bucket(
                    name="misconfigured-bucket",
                    id="misconfigured-bucket",
                    region=GCP_US_CENTER1_LOCATION,
                    uniform_bucket_level_access=True,
                    public=False,
                    project_id=GCP_PROJECT_ID,
                )
            ]

            # Perimeter exists but storage.googleapis.com is NOT in restricted services
            accesscontextmanager_client.service_perimeters = [
                ServicePerimeter(
                    name="accessPolicies/123456/servicePerimeters/test_perimeter",
                    title="Test Perimeter",
                    perimeter_type="PERIMETER_TYPE_REGULAR",
                    resources=[f"projects/{GCP_PROJECT_ID}"],
                    restricted_services=[
                        "bigquery.googleapis.com",
                        "compute.googleapis.com",
                    ],
                    policy_name="accessPolicies/123456",
                )
            ]

            check = cloudstorage_bucket_uses_vpc_service_controls()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Bucket {cloudstorage_client.buckets[0].name} is not protected by VPC Service Controls."
            )
            assert result[0].resource_id == "misconfigured-bucket"
            assert result[0].resource_name == "misconfigured-bucket"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_bucket_project_not_in_perimeter(self):
        cloudstorage_client = mock.MagicMock()
        accesscontextmanager_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_uses_vpc_service_controls.cloudstorage_bucket_uses_vpc_service_controls.cloudstorage_client",
                new=cloudstorage_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_uses_vpc_service_controls.cloudstorage_bucket_uses_vpc_service_controls.accesscontextmanager_client",
                new=accesscontextmanager_client,
            ),
        ):
            from prowler.providers.gcp.services.accesscontextmanager.accesscontextmanager_service import (
                ServicePerimeter,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_uses_vpc_service_controls.cloudstorage_bucket_uses_vpc_service_controls import (
                cloudstorage_bucket_uses_vpc_service_controls,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
                Bucket,
            )

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION

            cloudstorage_client.buckets = [
                Bucket(
                    name="outside-perimeter-bucket",
                    id="outside-perimeter-bucket",
                    region=GCP_US_CENTER1_LOCATION,
                    uniform_bucket_level_access=True,
                    public=False,
                    project_id=GCP_PROJECT_ID,
                )
            ]

            # Perimeter exists with storage restricted, but different project
            accesscontextmanager_client.service_perimeters = [
                ServicePerimeter(
                    name="accessPolicies/123456/servicePerimeters/test_perimeter",
                    title="Test Perimeter",
                    perimeter_type="PERIMETER_TYPE_REGULAR",
                    resources=["projects/different-project"],
                    restricted_services=["storage.googleapis.com"],
                    policy_name="accessPolicies/123456",
                )
            ]

            check = cloudstorage_bucket_uses_vpc_service_controls()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Bucket {cloudstorage_client.buckets[0].name} is not protected by VPC Service Controls."
            )
            assert result[0].resource_id == "outside-perimeter-bucket"
            assert result[0].resource_name == "outside-perimeter-bucket"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_no_buckets(self):
        cloudstorage_client = mock.MagicMock()
        accesscontextmanager_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_uses_vpc_service_controls.cloudstorage_bucket_uses_vpc_service_controls.cloudstorage_client",
                new=cloudstorage_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_uses_vpc_service_controls.cloudstorage_bucket_uses_vpc_service_controls.accesscontextmanager_client",
                new=accesscontextmanager_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_uses_vpc_service_controls.cloudstorage_bucket_uses_vpc_service_controls import (
                cloudstorage_bucket_uses_vpc_service_controls,
            )

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION
            cloudstorage_client.buckets = []
            accesscontextmanager_client.service_perimeters = []

            check = cloudstorage_bucket_uses_vpc_service_controls()
            result = check.execute()

            assert len(result) == 0
