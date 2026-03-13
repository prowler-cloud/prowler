from unittest import mock

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    GCP_US_CENTER1_LOCATION,
    set_mocked_gcp_provider,
)


class TestCloudStorageBucketSoftDeleteEnabled:
    def test_no_buckets(self):
        cloudstorage_client = mock.MagicMock()
        cloudstorage_client.buckets = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_soft_delete_enabled.cloudstorage_bucket_soft_delete_enabled.cloudstorage_client",
                new=cloudstorage_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_soft_delete_enabled.cloudstorage_bucket_soft_delete_enabled import (
                cloudstorage_bucket_soft_delete_enabled,
            )

            check = cloudstorage_bucket_soft_delete_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_bucket_with_soft_delete_disabled(self):
        cloudstorage_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_soft_delete_enabled.cloudstorage_bucket_soft_delete_enabled.cloudstorage_client",
                new=cloudstorage_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_soft_delete_enabled.cloudstorage_bucket_soft_delete_enabled import (
                cloudstorage_bucket_soft_delete_enabled,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
                Bucket,
            )

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION

            cloudstorage_client.buckets = [
                Bucket(
                    name="soft-delete-disabled",
                    id="soft-delete-disabled",
                    region=GCP_US_CENTER1_LOCATION,
                    uniform_bucket_level_access=True,
                    public=False,
                    retention_policy=None,
                    project_id=GCP_PROJECT_ID,
                    lifecycle_rules=[],
                    versioning_enabled=False,
                    soft_delete_enabled=False,
                )
            ]

            check = cloudstorage_bucket_soft_delete_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Bucket {cloudstorage_client.buckets[0].name} does not have Soft Delete enabled."
            )
            assert result[0].resource_id == "soft-delete-disabled"
            assert result[0].resource_name == "soft-delete-disabled"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_bucket_with_soft_delete_enabled(self):
        cloudstorage_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_soft_delete_enabled.cloudstorage_bucket_soft_delete_enabled.cloudstorage_client",
                new=cloudstorage_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_soft_delete_enabled.cloudstorage_bucket_soft_delete_enabled import (
                cloudstorage_bucket_soft_delete_enabled,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
                Bucket,
            )

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION

            cloudstorage_client.buckets = [
                Bucket(
                    name="with-soft-delete",
                    id="with-soft-delete",
                    region=GCP_US_CENTER1_LOCATION,
                    uniform_bucket_level_access=True,
                    public=False,
                    retention_policy=None,
                    project_id=GCP_PROJECT_ID,
                    lifecycle_rules=[],
                    versioning_enabled=True,
                    soft_delete_enabled=True,
                )
            ]

            check = cloudstorage_bucket_soft_delete_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Bucket {cloudstorage_client.buckets[0].name} has Soft Delete enabled."
            )
            assert result[0].resource_id == "with-soft-delete"
            assert result[0].resource_name == "with-soft-delete"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_bucket_without_soft_delete_configured_treated_as_disabled(self):
        cloudstorage_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_soft_delete_enabled.cloudstorage_bucket_soft_delete_enabled.cloudstorage_client",
                new=cloudstorage_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_soft_delete_enabled.cloudstorage_bucket_soft_delete_enabled import (
                cloudstorage_bucket_soft_delete_enabled,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
                Bucket,
            )

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION

            cloudstorage_client.buckets = [
                Bucket(
                    name="no-soft-delete-policy",
                    id="no-soft-delete-policy",
                    region=GCP_US_CENTER1_LOCATION,
                    uniform_bucket_level_access=True,
                    public=False,
                    retention_policy=None,
                    project_id=GCP_PROJECT_ID,
                    lifecycle_rules=[],
                    versioning_enabled=False,
                )
            ]

            check = cloudstorage_bucket_soft_delete_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Bucket {cloudstorage_client.buckets[0].name} does not have Soft Delete enabled."
            )
            assert result[0].resource_id == "no-soft-delete-policy"
            assert result[0].resource_name == "no-soft-delete-policy"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID
