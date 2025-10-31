from unittest import mock

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    GCP_US_CENTER1_LOCATION,
    set_mocked_gcp_provider,
)


class TestCloudStorageBucketLoggingEnabled:
    def test_no_buckets(self):
        cloudstorage_client = mock.MagicMock()
        cloudstorage_client.buckets = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_logging_enabled.cloudstorage_bucket_logging_enabled.cloudstorage_client",
                new=cloudstorage_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_logging_enabled.cloudstorage_bucket_logging_enabled import (
                cloudstorage_bucket_logging_enabled,
            )

            check = cloudstorage_bucket_logging_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_bucket_with_logging_disabled(self):
        cloudstorage_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_logging_enabled.cloudstorage_bucket_logging_enabled.cloudstorage_client",
                new=cloudstorage_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_logging_enabled.cloudstorage_bucket_logging_enabled import (
                cloudstorage_bucket_logging_enabled,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
                Bucket,
            )

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION

            cloudstorage_client.buckets = [
                Bucket(
                    name="logging-disabled",
                    id="logging-disabled",
                    region=GCP_US_CENTER1_LOCATION,
                    uniform_bucket_level_access=True,
                    public=False,
                    retention_policy=None,
                    project_id=GCP_PROJECT_ID,
                    lifecycle_rules=[],
                    versioning_enabled=True,
                    soft_delete_enabled=True,
                    logging_bucket=None,
                    logging_prefix=None,
                )
            ]

            check = cloudstorage_bucket_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Bucket {cloudstorage_client.buckets[0].name} does not have Usage and Storage Logs enabled."
            )
            assert result[0].resource_id == "logging-disabled"
            assert result[0].resource_name == "logging-disabled"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_bucket_with_logging_enabled(self):
        cloudstorage_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_logging_enabled.cloudstorage_bucket_logging_enabled.cloudstorage_client",
                new=cloudstorage_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_logging_enabled.cloudstorage_bucket_logging_enabled import (
                cloudstorage_bucket_logging_enabled,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
                Bucket,
            )

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION

            cloudstorage_client.buckets = [
                Bucket(
                    name="logging-enabled",
                    id="logging-enabled",
                    region=GCP_US_CENTER1_LOCATION,
                    uniform_bucket_level_access=True,
                    public=False,
                    retention_policy=None,
                    project_id=GCP_PROJECT_ID,
                    lifecycle_rules=[],
                    versioning_enabled=True,
                    soft_delete_enabled=True,
                    logging_bucket="log-bucket",
                    logging_prefix="logs/",
                )
            ]

            check = cloudstorage_bucket_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Bucket {cloudstorage_client.buckets[0].name} has Usage and Storage Logs enabled. Logs are stored in bucket 'log-bucket' with prefix 'logs/'."
            )
            assert result[0].resource_id == "logging-enabled"
            assert result[0].resource_name == "logging-enabled"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_bucket_with_logging_enabled_no_prefix(self):
        cloudstorage_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_logging_enabled.cloudstorage_bucket_logging_enabled.cloudstorage_client",
                new=cloudstorage_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_logging_enabled.cloudstorage_bucket_logging_enabled import (
                cloudstorage_bucket_logging_enabled,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
                Bucket,
            )

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION

            cloudstorage_client.buckets = [
                Bucket(
                    name="logging-enabled-no-prefix",
                    id="logging-enabled-no-prefix",
                    region=GCP_US_CENTER1_LOCATION,
                    uniform_bucket_level_access=True,
                    public=False,
                    retention_policy=None,
                    project_id=GCP_PROJECT_ID,
                    lifecycle_rules=[],
                    versioning_enabled=True,
                    soft_delete_enabled=True,
                    logging_bucket="log-bucket",
                    logging_prefix=None,
                )
            ]

            check = cloudstorage_bucket_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Bucket {cloudstorage_client.buckets[0].name} has Usage and Storage Logs enabled. Logs are stored in bucket 'log-bucket' with default prefix."
            )
            assert result[0].resource_id == "logging-enabled-no-prefix"
            assert result[0].resource_name == "logging-enabled-no-prefix"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID
