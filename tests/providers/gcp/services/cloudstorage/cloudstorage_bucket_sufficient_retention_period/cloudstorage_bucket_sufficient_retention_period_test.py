from unittest import mock

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    GCP_US_CENTER1_LOCATION,
    set_mocked_gcp_provider,
)


class TestCloudStorageBucketSufficientRetentionPeriod:
    def test_no_buckets(self):
        cloudstorage_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_sufficient_retention_period.cloudstorage_bucket_sufficient_retention_period.cloudstorage_client",
                new=cloudstorage_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_sufficient_retention_period.cloudstorage_bucket_sufficient_retention_period import (
                cloudstorage_bucket_sufficient_retention_period,
            )

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION
            cloudstorage_client.buckets = []
            cloudstorage_client.audit_config = {"storage_min_retention_days": 90}

            check = cloudstorage_bucket_sufficient_retention_period()
            result = check.execute()

            assert len(result) == 0

    def test_bucket_without_retention_policy(self):
        cloudstorage_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_sufficient_retention_period.cloudstorage_bucket_sufficient_retention_period.cloudstorage_client",
                new=cloudstorage_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_sufficient_retention_period.cloudstorage_bucket_sufficient_retention_period import (
                cloudstorage_bucket_sufficient_retention_period,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
                Bucket,
            )

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION
            cloudstorage_client.audit_config = {"storage_min_retention_days": 90}

            cloudstorage_client.buckets = [
                Bucket(
                    name="no-retention-policy",
                    id="no-retention-policy",
                    region=GCP_US_CENTER1_LOCATION,
                    uniform_bucket_level_access=True,
                    public=False,
                    retention_policy=None,
                    project_id=GCP_PROJECT_ID,
                    lifecycle_rules=[],
                    versioning_enabled=True,
                )
            ]

            check = cloudstorage_bucket_sufficient_retention_period()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Bucket no-retention-policy does not have a retention policy (minimum required: 90 days)."
            )
            assert result[0].resource_id == "no-retention-policy"
            assert result[0].resource_name == "no-retention-policy"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_bucket_with_sufficient_retention_policy(self):
        cloudstorage_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_sufficient_retention_period.cloudstorage_bucket_sufficient_retention_period.cloudstorage_client",
                new=cloudstorage_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_sufficient_retention_period.cloudstorage_bucket_sufficient_retention_period import (
                cloudstorage_bucket_sufficient_retention_period,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
                Bucket,
                RetentionPolicy,
            )

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION
            cloudstorage_client.audit_config = {"storage_min_retention_days": 90}

            cloudstorage_client.buckets = [
                Bucket(
                    name="sufficient-retention-policy",
                    id="sufficient-retention-policy",
                    region=GCP_US_CENTER1_LOCATION,
                    uniform_bucket_level_access=True,
                    public=False,
                    retention_policy=RetentionPolicy(
                        retention_period=12096000,  # 140 days
                        is_locked=False,
                        effective_time=None,
                    ),
                    project_id=GCP_PROJECT_ID,
                    lifecycle_rules=[],
                    versioning_enabled=True,
                )
            ]

            check = cloudstorage_bucket_sufficient_retention_period()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Bucket sufficient-retention-policy has a sufficient retention policy of 140 days (minimum required: 90)."
            )
            assert result[0].resource_id == "sufficient-retention-policy"
            assert result[0].resource_name == "sufficient-retention-policy"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_bucket_with_insufficient_retention_policy(self):
        cloudstorage_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_sufficient_retention_period.cloudstorage_bucket_sufficient_retention_period.cloudstorage_client",
                new=cloudstorage_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_sufficient_retention_period.cloudstorage_bucket_sufficient_retention_period import (
                cloudstorage_bucket_sufficient_retention_period,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
                Bucket,
                RetentionPolicy,
            )

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION
            cloudstorage_client.audit_config = {"storage_min_retention_days": 90}

            cloudstorage_client.buckets = [
                Bucket(
                    name="insufficient-retention-policy",
                    id="insufficient-retention-policy",
                    region=GCP_US_CENTER1_LOCATION,
                    uniform_bucket_level_access=True,
                    public=False,
                    retention_policy=RetentionPolicy(
                        retention_period=604800,  # 7 days
                        is_locked=False,
                        effective_time=None,
                    ),
                    project_id=GCP_PROJECT_ID,
                    lifecycle_rules=[],
                    versioning_enabled=True,
                )
            ]

            check = cloudstorage_bucket_sufficient_retention_period()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Bucket insufficient-retention-policy has an insufficient retention policy of 7 days (minimum required: 90)."
            )
            assert result[0].resource_id == "insufficient-retention-policy"
            assert result[0].resource_name == "insufficient-retention-policy"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID
