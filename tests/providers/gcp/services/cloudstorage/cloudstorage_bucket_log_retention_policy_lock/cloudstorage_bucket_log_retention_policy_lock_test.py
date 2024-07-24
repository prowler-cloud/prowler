from unittest import mock

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    GCP_US_CENTER1_LOCATION,
    set_mocked_gcp_provider,
)


class TestCloudStorageBucketLogRetentionPolicyLock:
    def test_bucket_with_retention_policy_and_lock(self):
        cloudstorage_client = mock.MagicMock()
        logging_client = mock.MagicMock()

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_log_retention_policy_lock.cloudstorage_bucket_log_retention_policy_lock.cloudstorage_client",
            new=cloudstorage_client,
        ), mock.patch(
            "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_log_retention_policy_lock.cloudstorage_bucket_log_retention_policy_lock.logging_client",
            new=logging_client,
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_log_retention_policy_lock.cloudstorage_bucket_log_retention_policy_lock import (
                cloudstorage_bucket_log_retention_policy_lock,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
                Bucket,
            )
            from prowler.providers.gcp.services.logging.logging_service import Sink

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION

            logging_client.sinks = [
                Sink(
                    name="sink1",
                    destination="storage.googleapis.com/example-bucket",
                    filter="all",
                    project_id=GCP_PROJECT_ID,
                )
            ]

            cloudstorage_client.buckets = [
                Bucket(
                    name="example-bucket",
                    id="example-bucket",
                    region=GCP_US_CENTER1_LOCATION,
                    uniform_bucket_level_access=True,
                    public=True,
                    retention_policy={"isLocked": True},
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = cloudstorage_bucket_log_retention_policy_lock()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Log Sink Bucket {cloudstorage_client.buckets[0].name} has a Retention Policy with Bucket Lock."
            )
            assert result[0].resource_id == "example-bucket"
            assert result[0].resource_name == "example-bucket"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_bucket_with_retention_policy_without_lock(self):
        cloudstorage_client = mock.MagicMock()
        logging_client = mock.MagicMock()

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_log_retention_policy_lock.cloudstorage_bucket_log_retention_policy_lock.cloudstorage_client",
            new=cloudstorage_client,
        ), mock.patch(
            "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_log_retention_policy_lock.cloudstorage_bucket_log_retention_policy_lock.logging_client",
            new=logging_client,
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_log_retention_policy_lock.cloudstorage_bucket_log_retention_policy_lock import (
                cloudstorage_bucket_log_retention_policy_lock,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
                Bucket,
            )
            from prowler.providers.gcp.services.logging.logging_service import Sink

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION

            logging_client.sinks = [
                Sink(
                    name="sink1",
                    destination="storage.googleapis.com/example-bucket",
                    filter="all",
                    project_id=GCP_PROJECT_ID,
                )
            ]

            cloudstorage_client.buckets = [
                Bucket(
                    name="example-bucket",
                    id="example-bucket",
                    region=GCP_US_CENTER1_LOCATION,
                    uniform_bucket_level_access=True,
                    public=True,
                    retention_policy={"isLocked": False},
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = cloudstorage_bucket_log_retention_policy_lock()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Log Sink Bucket {cloudstorage_client.buckets[0].name} has no Retention Policy but without Bucket Lock."
            )
            assert result[0].resource_id == "example-bucket"
            assert result[0].resource_name == "example-bucket"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_bucket_without_retention_policy(self):
        cloudstorage_client = mock.MagicMock()
        logging_client = mock.MagicMock()

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_log_retention_policy_lock.cloudstorage_bucket_log_retention_policy_lock.cloudstorage_client",
            new=cloudstorage_client,
        ), mock.patch(
            "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_log_retention_policy_lock.cloudstorage_bucket_log_retention_policy_lock.logging_client",
            new=logging_client,
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_log_retention_policy_lock.cloudstorage_bucket_log_retention_policy_lock import (
                cloudstorage_bucket_log_retention_policy_lock,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
                Bucket,
            )
            from prowler.providers.gcp.services.logging.logging_service import Sink

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION

            logging_client.sinks = [
                Sink(
                    name="sink1",
                    destination="storage.googleapis.com/example-bucket",
                    filter="all",
                    project_id=GCP_PROJECT_ID,
                )
            ]

            cloudstorage_client.buckets = [
                Bucket(
                    name="example-bucket",
                    id="example-bucket",
                    region=GCP_US_CENTER1_LOCATION,
                    uniform_bucket_level_access=True,
                    public=True,
                    retention_policy=None,
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = cloudstorage_bucket_log_retention_policy_lock()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Log Sink Bucket {cloudstorage_client.buckets[0].name} has no Retention Policy."
            )
            assert result[0].resource_id == "example-bucket"
            assert result[0].resource_name == "example-bucket"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_no_buckets(self):
        cloudstorage_client = mock.MagicMock()
        logging_client = mock.MagicMock()

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_log_retention_policy_lock.cloudstorage_bucket_log_retention_policy_lock.cloudstorage_client",
            new=cloudstorage_client,
        ), mock.patch(
            "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_log_retention_policy_lock.cloudstorage_bucket_log_retention_policy_lock.logging_client",
            new=logging_client,
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_log_retention_policy_lock.cloudstorage_bucket_log_retention_policy_lock import (
                cloudstorage_bucket_log_retention_policy_lock,
            )
            from prowler.providers.gcp.services.logging.logging_service import Sink

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION

            logging_client.sinks = [
                Sink(
                    name="sink1",
                    destination="storage.googleapis.com/example-bucket",
                    filter="all",
                    project_id=GCP_PROJECT_ID,
                )
            ]

            cloudstorage_client.buckets = []

            check = cloudstorage_bucket_log_retention_policy_lock()
            result = check.execute()

            assert len(result) == 0

    def test_no_buckets_no_sinks(self):
        cloudstorage_client = mock.MagicMock()
        logging_client = mock.MagicMock()

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_log_retention_policy_lock.cloudstorage_bucket_log_retention_policy_lock.cloudstorage_client",
            new=cloudstorage_client,
        ), mock.patch(
            "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_log_retention_policy_lock.cloudstorage_bucket_log_retention_policy_lock.logging_client",
            new=logging_client,
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_log_retention_policy_lock.cloudstorage_bucket_log_retention_policy_lock import (
                cloudstorage_bucket_log_retention_policy_lock,
            )

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION

            logging_client.sinks = []

            cloudstorage_client.buckets = []

            check = cloudstorage_bucket_log_retention_policy_lock()
            result = check.execute()

            assert len(result) == 0
