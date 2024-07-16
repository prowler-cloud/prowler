from unittest import mock
import re

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider

class TestCloudStorageBucketLogRetentionPolicyLock:
    def test_bucket_with_retention_policy_and_lock(self):
        cloudstorage_client = mock.MagicMock()
        logging_client = mock.MagicMock()
        
        cloudstorage_client.project_ids = [GCP_PROJECT_ID]
        cloudstorage_client.region = "global"
        logging_client.sinks = [mock.MagicMock(destination="storage.googleapis.com/bucket1")]

        from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import Bucket

        cloudstorage_client.buckets = [Bucket(
            name="bucket1",
            id="bucket1",
            region="US",
            uniform_bucket_level_access=True,
            public=True,
            retention_policy={"isLocked": True},
            project_id=GCP_PROJECT_ID,
        )]

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

            check = cloudstorage_bucket_log_retention_policy_lock()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert re.search("Retention Policy with Bucket Lock", result[0].status_extended)
            assert result[0].resource_id == "bucket1"

    def test_bucket_with_retention_policy_without_lock(self):
        cloudstorage_client = mock.MagicMock()
        logging_client = mock.MagicMock()
        
        cloudstorage_client.project_ids = [GCP_PROJECT_ID]
        cloudstorage_client.region = "global"
        logging_client.sinks = [mock.MagicMock(destination="storage.googleapis.com/bucket1")]

        from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import Bucket

        cloudstorage_client.buckets = [Bucket(
            name="bucket1",
            id="bucket1",
            region="US",
            uniform_bucket_level_access=True,
            public=True,
            retention_policy={"isLocked": False},
            project_id=GCP_PROJECT_ID,
        )]

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

            check = cloudstorage_bucket_log_retention_policy_lock()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert re.search("no Retention Policy but without Bucket Lock", result[0].status_extended)
            assert result[0].resource_id == "bucket1"
    
    def test_bucket_without_retention_policy(self):
        cloudstorage_client = mock.MagicMock()
        logging_client = mock.MagicMock()
        
        cloudstorage_client.project_ids = [GCP_PROJECT_ID]
        cloudstorage_client.region = "global"
        logging_client.sinks = [mock.MagicMock(destination="storage.googleapis.com/bucket1")]

        from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import Bucket

        cloudstorage_client.buckets = [Bucket(
            name="bucket1",
            id="bucket1",
            region="US",
            uniform_bucket_level_access=True,
            public=True,
            retention_policy=None,
            project_id=GCP_PROJECT_ID,
        )]

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

            check = cloudstorage_bucket_log_retention_policy_lock()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert re.search("no Retention Policy", result[0].status_extended)
            assert result[0].resource_id == "bucket1"

 
    def test_no_buckets(self):
        cloudstorage_client = mock.MagicMock()
        logging_client = mock.MagicMock()
        
        cloudstorage_client.project_ids = [GCP_PROJECT_ID]
        cloudstorage_client.region = "global"
        logging_client.sinks = [mock.MagicMock(destination="storage.googleapis.com/bucket1")]

        cloudstorage_client.buckets = []

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

            check = cloudstorage_bucket_log_retention_policy_lock()
            result = check.execute()

            assert len(result) == 0

