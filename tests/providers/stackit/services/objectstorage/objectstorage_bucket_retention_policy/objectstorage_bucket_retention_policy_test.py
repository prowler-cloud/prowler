from unittest import mock

from prowler.providers.stackit.services.objectstorage.objectstorage_service import (
    Bucket,
)
from tests.providers.stackit.stackit_fixtures import (
    STACKIT_PROJECT_ID,
    set_mocked_stackit_provider,
)


class Test_objectstorage_bucket_retention_policy:
    def test_no_buckets(self):
        objectstorage_client = mock.MagicMock
        objectstorage_client.buckets = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_stackit_provider(),
            ),
            mock.patch(
                "prowler.providers.stackit.services.objectstorage.objectstorage_service.ObjectStorageService",
                new=objectstorage_client,
            ) as service_client,
            mock.patch(
                "prowler.providers.stackit.services.objectstorage.objectstorage_client.objectstorage_client",
                new=service_client,
            ),
        ):
            from prowler.providers.stackit.services.objectstorage.objectstorage_bucket_retention_policy.objectstorage_bucket_retention_policy import (
                objectstorage_bucket_retention_policy,
            )

            check = objectstorage_bucket_retention_policy()
            result = check.execute()
            assert len(result) == 0

    def test_bucket_with_retention_policy(self):
        objectstorage_client = mock.MagicMock
        objectstorage_client.buckets = [
            Bucket(
                name="my-bucket",
                region="eu01",
                project_id=STACKIT_PROJECT_ID,
                object_lock_enabled=True,
                retention_days=30,
                retention_mode="COMPLIANCE",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_stackit_provider(),
            ),
            mock.patch(
                "prowler.providers.stackit.services.objectstorage.objectstorage_service.ObjectStorageService",
                new=objectstorage_client,
            ) as service_client,
            mock.patch(
                "prowler.providers.stackit.services.objectstorage.objectstorage_client.objectstorage_client",
                new=service_client,
            ),
        ):
            from prowler.providers.stackit.services.objectstorage.objectstorage_bucket_retention_policy.objectstorage_bucket_retention_policy import (
                objectstorage_bucket_retention_policy,
            )

            check = objectstorage_bucket_retention_policy()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "30 day(s)" in result[0].status_extended
            assert "COMPLIANCE" in result[0].status_extended
            assert result[0].resource_id == "my-bucket"
            assert result[0].location == "eu01"

    def test_bucket_without_retention_policy(self):
        objectstorage_client = mock.MagicMock
        objectstorage_client.buckets = [
            Bucket(
                name="my-bucket",
                region="eu01",
                project_id=STACKIT_PROJECT_ID,
                object_lock_enabled=False,
                retention_days=None,
                retention_mode=None,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_stackit_provider(),
            ),
            mock.patch(
                "prowler.providers.stackit.services.objectstorage.objectstorage_service.ObjectStorageService",
                new=objectstorage_client,
            ) as service_client,
            mock.patch(
                "prowler.providers.stackit.services.objectstorage.objectstorage_client.objectstorage_client",
                new=service_client,
            ),
        ):
            from prowler.providers.stackit.services.objectstorage.objectstorage_bucket_retention_policy.objectstorage_bucket_retention_policy import (
                objectstorage_bucket_retention_policy,
            )

            check = objectstorage_bucket_retention_policy()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "does not have a default retention policy" in result[0].status_extended
            )
            assert result[0].resource_id == "my-bucket"

    def test_bucket_retention_zero_days(self):
        objectstorage_client = mock.MagicMock
        objectstorage_client.buckets = [
            Bucket(
                name="my-bucket",
                region="eu01",
                project_id=STACKIT_PROJECT_ID,
                object_lock_enabled=True,
                retention_days=0,
                retention_mode="GOVERNANCE",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_stackit_provider(),
            ),
            mock.patch(
                "prowler.providers.stackit.services.objectstorage.objectstorage_service.ObjectStorageService",
                new=objectstorage_client,
            ) as service_client,
            mock.patch(
                "prowler.providers.stackit.services.objectstorage.objectstorage_client.objectstorage_client",
                new=service_client,
            ),
        ):
            from prowler.providers.stackit.services.objectstorage.objectstorage_bucket_retention_policy.objectstorage_bucket_retention_policy import (
                objectstorage_bucket_retention_policy,
            )

            check = objectstorage_bucket_retention_policy()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
