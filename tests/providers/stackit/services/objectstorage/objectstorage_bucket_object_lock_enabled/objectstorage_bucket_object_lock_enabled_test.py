from unittest import mock

from prowler.providers.stackit.services.objectstorage.objectstorage_service import (
    Bucket,
)
from tests.providers.stackit.stackit_fixtures import (
    STACKIT_PROJECT_ID,
    set_mocked_stackit_provider,
)


class Test_objectstorage_bucket_object_lock_enabled:
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
            from prowler.providers.stackit.services.objectstorage.objectstorage_bucket_object_lock_enabled.objectstorage_bucket_object_lock_enabled import (
                objectstorage_bucket_object_lock_enabled,
            )

            check = objectstorage_bucket_object_lock_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_bucket_object_lock_enabled(self):
        objectstorage_client = mock.MagicMock
        objectstorage_client.buckets = [
            Bucket(
                name="my-bucket",
                region="eu01",
                project_id=STACKIT_PROJECT_ID,
                object_lock_enabled=True,
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
            from prowler.providers.stackit.services.objectstorage.objectstorage_bucket_object_lock_enabled.objectstorage_bucket_object_lock_enabled import (
                objectstorage_bucket_object_lock_enabled,
            )

            check = objectstorage_bucket_object_lock_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "has S3 Object Lock enabled" in result[0].status_extended
            assert result[0].resource_id == "my-bucket"
            assert result[0].resource_name == "my-bucket"
            assert result[0].location == "eu01"

    def test_bucket_object_lock_disabled(self):
        objectstorage_client = mock.MagicMock
        objectstorage_client.buckets = [
            Bucket(
                name="my-bucket",
                region="eu01",
                project_id=STACKIT_PROJECT_ID,
                object_lock_enabled=False,
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
            from prowler.providers.stackit.services.objectstorage.objectstorage_bucket_object_lock_enabled.objectstorage_bucket_object_lock_enabled import (
                objectstorage_bucket_object_lock_enabled,
            )

            check = objectstorage_bucket_object_lock_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "does not have S3 Object Lock enabled" in result[0].status_extended
            assert result[0].resource_id == "my-bucket"
