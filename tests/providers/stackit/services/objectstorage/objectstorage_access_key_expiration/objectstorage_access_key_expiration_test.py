from unittest import mock

from prowler.providers.stackit.services.objectstorage.objectstorage_service import (
    AccessKey,
)
from tests.providers.stackit.stackit_fixtures import (
    STACKIT_PROJECT_ID,
    set_mocked_stackit_provider,
)


class Test_objectstorage_access_key_expiration:
    def test_no_access_keys(self):
        objectstorage_client = mock.MagicMock
        objectstorage_client.access_keys = []

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
            from prowler.providers.stackit.services.objectstorage.objectstorage_access_key_expiration.objectstorage_access_key_expiration import (
                objectstorage_access_key_expiration,
            )

            check = objectstorage_access_key_expiration()
            result = check.execute()
            assert len(result) == 0

    def test_access_key_with_expiration(self):
        objectstorage_client = mock.MagicMock
        objectstorage_client.access_keys = [
            AccessKey(
                key_id="key-123",
                display_name="my-key",
                expires="2027-01-01T00:00:00+00:00",
                region="eu01",
                project_id=STACKIT_PROJECT_ID,
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
            from prowler.providers.stackit.services.objectstorage.objectstorage_access_key_expiration.objectstorage_access_key_expiration import (
                objectstorage_access_key_expiration,
            )

            check = objectstorage_access_key_expiration()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "has an expiration date set" in result[0].status_extended
            assert result[0].resource_id == "key-123"
            assert result[0].resource_name == "my-key"
            assert result[0].location == "eu01"

    def test_access_key_no_expiration_none(self):
        objectstorage_client = mock.MagicMock
        objectstorage_client.access_keys = [
            AccessKey(
                key_id="key-456",
                display_name="never-expiring-key",
                expires=None,
                region="eu01",
                project_id=STACKIT_PROJECT_ID,
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
            from prowler.providers.stackit.services.objectstorage.objectstorage_access_key_expiration.objectstorage_access_key_expiration import (
                objectstorage_access_key_expiration,
            )

            check = objectstorage_access_key_expiration()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "no expiration date" in result[0].status_extended
            assert result[0].resource_id == "key-456"

    def test_access_key_no_expiration_sentinel(self):
        """Year-0001 date is the SDK sentinel for 'never expires'."""
        objectstorage_client = mock.MagicMock
        objectstorage_client.access_keys = [
            AccessKey(
                key_id="key-789",
                display_name="sentinel-key",
                expires="0001-01-01T00:00:00+00:00",
                region="eu01",
                project_id=STACKIT_PROJECT_ID,
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
            from prowler.providers.stackit.services.objectstorage.objectstorage_access_key_expiration.objectstorage_access_key_expiration import (
                objectstorage_access_key_expiration,
            )

            check = objectstorage_access_key_expiration()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "no expiration date" in result[0].status_extended
