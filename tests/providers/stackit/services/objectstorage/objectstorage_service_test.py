from types import SimpleNamespace
from unittest import mock

import pytest

from prowler.providers.stackit.services.objectstorage.objectstorage_service import (
    ObjectStorageService,
)
from tests.providers.stackit.stackit_fixtures import STACKIT_PROJECT_ID


class TestObjectStorageService:
    def test_list_buckets_keeps_bucket_when_retention_not_configured(self):
        service = ObjectStorageService.__new__(ObjectStorageService)
        service.provider = mock.MagicMock()
        service.project_id = STACKIT_PROJECT_ID
        service.buckets = []

        not_found_error = Exception("not found")
        not_found_error.status = 404

        client = mock.MagicMock()
        client.list_buckets.return_value = SimpleNamespace(
            buckets=[
                SimpleNamespace(
                    name="my-bucket",
                    object_lock_enabled=True,
                )
            ]
        )
        client.get_default_retention.side_effect = not_found_error

        service._list_buckets(client, "eu01")

        assert len(service.buckets) == 1
        assert service.buckets[0].name == "my-bucket"
        assert service.buckets[0].object_lock_enabled is True
        assert service.buckets[0].retention_days is None
        assert service.buckets[0].retention_mode is None

    def test_list_buckets_propagates_unexpected_retention_api_errors(self):
        service = ObjectStorageService.__new__(ObjectStorageService)
        service.provider = mock.MagicMock()
        service.project_id = STACKIT_PROJECT_ID
        service.buckets = []

        api_error = Exception("service unavailable")
        api_error.status = 503

        client = mock.MagicMock()
        client.list_buckets.return_value = SimpleNamespace(
            buckets=[
                SimpleNamespace(
                    name="my-bucket",
                    object_lock_enabled=True,
                )
            ]
        )
        client.get_default_retention.side_effect = api_error

        with pytest.raises(Exception, match="service unavailable"):
            service._list_buckets(client, "eu01")

        assert service.buckets == []
        service.provider.handle_api_error.assert_called_once_with(api_error)
