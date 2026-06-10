from types import SimpleNamespace
from unittest import mock

import pytest

from prowler.providers.stackit.services.objectstorage.objectstorage_service import (
    AccessKey,
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

    def test_init_creates_service_with_no_regions(self):
        provider = mock.MagicMock()
        provider.identity.project_id = STACKIT_PROJECT_ID
        provider.generate_regional_clients.return_value = {}

        service = ObjectStorageService(provider)

        assert service.project_id == STACKIT_PROJECT_ID
        assert service.buckets == []
        assert service.access_keys == []
        provider.generate_regional_clients.assert_called_once_with("objectstorage")

    def test_fetch_all_regions_skips_404_region(self):
        service = ObjectStorageService.__new__(ObjectStorageService)
        service.provider = mock.MagicMock()
        service.project_id = STACKIT_PROJECT_ID
        service.buckets = []
        service.access_keys = []

        not_found = Exception("not found")
        not_found.status = 404
        service.regional_clients = {"eu01": mock.MagicMock()}

        with mock.patch.object(service, "_list_buckets", side_effect=not_found):
            service._fetch_all_regions()

        assert service.buckets == []

    def test_fetch_all_regions_reraises_non_404_error(self):
        service = ObjectStorageService.__new__(ObjectStorageService)
        service.provider = mock.MagicMock()
        service.project_id = STACKIT_PROJECT_ID
        service.buckets = []
        service.access_keys = []

        server_error = Exception("internal server error")
        server_error.status = 500
        service.regional_clients = {"eu01": mock.MagicMock()}

        with mock.patch.object(service, "_list_buckets", side_effect=server_error):
            with pytest.raises(Exception, match="internal server error"):
                service._fetch_all_regions()

    def test_list_buckets_with_dict_api_response(self):
        service = ObjectStorageService.__new__(ObjectStorageService)
        service.provider = mock.MagicMock()
        service.project_id = STACKIT_PROJECT_ID
        service.buckets = []

        not_found = Exception("not found")
        not_found.status = 404

        client = mock.MagicMock()
        client.list_buckets.return_value = {
            "buckets": [
                SimpleNamespace(name="dict-response-bucket", object_lock_enabled=True)
            ]
        }
        client.get_default_retention.side_effect = not_found

        service._list_buckets(client, "eu01")

        assert len(service.buckets) == 1
        assert service.buckets[0].name == "dict-response-bucket"

    def test_list_buckets_with_dict_bucket_data(self):
        service = ObjectStorageService.__new__(ObjectStorageService)
        service.provider = mock.MagicMock()
        service.project_id = STACKIT_PROJECT_ID
        service.buckets = []

        not_found = Exception("not found")
        not_found.status = 404

        client = mock.MagicMock()
        client.list_buckets.return_value = SimpleNamespace(
            buckets=[{"name": "dict-bucket", "objectLockEnabled": True}]
        )
        client.get_default_retention.side_effect = not_found

        service._list_buckets(client, "eu01")

        assert len(service.buckets) == 1
        assert service.buckets[0].name == "dict-bucket"
        assert service.buckets[0].object_lock_enabled is True

    def test_list_buckets_skips_unknown_bucket_type(self):
        service = ObjectStorageService.__new__(ObjectStorageService)
        service.provider = mock.MagicMock()
        service.project_id = STACKIT_PROJECT_ID
        service.buckets = []

        client = mock.MagicMock()
        client.list_buckets.return_value = SimpleNamespace(buckets=[42])

        service._list_buckets(client, "eu01")

        assert len(service.buckets) == 0

    def test_get_default_retention_with_dict_response(self):
        service = ObjectStorageService.__new__(ObjectStorageService)
        service.provider = mock.MagicMock()
        service.project_id = STACKIT_PROJECT_ID

        client = mock.MagicMock()
        client.get_default_retention.return_value = {"days": 14, "mode": "GOVERNANCE"}

        days, mode = service._get_default_retention(client, "eu01", "my-bucket")

        assert days == 14
        assert mode == "GOVERNANCE"

    def test_list_access_keys_with_object_data(self):
        service = ObjectStorageService.__new__(ObjectStorageService)
        service.provider = mock.MagicMock()
        service.project_id = STACKIT_PROJECT_ID
        service.access_keys = []

        client = mock.MagicMock()
        client.list_credentials_groups.return_value = SimpleNamespace(
            credentials_groups=[SimpleNamespace(id="cg-001", display_name="main-group")]
        )
        client.list_access_keys.return_value = SimpleNamespace(
            access_keys=[
                SimpleNamespace(
                    key_id="key-001",
                    display_name="my-key",
                    expires="2027-01-01T00:00:00+00:00",
                )
            ]
        )

        service._list_access_keys(client, "eu01")

        client.list_credentials_groups.assert_called_once_with(
            project_id=STACKIT_PROJECT_ID, region="eu01"
        )
        client.list_access_keys.assert_called_once_with(
            project_id=STACKIT_PROJECT_ID, region="eu01", credentials_group="cg-001"
        )
        assert len(service.access_keys) == 1
        assert service.access_keys[0].key_id == "key-001"
        assert service.access_keys[0].display_name == "my-key"
        assert service.access_keys[0].region == "eu01"
        assert service.access_keys[0].expires == "2027-01-01T00:00:00+00:00"
        assert service.access_keys[0].credentials_group_id == "cg-001"
        assert service.access_keys[0].credentials_group_name == "main-group"

    def test_list_access_keys_with_credentials_group_id_object_data(self):
        service = ObjectStorageService.__new__(ObjectStorageService)
        service.provider = mock.MagicMock()
        service.project_id = STACKIT_PROJECT_ID
        service.access_keys = []

        client = mock.MagicMock()
        client.list_credentials_groups.return_value = SimpleNamespace(
            credentials_groups=[
                SimpleNamespace(
                    credentials_group_id="cg-sdk",
                    display_name="sdk-group",
                )
            ]
        )
        client.list_access_keys.return_value = SimpleNamespace(access_keys=[])

        service._list_access_keys(client, "eu01")

        client.list_access_keys.assert_called_once_with(
            project_id=STACKIT_PROJECT_ID, region="eu01", credentials_group="cg-sdk"
        )

    def test_list_access_keys_collects_keys_from_multiple_credentials_groups(self):
        service = ObjectStorageService.__new__(ObjectStorageService)
        service.provider = mock.MagicMock()
        service.project_id = STACKIT_PROJECT_ID
        service.access_keys = []

        client = mock.MagicMock()
        client.list_credentials_groups.return_value = SimpleNamespace(
            credentials_groups=[
                SimpleNamespace(id="cg-001", display_name="group-one"),
                SimpleNamespace(id="cg-002", display_name="group-two"),
            ]
        )
        client.list_access_keys.side_effect = [
            SimpleNamespace(
                access_keys=[
                    SimpleNamespace(
                        key_id="key-001",
                        display_name="key-one",
                        expires="2027-01-01T00:00:00+00:00",
                    )
                ]
            ),
            SimpleNamespace(
                access_keys=[
                    SimpleNamespace(
                        key_id="key-002",
                        display_name="key-two",
                        expires=None,
                    )
                ]
            ),
        ]

        service._list_access_keys(client, "eu01")

        assert client.list_access_keys.call_args_list == [
            mock.call(
                project_id=STACKIT_PROJECT_ID,
                region="eu01",
                credentials_group="cg-001",
            ),
            mock.call(
                project_id=STACKIT_PROJECT_ID,
                region="eu01",
                credentials_group="cg-002",
            ),
        ]
        assert [key.key_id for key in service.access_keys] == ["key-001", "key-002"]
        assert service.access_keys[1].expires is None
        assert service.access_keys[1].has_expiration() is False
        assert [key.credentials_group_id for key in service.access_keys] == [
            "cg-001",
            "cg-002",
        ]

    def test_list_access_keys_with_dict_api_response(self):
        service = ObjectStorageService.__new__(ObjectStorageService)
        service.provider = mock.MagicMock()
        service.project_id = STACKIT_PROJECT_ID
        service.access_keys = []

        client = mock.MagicMock()
        client.list_credentials_groups.return_value = {
            "credentialsGroups": [{"id": "cg-dict", "displayName": "dict-group"}]
        }
        client.list_access_keys.return_value = {
            "accessKeys": [
                {"keyId": "key-dict", "displayName": "dict-key", "expires": None}
            ]
        }

        service._list_access_keys(client, "eu01")

        assert len(service.access_keys) == 1
        assert service.access_keys[0].key_id == "key-dict"
        assert service.access_keys[0].display_name == "dict-key"
        assert service.access_keys[0].expires is None
        assert service.access_keys[0].has_expiration() is False
        assert service.access_keys[0].credentials_group_id == "cg-dict"
        assert service.access_keys[0].credentials_group_name == "dict-group"

    def test_list_access_keys_with_raw_json_response_and_null_expires(self):
        service = ObjectStorageService.__new__(ObjectStorageService)
        service.provider = mock.MagicMock()
        service.project_id = STACKIT_PROJECT_ID
        service.access_keys = []

        class RawResponse:
            status = 200

            def json(self):
                return {
                    "accessKeys": [
                        {
                            "keyId": "key-raw",
                            "displayName": "raw-key",
                            "expires": None,
                        }
                    ]
                }

        class FakeClient:
            def __init__(self):
                self.list_credentials_groups = mock.MagicMock(
                    return_value=SimpleNamespace(
                        credentials_groups=[SimpleNamespace(id="cg-raw")]
                    )
                )
                self.list_access_keys = mock.MagicMock()
                self.raw_call = None

            def list_access_keys_without_preload_content(self, **kwargs):
                self.raw_call = kwargs
                return RawResponse()

        client = FakeClient()

        service._list_access_keys(client, "eu01")

        assert client.raw_call == {
            "project_id": STACKIT_PROJECT_ID,
            "region": "eu01",
            "credentials_group": "cg-raw",
        }
        client.list_access_keys.assert_not_called()
        assert len(service.access_keys) == 1
        assert service.access_keys[0].key_id == "key-raw"
        assert service.access_keys[0].expires is None
        assert service.access_keys[0].has_expiration() is False

    def test_list_access_keys_with_raw_data_response(self):
        service = ObjectStorageService.__new__(ObjectStorageService)
        service.provider = mock.MagicMock()
        service.project_id = STACKIT_PROJECT_ID
        service.access_keys = []

        class RawResponse:
            status = 200
            data = b'{"accessKeys":[{"keyId":"key-data","displayName":"data-key"}]}'

        class FakeClient:
            def __init__(self):
                self.list_credentials_groups = mock.MagicMock(
                    return_value=SimpleNamespace(
                        credentials_groups=[SimpleNamespace(id="cg-data")]
                    )
                )

            def list_access_keys_without_preload_content(self, **kwargs):
                return RawResponse()

        service._list_access_keys(FakeClient(), "eu01")

        assert len(service.access_keys) == 1
        assert service.access_keys[0].key_id == "key-data"
        assert service.access_keys[0].display_name == "data-key"

    def test_list_access_keys_raw_response_propagates_non_success_status(self):
        service = ObjectStorageService.__new__(ObjectStorageService)
        service.provider = mock.MagicMock()
        service.project_id = STACKIT_PROJECT_ID
        service.access_keys = []

        class RawResponse:
            status = 503

        class FakeClient:
            def __init__(self):
                self.list_credentials_groups = mock.MagicMock(
                    return_value=SimpleNamespace(
                        credentials_groups=[SimpleNamespace(id="cg-error")]
                    )
                )

            def list_access_keys_without_preload_content(self, **kwargs):
                return RawResponse()

        with pytest.raises(Exception, match="status 503") as error:
            service._list_access_keys(FakeClient(), "eu01")

        assert error.value.status == 503
        service.provider.handle_api_error.assert_called_once_with(error.value)

    def test_list_access_keys_with_dict_key_data(self):
        service = ObjectStorageService.__new__(ObjectStorageService)
        service.provider = mock.MagicMock()
        service.project_id = STACKIT_PROJECT_ID
        service.access_keys = []

        client = mock.MagicMock()
        client.list_credentials_groups.return_value = SimpleNamespace(
            credentials_groups=[{"id": "cg-456", "displayName": "group-456"}]
        )
        client.list_access_keys.return_value = SimpleNamespace(
            access_keys=[
                {
                    "keyId": "key-456",
                    "displayName": "my-dict-key",
                    "expires": "2028-06-01T00:00:00+00:00",
                }
            ]
        )

        service._list_access_keys(client, "eu01")

        assert len(service.access_keys) == 1
        assert service.access_keys[0].key_id == "key-456"
        assert service.access_keys[0].display_name == "my-dict-key"
        assert service.access_keys[0].credentials_group_id == "cg-456"

    def test_list_access_keys_skips_unknown_type(self):
        service = ObjectStorageService.__new__(ObjectStorageService)
        service.provider = mock.MagicMock()
        service.project_id = STACKIT_PROJECT_ID
        service.access_keys = []

        client = mock.MagicMock()
        client.list_credentials_groups.return_value = SimpleNamespace(
            credentials_groups=[SimpleNamespace(id="cg-001")]
        )
        client.list_access_keys.return_value = SimpleNamespace(access_keys=[42])

        service._list_access_keys(client, "eu01")

        assert len(service.access_keys) == 0

    def test_list_access_keys_no_keys(self):
        service = ObjectStorageService.__new__(ObjectStorageService)
        service.provider = mock.MagicMock()
        service.project_id = STACKIT_PROJECT_ID
        service.access_keys = []

        client = mock.MagicMock()
        client.list_credentials_groups.return_value = SimpleNamespace(
            credentials_groups=[SimpleNamespace(id="cg-empty")]
        )
        client.list_access_keys.return_value = SimpleNamespace(access_keys=[])

        service._list_access_keys(client, "eu01")

        assert len(service.access_keys) == 0

    def test_list_access_keys_no_credentials_groups(self):
        service = ObjectStorageService.__new__(ObjectStorageService)
        service.provider = mock.MagicMock()
        service.project_id = STACKIT_PROJECT_ID
        service.access_keys = []

        client = mock.MagicMock()
        client.list_credentials_groups.return_value = SimpleNamespace(
            credentials_groups=[]
        )

        service._list_access_keys(client, "eu01")

        assert len(service.access_keys) == 0
        client.list_access_keys.assert_not_called()

    def test_list_access_keys_skips_malformed_credentials_groups(self):
        service = ObjectStorageService.__new__(ObjectStorageService)
        service.provider = mock.MagicMock()
        service.project_id = STACKIT_PROJECT_ID
        service.access_keys = []

        client = mock.MagicMock()
        client.list_credentials_groups.return_value = SimpleNamespace(
            credentials_groups=[
                42,
                {},
                SimpleNamespace(id="cg-valid", display_name="valid-group"),
            ]
        )
        client.list_access_keys.return_value = SimpleNamespace(
            access_keys=[SimpleNamespace(key_id="key-valid")]
        )

        service._list_access_keys(client, "eu01")

        client.list_access_keys.assert_called_once_with(
            project_id=STACKIT_PROJECT_ID, region="eu01", credentials_group="cg-valid"
        )
        assert len(service.access_keys) == 1
        assert service.access_keys[0].key_id == "key-valid"

    def test_fetch_all_regions_calls_both_list_methods(self):
        service = ObjectStorageService.__new__(ObjectStorageService)
        service.provider = mock.MagicMock()
        service.project_id = STACKIT_PROJECT_ID
        service.buckets = []
        service.access_keys = []

        service.regional_clients = {"eu01": mock.MagicMock()}

        with (
            mock.patch.object(service, "_list_buckets") as mock_buckets,
            mock.patch.object(service, "_list_access_keys") as mock_keys,
        ):
            service._fetch_all_regions()

        mock_buckets.assert_called_once()
        mock_keys.assert_called_once()

    def test_list_buckets_handles_bucket_processing_error(self):
        service = ObjectStorageService.__new__(ObjectStorageService)
        service.provider = mock.MagicMock()
        service.project_id = STACKIT_PROJECT_ID
        service.buckets = []

        class BrokenBucket:
            @property
            def name(self):
                raise RuntimeError("broken bucket attribute")

        client = mock.MagicMock()
        client.list_buckets.return_value = SimpleNamespace(buckets=[BrokenBucket()])

        service._list_buckets(client, "eu01")

        assert len(service.buckets) == 0

    def test_list_access_keys_handles_key_processing_error(self):
        service = ObjectStorageService.__new__(ObjectStorageService)
        service.provider = mock.MagicMock()
        service.project_id = STACKIT_PROJECT_ID
        service.access_keys = []

        class BrokenKey:
            @property
            def key_id(self):
                raise RuntimeError("broken key attribute")

        client = mock.MagicMock()
        client.list_credentials_groups.return_value = SimpleNamespace(
            credentials_groups=[SimpleNamespace(id="cg-001")]
        )
        client.list_access_keys.return_value = SimpleNamespace(
            access_keys=[BrokenKey()]
        )

        service._list_access_keys(client, "eu01")

        assert len(service.access_keys) == 0


class TestAccessKeyModel:
    def test_has_expiration_with_invalid_date_string(self):
        key = AccessKey(
            key_id="k",
            display_name="k",
            expires="not-a-valid-date",
            region="eu01",
            project_id=STACKIT_PROJECT_ID,
        )
        assert key.has_expiration() is False

    def test_expires_within_days_when_no_expiration(self):
        key = AccessKey(
            key_id="k",
            display_name="k",
            expires=None,
            region="eu01",
            project_id=STACKIT_PROJECT_ID,
        )
        assert key.expires is None
        assert key.has_expiration() is False
        assert key.expires_within_days(90) is False

    def test_expires_within_days_when_expiring_soon(self):
        key = AccessKey(
            key_id="k",
            display_name="k",
            expires="2026-06-15T00:00:00+00:00",
            region="eu01",
            project_id=STACKIT_PROJECT_ID,
        )
        assert key.expires_within_days(90) is True

    def test_expires_within_days_when_not_expiring_soon(self):
        key = AccessKey(
            key_id="k",
            display_name="k",
            expires="2030-01-01T00:00:00+00:00",
            region="eu01",
            project_id=STACKIT_PROJECT_ID,
        )
        assert key.expires_within_days(30) is False

    def test_expires_within_days_with_naive_datetime(self):
        key = AccessKey(
            key_id="k",
            display_name="k",
            expires="2026-06-10T00:00:00",
            region="eu01",
            project_id=STACKIT_PROJECT_ID,
        )
        assert key.expires_within_days(90) is True

    def test_expires_within_days_with_sentinel_key(self):
        key = AccessKey(
            key_id="k",
            display_name="k",
            expires="0001-01-01T00:00:00+00:00",
            region="eu01",
            project_id=STACKIT_PROJECT_ID,
        )
        assert key.expires_within_days(90) is False
