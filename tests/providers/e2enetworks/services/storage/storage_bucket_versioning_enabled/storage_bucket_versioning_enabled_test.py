from unittest import mock

from prowler.providers.e2enetworks.services.storage.storage_service import (
    StorageBucket,
)
from tests.providers.e2enetworks.e2enetworks_fixtures import (
    set_mocked_e2enetworks_provider,
)

CLIENT_PATH = "prowler.providers.e2enetworks.services.storage.storage_bucket_versioning_enabled.storage_bucket_versioning_enabled.storage_client"


class Test_storage_bucket_versioning_enabled:
    def test_no_buckets(self):
        client = mock.MagicMock()
        client.buckets = []
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.storage.storage_bucket_versioning_enabled.storage_bucket_versioning_enabled import (
                storage_bucket_versioning_enabled,
            )

            assert storage_bucket_versioning_enabled().execute() == []

    def test_storage_bucket_versioning_enabled_compliant(self):
        client = mock.MagicMock()
        client.buckets = [
            StorageBucket(
                id="1", name="ok", location="Delhi", versioning_status="Enabled"
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.storage.storage_bucket_versioning_enabled.storage_bucket_versioning_enabled import (
                storage_bucket_versioning_enabled,
            )

            findings = storage_bucket_versioning_enabled().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"

    def test_storage_bucket_versioning_enabled_non_compliant(self):
        client = mock.MagicMock()
        client.buckets = [
            StorageBucket(
                id="2", name="bad", location="Delhi", versioning_status="Off"
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.storage.storage_bucket_versioning_enabled.storage_bucket_versioning_enabled import (
                storage_bucket_versioning_enabled,
            )

            findings = storage_bucket_versioning_enabled().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
