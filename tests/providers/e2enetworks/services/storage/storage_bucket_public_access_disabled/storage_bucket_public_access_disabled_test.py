from unittest import mock

from prowler.providers.e2enetworks.services.storage.storage_service import (
    StorageBucket,
)
from tests.providers.e2enetworks.e2enetworks_fixtures import (
    set_mocked_e2enetworks_provider,
)

CLIENT_PATH = "prowler.providers.e2enetworks.services.storage.storage_bucket_public_access_disabled.storage_bucket_public_access_disabled.storage_client"


class Test_storage_bucket_public_access_disabled:
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
            from prowler.providers.e2enetworks.services.storage.storage_bucket_public_access_disabled.storage_bucket_public_access_disabled import (
                storage_bucket_public_access_disabled,
            )

            assert storage_bucket_public_access_disabled().execute() == []

    def test_storage_bucket_public_access_disabled_compliant(self):
        client = mock.MagicMock()
        client.buckets = [
            StorageBucket(
                id="1", name="ok", location="Delhi", is_public_access_enabled=False
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.storage.storage_bucket_public_access_disabled.storage_bucket_public_access_disabled import (
                storage_bucket_public_access_disabled,
            )

            findings = storage_bucket_public_access_disabled().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"

    def test_storage_bucket_public_access_disabled_non_compliant(self):
        client = mock.MagicMock()
        client.buckets = [
            StorageBucket(
                id="2", name="bad", location="Delhi", is_public_access_enabled=True
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.storage.storage_bucket_public_access_disabled.storage_bucket_public_access_disabled import (
                storage_bucket_public_access_disabled,
            )

            findings = storage_bucket_public_access_disabled().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
