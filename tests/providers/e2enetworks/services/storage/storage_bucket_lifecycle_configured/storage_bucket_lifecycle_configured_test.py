from unittest import mock

from prowler.providers.e2enetworks.services.storage.storage_service import (
    StorageBucket,
)
from tests.providers.e2enetworks.e2enetworks_fixtures import (
    set_mocked_e2enetworks_provider,
)

CLIENT_PATH = "prowler.providers.e2enetworks.services.storage.storage_bucket_lifecycle_configured.storage_bucket_lifecycle_configured.storage_client"


class Test_storage_bucket_lifecycle_configured:
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
            from prowler.providers.e2enetworks.services.storage.storage_bucket_lifecycle_configured.storage_bucket_lifecycle_configured import (
                storage_bucket_lifecycle_configured,
            )

            assert storage_bucket_lifecycle_configured().execute() == []

    def test_storage_bucket_lifecycle_configured_compliant(self):
        client = mock.MagicMock()
        client.buckets = [
            StorageBucket(
                id="1",
                name="ok",
                location="Delhi",
                lifecycle_configuration_status="Configured",
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.storage.storage_bucket_lifecycle_configured.storage_bucket_lifecycle_configured import (
                storage_bucket_lifecycle_configured,
            )

            findings = storage_bucket_lifecycle_configured().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"

    def test_storage_bucket_lifecycle_configured_non_compliant(self):
        client = mock.MagicMock()
        client.buckets = [
            StorageBucket(
                id="2",
                name="bad",
                location="Delhi",
                lifecycle_configuration_status="Disabled",
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.storage.storage_bucket_lifecycle_configured.storage_bucket_lifecycle_configured import (
                storage_bucket_lifecycle_configured,
            )

            findings = storage_bucket_lifecycle_configured().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
