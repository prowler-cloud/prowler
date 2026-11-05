from unittest import mock

from prowler.providers.e2enetworks.services.storage.storage_service import (
    EfsVolume,
)
from tests.providers.e2enetworks.e2enetworks_fixtures import (
    set_mocked_e2enetworks_provider,
)

CLIENT_PATH = "prowler.providers.e2enetworks.services.storage.storage_efs_vpc_access_restricted.storage_efs_vpc_access_restricted.storage_client"


class Test_storage_efs_vpc_access_restricted:
    def test_no_efs_volumes(self):
        client = mock.MagicMock()
        client.efs_volumes = []
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.storage.storage_efs_vpc_access_restricted.storage_efs_vpc_access_restricted import (
                storage_efs_vpc_access_restricted,
            )

            assert storage_efs_vpc_access_restricted().execute() == []

    def test_storage_efs_vpc_access_restricted_compliant(self):
        client = mock.MagicMock()
        client.efs_volumes = [
            EfsVolume(
                id="1", name="ok", location="Delhi", is_all_vpc_resources_allowed=False
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.storage.storage_efs_vpc_access_restricted.storage_efs_vpc_access_restricted import (
                storage_efs_vpc_access_restricted,
            )

            findings = storage_efs_vpc_access_restricted().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"

    def test_storage_efs_vpc_access_restricted_non_compliant(self):
        client = mock.MagicMock()
        client.efs_volumes = [
            EfsVolume(
                id="2", name="bad", location="Delhi", is_all_vpc_resources_allowed=True
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.storage.storage_efs_vpc_access_restricted.storage_efs_vpc_access_restricted import (
                storage_efs_vpc_access_restricted,
            )

            findings = storage_efs_vpc_access_restricted().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
