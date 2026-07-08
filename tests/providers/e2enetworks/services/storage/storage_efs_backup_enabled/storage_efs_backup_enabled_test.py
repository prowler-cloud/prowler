from unittest import mock

from prowler.providers.e2enetworks.services.storage.storage_service import (
    EfsVolume,
)
from tests.providers.e2enetworks.e2enetworks_fixtures import (
    set_mocked_e2enetworks_provider,
)

CLIENT_PATH = "prowler.providers.e2enetworks.services.storage.storage_efs_backup_enabled.storage_efs_backup_enabled.storage_client"


class Test_storage_efs_backup_enabled:
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
            from prowler.providers.e2enetworks.services.storage.storage_efs_backup_enabled.storage_efs_backup_enabled import (
                storage_efs_backup_enabled,
            )

            assert storage_efs_backup_enabled().execute() == []

    def test_storage_efs_backup_enabled_compliant(self):
        client = mock.MagicMock()
        client.efs_volumes = [
            EfsVolume(id="1", name="ok", location="Delhi", is_backup_enabled=True),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.storage.storage_efs_backup_enabled.storage_efs_backup_enabled import (
                storage_efs_backup_enabled,
            )

            findings = storage_efs_backup_enabled().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"

    def test_storage_efs_backup_enabled_non_compliant(self):
        client = mock.MagicMock()
        client.efs_volumes = [
            EfsVolume(id="2", name="bad", location="Delhi", is_backup_enabled=False),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.storage.storage_efs_backup_enabled.storage_efs_backup_enabled import (
                storage_efs_backup_enabled,
            )

            findings = storage_efs_backup_enabled().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
