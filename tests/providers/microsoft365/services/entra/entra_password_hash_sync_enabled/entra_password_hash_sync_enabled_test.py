from unittest import mock

from prowler.providers.microsoft365.services.entra.entra_service import Organization
from tests.providers.microsoft365.microsoft365_fixtures import (
    set_mocked_microsoft365_provider,
)


class Test_entra_password_hash_sync_enabled:
    def test_password_hash_sync_enabled(self):
        org = Organization(
            id="org1",
            name="Organization 1",
            on_premises_sync_enabled=True,
            location="USA",
        )

        entra_client = mock.MagicMock()
        entra_client.organization = [org]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_microsoft365_provider(),
        ), mock.patch(
            "prowler.providers.microsoft365.services.entra.entra_password_hash_sync_enabled.entra_password_hash_sync_enabled.entra_client",
            new=entra_client,
        ):
            from prowler.providers.microsoft365.services.entra.entra_password_hash_sync_enabled.entra_password_hash_sync_enabled import (
                entra_password_hash_sync_enabled,
            )

            check = entra_password_hash_sync_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Password hash synchronization is enabled for hybrid Microsoft Entra deployments."
            )
            assert result[0].resource_id == "org1"

    def test_password_hash_sync_disabled(self):
        org = Organization(
            id="org2",
            name="Organization 2",
            on_premises_sync_enabled=False,
            location="USA",
        )

        entra_client = mock.MagicMock()
        entra_client.organization = [org]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_microsoft365_provider(),
        ), mock.patch(
            "prowler.providers.microsoft365.services.entra.entra_password_hash_sync_enabled.entra_password_hash_sync_enabled.entra_client",
            new=entra_client,
        ):
            from prowler.providers.microsoft365.services.entra.entra_password_hash_sync_enabled.entra_password_hash_sync_enabled import (
                entra_password_hash_sync_enabled,
            )

            check = entra_password_hash_sync_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Password hash synchronization is not enabled for hybrid Microsoft Entra deployments."
            )
            assert result[0].resource_id == "org2"

    def test_empty_organization(self):
        entra_client = mock.MagicMock()
        entra_client.organization = []

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_microsoft365_provider(),
        ), mock.patch(
            "prowler.providers.microsoft365.services.entra.entra_password_hash_sync_enabled.entra_password_hash_sync_enabled.entra_client",
            new=entra_client,
        ):
            from prowler.providers.microsoft365.services.entra.entra_password_hash_sync_enabled.entra_password_hash_sync_enabled import (
                entra_password_hash_sync_enabled,
            )

            check = entra_password_hash_sync_enabled()
            result = check.execute()

            assert len(result) == 0
