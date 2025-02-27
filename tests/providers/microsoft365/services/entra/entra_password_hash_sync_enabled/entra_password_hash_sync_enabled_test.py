from unittest import mock

from prowler.providers.microsoft365.services.entra.entra_service import Organization
from tests.providers.microsoft365.microsoft365_fixtures import (
    set_mocked_microsoft365_provider,
)


class Test_entra_password_hash_sync_enabled:
    def test_password_hash_sync_enabled(self):
        entra_client = mock.MagicMock()

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

            org = Organization(
                id="org1",
                name="Organization 1",
                on_premises_sync_enabled=True,
            )
            entra_client.organizations = [org]

            check = entra_password_hash_sync_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Password hash synchronization is enabled for hybrid Microsoft Entra deployments."
            )
            assert result[0].resource_id == "org1"
            assert result[0].resource_name == "Organization 1"
            assert result[0].location == "global"
            assert result[0].resource == {
                "id": "org1",
                "name": "Organization 1",
                "on_premises_sync_enabled": True,
            }

    def test_password_hash_sync_disabled(self):
        entra_client = mock.MagicMock()

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

            org1 = Organization(
                id="org1",
                name="Organization 1",
                on_premises_sync_enabled=False,
            )
            org2 = Organization(
                id="org2",
                name="Organization 2",
                on_premises_sync_enabled=True,
            )
            entra_client.organizations = [org1, org2]

            check = entra_password_hash_sync_enabled()
            result = check.execute()

            assert len(result) == 2
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Password hash synchronization is not enabled for hybrid Microsoft Entra deployments."
            )
            assert result[0].resource_id == "org1"
            assert result[0].resource_name == "Organization 1"
            assert result[0].location == "global"
            assert result[0].resource == {
                "id": "org1",
                "name": "Organization 1",
                "on_premises_sync_enabled": False,
            }
            assert result[1].status == "PASS"
            assert (
                result[1].status_extended
                == "Password hash synchronization is enabled for hybrid Microsoft Entra deployments."
            )
            assert result[1].resource_id == "org2"
            assert result[1].resource_name == "Organization 2"
            assert result[1].location == "global"
            assert result[1].resource == {
                "id": "org2",
                "name": "Organization 2",
                "on_premises_sync_enabled": True,
            }

    def test_password_hash_sync_disabled_two_org(self):
        entra_client = mock.MagicMock()

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

            org = Organization(
                id="org2",
                name="Organization 2",
                on_premises_sync_enabled=False,
            )
            entra_client.organizations = [org]

            check = entra_password_hash_sync_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Password hash synchronization is not enabled for hybrid Microsoft Entra deployments."
            )
            assert result[0].resource_id == "org2"
            assert result[0].resource_name == "Organization 2"
            assert result[0].location == "global"
            assert result[0].resource == {
                "id": "org2",
                "name": "Organization 2",
                "on_premises_sync_enabled": False,
            }

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
