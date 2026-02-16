from unittest import mock

from prowler.providers.m365.services.entra.entra_service import Organization
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider


class Test_entra_seamless_sso_disabled:
    def test_no_on_premises_sync(self):
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_seamless_sso_disabled.entra_seamless_sso_disabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_seamless_sso_disabled.entra_seamless_sso_disabled import (
                entra_seamless_sso_disabled,
            )

            org = Organization(
                id="org1",
                name="Organization 1",
                on_premises_sync_enabled=False,
            )
            entra_client.organizations = [org]

            check = entra_seamless_sso_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Entra organization Organization 1 does not have on-premises sync enabled, Seamless SSO is not applicable."
            )
            assert result[0].resource_id == "org1"
            assert result[0].resource_name == "Organization 1"
            assert result[0].location == "global"
            assert result[0].resource == org.dict()

    def test_on_premises_sync_enabled(self):
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_seamless_sso_disabled.entra_seamless_sso_disabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_seamless_sso_disabled.entra_seamless_sso_disabled import (
                entra_seamless_sso_disabled,
            )

            org = Organization(
                id="org1",
                name="Organization 1",
                on_premises_sync_enabled=True,
            )
            entra_client.organizations = [org]

            check = entra_seamless_sso_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Entra organization Organization 1 has on-premises sync enabled, Seamless SSO should be disabled to prevent lateral movement and brute force attacks."
            )
            assert result[0].resource_id == "org1"
            assert result[0].resource_name == "Organization 1"
            assert result[0].location == "global"
            assert result[0].resource == org.dict()

    def test_multiple_organizations_mixed(self):
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_seamless_sso_disabled.entra_seamless_sso_disabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_seamless_sso_disabled.entra_seamless_sso_disabled import (
                entra_seamless_sso_disabled,
            )

            org1 = Organization(
                id="org1",
                name="Organization 1",
                on_premises_sync_enabled=True,
            )
            org2 = Organization(
                id="org2",
                name="Organization 2",
                on_premises_sync_enabled=False,
            )
            entra_client.organizations = [org1, org2]

            check = entra_seamless_sso_disabled()
            result = check.execute()

            assert len(result) == 2
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Entra organization Organization 1 has on-premises sync enabled, Seamless SSO should be disabled to prevent lateral movement and brute force attacks."
            )
            assert result[0].resource_id == "org1"
            assert result[0].resource_name == "Organization 1"
            assert result[0].location == "global"
            assert result[0].resource == org1.dict()
            assert result[1].status == "PASS"
            assert (
                result[1].status_extended
                == "Entra organization Organization 2 does not have on-premises sync enabled, Seamless SSO is not applicable."
            )
            assert result[1].resource_id == "org2"
            assert result[1].resource_name == "Organization 2"
            assert result[1].location == "global"
            assert result[1].resource == org2.dict()

    def test_empty_organizations(self):
        entra_client = mock.MagicMock()
        entra_client.organizations = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_seamless_sso_disabled.entra_seamless_sso_disabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_seamless_sso_disabled.entra_seamless_sso_disabled import (
                entra_seamless_sso_disabled,
            )

            check = entra_seamless_sso_disabled()
            result = check.execute()

            assert len(result) == 0
