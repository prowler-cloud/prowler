from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    AuthorizationPolicy,
    DefaultUserRolePermissions,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider


class Test_entra_policy_msol_powershell_blocked:
    """Tests for the entra_policy_msol_powershell_blocked check."""

    def test_authorization_policy_none(self):
        """MANUAL when the authorization policy could not be retrieved."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_policy_msol_powershell_blocked.entra_policy_msol_powershell_blocked.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_policy_msol_powershell_blocked.entra_policy_msol_powershell_blocked import (
                entra_policy_msol_powershell_blocked,
            )

            entra_client.authorization_policy = None

            result = entra_policy_msol_powershell_blocked().execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert result[0].resource_id == "authorizationPolicy"
            assert result[0].resource_name == "Authorization Policy"
            assert "could not be retrieved" in result[0].status_extended

    def test_block_msol_powershell_none(self):
        """MANUAL when blockMsolPowerShell is missing/null in the response."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_policy_msol_powershell_blocked.entra_policy_msol_powershell_blocked.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_policy_msol_powershell_blocked.entra_policy_msol_powershell_blocked import (
                entra_policy_msol_powershell_blocked,
            )

            entra_client.authorization_policy = AuthorizationPolicy(
                id="authorizationPolicy",
                name="Authorization Policy",
                description="",
                default_user_role_permissions=DefaultUserRolePermissions(),
                block_msol_powershell=None,
            )

            result = entra_policy_msol_powershell_blocked().execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert result[0].resource_id == "authorizationPolicy"
            assert result[0].resource_name == "Authorization Policy"
            assert "could not be determined" in result[0].status_extended

    def test_block_msol_powershell_true(self):
        """PASS when blockMsolPowerShell is true."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_policy_msol_powershell_blocked.entra_policy_msol_powershell_blocked.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_policy_msol_powershell_blocked.entra_policy_msol_powershell_blocked import (
                entra_policy_msol_powershell_blocked,
            )

            entra_client.authorization_policy = AuthorizationPolicy(
                id="authorizationPolicy",
                name="Authorization Policy",
                description="",
                default_user_role_permissions=DefaultUserRolePermissions(),
                block_msol_powershell=True,
            )

            result = entra_policy_msol_powershell_blocked().execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "authorizationPolicy"
            assert result[0].resource_name == "Authorization Policy"
            assert (
                result[0].status_extended
                == "Legacy MSOnline (MSOL) PowerShell is blocked in the tenant authorization policy."
            )

    def test_block_msol_powershell_false(self):
        """FAIL when blockMsolPowerShell is false."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_policy_msol_powershell_blocked.entra_policy_msol_powershell_blocked.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_policy_msol_powershell_blocked.entra_policy_msol_powershell_blocked import (
                entra_policy_msol_powershell_blocked,
            )

            entra_client.authorization_policy = AuthorizationPolicy(
                id="authorizationPolicy",
                name="Authorization Policy",
                description="",
                default_user_role_permissions=DefaultUserRolePermissions(),
                block_msol_powershell=False,
            )

            result = entra_policy_msol_powershell_blocked().execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "authorizationPolicy"
            assert result[0].resource_name == "Authorization Policy"
            assert (
                result[0].status_extended
                == "Legacy MSOnline (MSOL) PowerShell is not blocked in the tenant authorization policy."
            )
