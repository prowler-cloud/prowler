from unittest import mock

from prowler.providers.m365.services.entra.entra_service import PimAlert
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_entra_pim_only_management:
    def test_no_roles_assigned_outside_pim(self):
        """
        Test when the RolesAssignedOutsidePimAlert has zero affected items:
        The check should PASS because all roles are managed through PIM.
        """
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_pim_only_management.entra_pim_only_management.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_pim_only_management.entra_pim_only_management import (
                entra_pim_only_management,
            )

            entra_client.pim_alerts = [
                PimAlert(
                    id="alert-1",
                    alert_definition_id="DirectoryRole_00000000-0000-0000-0000-000000000000_RolesAssignedOutsidePimAlert",
                    number_of_affected_items=0,
                    is_active=False,
                ),
            ]
            entra_client.tenant_domain = DOMAIN

            check = entra_pim_only_management()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "managed through Privileged Identity Management"
                in result[0].status_extended
            )
            assert result[0].resource_id == "privilegedIdentityManagement"
            assert result[0].location == "global"
            assert result[0].resource_name == "PIM Alerts"

    def test_roles_assigned_outside_pim(self):
        """
        Test when the RolesAssignedOutsidePimAlert is active with affected items:
        The check should FAIL because there are role assignments outside PIM.
        """
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_pim_only_management.entra_pim_only_management.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_pim_only_management.entra_pim_only_management import (
                entra_pim_only_management,
            )

            entra_client.pim_alerts = [
                PimAlert(
                    id="alert-1",
                    alert_definition_id="DirectoryRole_00000000-0000-0000-0000-000000000000_RolesAssignedOutsidePimAlert",
                    number_of_affected_items=3,
                    is_active=True,
                ),
            ]
            entra_client.tenant_domain = DOMAIN

            check = entra_pim_only_management()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "3 privileged role assignment(s)" in result[0].status_extended
            assert "outside of PIM" in result[0].status_extended
            assert result[0].resource_id == "alert-1"
            assert result[0].location == "global"
            assert result[0].resource_name == "PIM Alerts"

    def test_no_pim_alerts(self):
        """
        Test when there are no PIM alerts at all:
        The check should PASS because no alert indicates no issue detected.
        """
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_pim_only_management.entra_pim_only_management.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_pim_only_management.entra_pim_only_management import (
                entra_pim_only_management,
            )

            entra_client.pim_alerts = []
            entra_client.tenant_domain = DOMAIN

            check = entra_pim_only_management()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "managed through Privileged Identity Management"
                in result[0].status_extended
            )

    def test_pim_alerts_none(self):
        """
        Test when pim_alerts is None (API error or PIM not configured):
        The check should return an empty list of findings.
        """
        entra_client = mock.MagicMock()
        entra_client.pim_alerts = None
        entra_client.tenant_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_pim_only_management.entra_pim_only_management.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_pim_only_management.entra_pim_only_management import (
                entra_pim_only_management,
            )

            check = entra_pim_only_management()
            result = check.execute()

            assert len(result) == 0
            assert result == []

    def test_other_pim_alerts_only(self):
        """
        Test when PIM alerts exist but none are RolesAssignedOutsidePimAlert:
        The check should PASS because the specific alert for out-of-PIM
        assignments is not present.
        """
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_pim_only_management.entra_pim_only_management.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_pim_only_management.entra_pim_only_management import (
                entra_pim_only_management,
            )

            entra_client.pim_alerts = [
                PimAlert(
                    id="alert-2",
                    alert_definition_id="DirectoryRole_00000000-0000-0000-0000-000000000000_TooManyGlobalAdminsAssignedToTenantAlert",
                    number_of_affected_items=5,
                    is_active=True,
                ),
                PimAlert(
                    id="alert-3",
                    alert_definition_id="DirectoryRole_00000000-0000-0000-0000-000000000000_StaleSignInAlert",
                    number_of_affected_items=2,
                    is_active=True,
                ),
            ]
            entra_client.tenant_domain = DOMAIN

            check = entra_pim_only_management()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "managed through Privileged Identity Management"
                in result[0].status_extended
            )

    def test_roles_assigned_outside_pim_inactive_alert(self):
        """
        Test when the RolesAssignedOutsidePimAlert exists but is inactive:
        The check should PASS because the alert is not active.
        """
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_pim_only_management.entra_pim_only_management.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_pim_only_management.entra_pim_only_management import (
                entra_pim_only_management,
            )

            entra_client.pim_alerts = [
                PimAlert(
                    id="alert-1",
                    alert_definition_id="DirectoryRole_00000000-0000-0000-0000-000000000000_RolesAssignedOutsidePimAlert",
                    number_of_affected_items=3,
                    is_active=False,
                ),
            ]
            entra_client.tenant_domain = DOMAIN

            check = entra_pim_only_management()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "managed through Privileged Identity Management"
                in result[0].status_extended
            )
