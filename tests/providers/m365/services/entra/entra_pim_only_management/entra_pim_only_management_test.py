from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    Organization,
    PimAlert,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


CONTOSO_ORG = Organization(
    id="org-001",
    name="Contoso",
    on_premises_sync_enabled=False,
)


class Test_entra_pim_only_management:
    def test_no_roles_assigned_outside_pim(self):
        """PASS when the RolesAssignedOutsidePim alert has zero affected items."""
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

            entra_client.organizations = [CONTOSO_ORG]
            entra_client.pim_alerts = {
                "DirectoryRole_00000000-0000-0000-0000-000000000000_RolesAssignedOutsidePimAlert": PimAlert(
                    id="alert-1",
                    alert_definition_id="DirectoryRole_00000000-0000-0000-0000-000000000000_RolesAssignedOutsidePimAlert",
                    is_active=False,
                    number_of_affected_items=0,
                ),
            }
            entra_client.tenant_domain = DOMAIN

            check = entra_pim_only_management()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "managed through Privileged Identity Management"
                in result[0].status_extended
            )
            assert result[0].resource_id == "alert-1"
            assert result[0].resource_name == "PIM Roles Assigned Outside Of PIM Alert"

    def test_roles_assigned_outside_pim(self):
        """FAIL when the RolesAssignedOutsidePim alert is active with affected items."""
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

            entra_client.organizations = [CONTOSO_ORG]
            entra_client.pim_alerts = {
                "DirectoryRole_00000000-0000-0000-0000-000000000000_RolesAssignedOutsidePimAlert": PimAlert(
                    id="alert-1",
                    alert_definition_id="DirectoryRole_00000000-0000-0000-0000-000000000000_RolesAssignedOutsidePimAlert",
                    is_active=True,
                    number_of_affected_items=3,
                ),
            }
            entra_client.tenant_domain = DOMAIN

            check = entra_pim_only_management()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "3 privileged role assignment(s)" in result[0].status_extended
            assert "outside of PIM" in result[0].status_extended
            assert result[0].resource_id == "alert-1"

    def test_no_pim_alerts(self):
        """MANUAL when there are no PIM alerts (likely no P2 license)."""
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

            entra_client.organizations = [CONTOSO_ORG]
            entra_client.pim_alerts = {}
            entra_client.tenant_domain = DOMAIN

            check = entra_pim_only_management()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "not available" in result[0].status_extended
            assert "P2" in result[0].status_extended
            assert result[0].resource_id == "org-001"
            assert result[0].resource_name == "Contoso"

    def test_other_pim_alerts_only(self):
        """MANUAL when PIM alerts exist but none match the RolesAssignedOutsidePim definition."""
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

            entra_client.organizations = [CONTOSO_ORG]
            entra_client.pim_alerts = {
                "TooManyGlobalAdminsAssignedToTenantAlert": PimAlert(
                    id="alert-other",
                    alert_definition_id="TooManyGlobalAdminsAssignedToTenantAlert",
                    is_active=True,
                    number_of_affected_items=5,
                ),
            }
            entra_client.tenant_domain = DOMAIN

            check = entra_pim_only_management()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "not available" in result[0].status_extended

    def test_inactive_alert_with_lingering_affected_items(self):
        """PASS when the RolesAssignedOutsidePim alert reports counts but is not active."""
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

            entra_client.organizations = [CONTOSO_ORG]
            entra_client.pim_alerts = {
                "DirectoryRole_00000000-0000-0000-0000-000000000000_RolesAssignedOutsidePimAlert": PimAlert(
                    id="alert-1",
                    alert_definition_id="DirectoryRole_00000000-0000-0000-0000-000000000000_RolesAssignedOutsidePimAlert",
                    is_active=False,
                    number_of_affected_items=3,
                ),
            }
            entra_client.tenant_domain = DOMAIN

            check = entra_pim_only_management()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "managed through Privileged Identity Management"
                in result[0].status_extended
            )

    def test_no_organizations_returns_empty(self):
        """No findings when the provider returns no organizations."""
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

            entra_client.organizations = []
            entra_client.pim_alerts = {}
            entra_client.tenant_domain = DOMAIN

            check = entra_pim_only_management()
            result = check.execute()

            assert len(result) == 0
