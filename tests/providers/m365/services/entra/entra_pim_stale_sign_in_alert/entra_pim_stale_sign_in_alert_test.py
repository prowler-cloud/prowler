from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    Organization,
    PimAlert,
    PimAlertIncident,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider


class Test_entra_pim_stale_sign_in_alert:
    def test_no_stale_accounts(self):
        """PASS: PIM stale sign-in alert exists with no affected items."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_pim_stale_sign_in_alert.entra_pim_stale_sign_in_alert.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_pim_stale_sign_in_alert.entra_pim_stale_sign_in_alert import (
                entra_pim_stale_sign_in_alert,
            )

            entra_client.pim_alerts = {
                "DirectoryRole_StaleSignInAlert": PimAlert(
                    id="alert-001",
                    alert_definition_id="DirectoryRole_StaleSignInAlert",
                    scope_id="/",
                    scope_type="DirectoryRole",
                    is_active=True,
                    number_of_affected_items=0,
                    incident_count=0,
                    affected_items=[],
                )
            }

            check = entra_pim_stale_sign_in_alert()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "PIM stale sign-in alert reports no stale accounts in privileged roles."
            )
            assert result[0].resource_id == "alert-001"
            assert result[0].resource_name == "PIM Stale Sign-In Alert"
            assert result[0].location == "global"

    def test_stale_accounts_detected(self):
        """FAIL: PIM stale sign-in alert has affected items."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_pim_stale_sign_in_alert.entra_pim_stale_sign_in_alert.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_pim_stale_sign_in_alert.entra_pim_stale_sign_in_alert import (
                entra_pim_stale_sign_in_alert,
            )

            entra_client.pim_alerts = {
                "DirectoryRole_StaleSignInAlert": PimAlert(
                    id="alert-001",
                    alert_definition_id="DirectoryRole_StaleSignInAlert",
                    scope_id="/",
                    scope_type="DirectoryRole",
                    is_active=True,
                    number_of_affected_items=2,
                    incident_count=2,
                    affected_items=[
                        PimAlertIncident(
                            assignee_display_name="John Doe",
                            assignee_id="user-001",
                            role_display_name="Global Administrator",
                            last_sign_in_date_time="2025-01-01T00:00:00Z",
                        ),
                        PimAlertIncident(
                            assignee_display_name="Jane Smith",
                            assignee_id="user-002",
                            role_display_name="Security Administrator",
                            last_sign_in_date_time="2025-02-01T00:00:00Z",
                        ),
                    ],
                )
            }

            check = entra_pim_stale_sign_in_alert()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "2 stale account(s)" in result[0].status_extended
            assert "John Doe" in result[0].status_extended
            assert "Jane Smith" in result[0].status_extended
            assert result[0].resource_id == "alert-001"
            assert result[0].resource_name == "PIM Stale Sign-In Alert"
            assert result[0].location == "global"

    def test_stale_accounts_more_than_five(self):
        """FAIL: PIM stale sign-in alert with more than 5 affected items truncates display."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_pim_stale_sign_in_alert.entra_pim_stale_sign_in_alert.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_pim_stale_sign_in_alert.entra_pim_stale_sign_in_alert import (
                entra_pim_stale_sign_in_alert,
            )

            affected_items = [
                PimAlertIncident(
                    assignee_display_name=f"User {i}",
                    assignee_id=f"user-{i:03d}",
                    role_display_name="Global Administrator",
                    last_sign_in_date_time="2025-01-01T00:00:00Z",
                )
                for i in range(7)
            ]

            entra_client.pim_alerts = {
                "DirectoryRole_StaleSignInAlert": PimAlert(
                    id="alert-001",
                    alert_definition_id="DirectoryRole_StaleSignInAlert",
                    scope_id="/",
                    scope_type="DirectoryRole",
                    is_active=True,
                    number_of_affected_items=7,
                    incident_count=7,
                    affected_items=affected_items,
                )
            }

            check = entra_pim_stale_sign_in_alert()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "7 stale account(s)" in result[0].status_extended
            assert "and 2 more" in result[0].status_extended
            assert result[0].resource_id == "alert-001"

    def test_alert_not_configured(self):
        """FAIL: PIM stale sign-in alert is not configured."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_pim_stale_sign_in_alert.entra_pim_stale_sign_in_alert.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_pim_stale_sign_in_alert.entra_pim_stale_sign_in_alert import (
                entra_pim_stale_sign_in_alert,
            )

            entra_client.pim_alerts = {}
            entra_client.organizations = [
                Organization(
                    id="org-001",
                    name="Contoso",
                    on_premises_sync_enabled=False,
                )
            ]

            check = entra_pim_stale_sign_in_alert()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "not configured or not available" in result[0].status_extended
            assert result[0].resource_id == "org-001"
            assert result[0].resource_name == "Contoso"
            assert result[0].location == "global"

    def test_empty_pim_alerts_no_organizations(self):
        """No findings when PIM alerts empty and no organizations."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_pim_stale_sign_in_alert.entra_pim_stale_sign_in_alert.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_pim_stale_sign_in_alert.entra_pim_stale_sign_in_alert import (
                entra_pim_stale_sign_in_alert,
            )

            entra_client.pim_alerts = {}
            entra_client.organizations = []

            check = entra_pim_stale_sign_in_alert()
            result = check.execute()

            assert len(result) == 0
