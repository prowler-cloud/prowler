from unittest import mock

from prowler.providers.m365.services.entra.entra_service import PIMAlert
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_entra_pim_role_usage_alert_exists:
    def test_no_pim_alerts(self):
        """Test when no PIM alerts exist - should FAIL since the alert is always evaluated."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_pim_role_usage_alert_exists.entra_pim_role_usage_alert_exists.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_pim_role_usage_alert_exists.entra_pim_role_usage_alert_exists import (
                entra_pim_role_usage_alert_exists,
            )

            entra_client.pim_alerts = []

            check = entra_pim_role_usage_alert_exists()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "PIM alert for unused privileged roles does not exist or is not active."
            )
            assert result[0].resource_name == "PIM Role Usage Alert"
            assert result[0].resource_id == "pimRoleUsageAlert"

    def test_entra_pim_role_usage_alert_exists_pass(self):
        """Test when the PIM alert for unused privileged roles exists and is active."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_pim_role_usage_alert_exists.entra_pim_role_usage_alert_exists.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_pim_role_usage_alert_exists.entra_pim_role_usage_alert_exists import (
                entra_pim_role_usage_alert_exists,
            )

            entra_client.pim_alerts = [
                PIMAlert(
                    id="alert-1",
                    alert_definition_id="DirectoryRoleInactiveAlertDefinition",
                    scope_id="tenant-id",
                    scope_type="DirectoryRole",
                    is_active=True,
                    number_of_affected_items=3,
                ),
            ]

            check = entra_pim_role_usage_alert_exists()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "PIM alert for unused privileged roles exists and is active."
            )
            assert result[0].resource_name == "PIM Role Usage Alert"
            assert result[0].resource_id == "pimRoleUsageAlert"

    def test_entra_pim_role_usage_alert_exists_fail_not_active(self):
        """Test when the PIM alert for unused privileged roles exists but is not active."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_pim_role_usage_alert_exists.entra_pim_role_usage_alert_exists.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_pim_role_usage_alert_exists.entra_pim_role_usage_alert_exists import (
                entra_pim_role_usage_alert_exists,
            )

            entra_client.pim_alerts = [
                PIMAlert(
                    id="alert-1",
                    alert_definition_id="DirectoryRoleInactiveAlertDefinition",
                    scope_id="tenant-id",
                    scope_type="DirectoryRole",
                    is_active=False,
                    number_of_affected_items=0,
                ),
            ]

            check = entra_pim_role_usage_alert_exists()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "PIM alert for unused privileged roles does not exist or is not active."
            )
            assert result[0].resource_name == "PIM Role Usage Alert"
            assert result[0].resource_id == "pimRoleUsageAlert"

    def test_entra_pim_role_usage_alert_exists_fail_different_alert(self):
        """Test when PIM alerts exist but none match the expected definition ID."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_pim_role_usage_alert_exists.entra_pim_role_usage_alert_exists.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_pim_role_usage_alert_exists.entra_pim_role_usage_alert_exists import (
                entra_pim_role_usage_alert_exists,
            )

            entra_client.pim_alerts = [
                PIMAlert(
                    id="alert-1",
                    alert_definition_id="SomeOtherAlertDefinition",
                    scope_id="tenant-id",
                    scope_type="DirectoryRole",
                    is_active=True,
                    number_of_affected_items=1,
                ),
            ]

            check = entra_pim_role_usage_alert_exists()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "PIM alert for unused privileged roles does not exist or is not active."
            )
            assert result[0].resource_name == "PIM Role Usage Alert"
            assert result[0].resource_id == "pimRoleUsageAlert"

    def test_entra_pim_role_usage_alert_exists_pass_among_multiple_alerts(self):
        """Test when multiple PIM alerts exist and the correct one is active."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_pim_role_usage_alert_exists.entra_pim_role_usage_alert_exists.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_pim_role_usage_alert_exists.entra_pim_role_usage_alert_exists import (
                entra_pim_role_usage_alert_exists,
            )

            entra_client.pim_alerts = [
                PIMAlert(
                    id="alert-1",
                    alert_definition_id="SomeOtherAlertDefinition",
                    scope_id="tenant-id",
                    scope_type="DirectoryRole",
                    is_active=True,
                    number_of_affected_items=1,
                ),
                PIMAlert(
                    id="alert-2",
                    alert_definition_id="DirectoryRoleInactiveAlertDefinition",
                    scope_id="tenant-id",
                    scope_type="DirectoryRole",
                    is_active=True,
                    number_of_affected_items=5,
                ),
            ]

            check = entra_pim_role_usage_alert_exists()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "PIM alert for unused privileged roles exists and is active."
            )
            assert result[0].resource_name == "PIM Role Usage Alert"
            assert result[0].resource_id == "pimRoleUsageAlert"
