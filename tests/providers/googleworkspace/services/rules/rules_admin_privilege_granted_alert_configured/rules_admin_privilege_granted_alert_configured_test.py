from unittest.mock import patch

from prowler.providers.googleworkspace.services.rules.rules_service import (
    SystemDefinedAlert,
)
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    set_mocked_googleworkspace_provider,
)

RULE_NAME = "User granted Admin privilege"


class TestRulesAdminPrivilegeGrantedAlertConfigured:
    def test_pass_fully_configured(self):
        """Test PASS when alert is ON, email notifications ON, recipients = all super admins."""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.rules.rules_admin_privilege_granted_alert_configured.rules_admin_privilege_granted_alert_configured.rules_client"
            ) as mock_rules_client,
        ):
            from prowler.providers.googleworkspace.services.rules.rules_admin_privilege_granted_alert_configured.rules_admin_privilege_granted_alert_configured import (
                rules_admin_privilege_granted_alert_configured,
            )

            mock_rules_client.provider = mock_provider
            mock_rules_client.policies_fetched = True
            mock_rules_client.system_defined_alerts = [
                SystemDefinedAlert(
                    display_name=RULE_NAME,
                    state="ACTIVE",
                    severity="MEDIUM",
                    email_notifications_enabled=True,
                    all_super_admins=True,
                )
            ]

            check = rules_admin_privilege_granted_alert_configured()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "properly configured" in findings[0].status_extended
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_alert_off(self):
        """Test FAIL when alert is OFF (INACTIVE state)."""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.rules.rules_admin_privilege_granted_alert_configured.rules_admin_privilege_granted_alert_configured.rules_client"
            ) as mock_rules_client,
        ):
            from prowler.providers.googleworkspace.services.rules.rules_admin_privilege_granted_alert_configured.rules_admin_privilege_granted_alert_configured import (
                rules_admin_privilege_granted_alert_configured,
            )

            mock_rules_client.provider = mock_provider
            mock_rules_client.policies_fetched = True
            mock_rules_client.system_defined_alerts = [
                SystemDefinedAlert(
                    display_name=RULE_NAME,
                    state="INACTIVE",
                )
            ]

            check = rules_admin_privilege_granted_alert_configured()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "alert is OFF" in findings[0].status_extended

    def test_fail_no_email_notifications(self):
        """Test FAIL when alert is ON but email notifications are disabled."""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.rules.rules_admin_privilege_granted_alert_configured.rules_admin_privilege_granted_alert_configured.rules_client"
            ) as mock_rules_client,
        ):
            from prowler.providers.googleworkspace.services.rules.rules_admin_privilege_granted_alert_configured.rules_admin_privilege_granted_alert_configured import (
                rules_admin_privilege_granted_alert_configured,
            )

            mock_rules_client.provider = mock_provider
            mock_rules_client.policies_fetched = True
            mock_rules_client.system_defined_alerts = [
                SystemDefinedAlert(
                    display_name=RULE_NAME,
                    state="ACTIVE",
                    severity="MEDIUM",
                    email_notifications_enabled=False,
                    all_super_admins=False,
                )
            ]

            check = rules_admin_privilege_granted_alert_configured()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "email notifications are disabled" in findings[0].status_extended

    def test_fail_recipients_not_all_super_admins(self):
        """Test FAIL when email notifications ON but recipients do not include all super admins."""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.rules.rules_admin_privilege_granted_alert_configured.rules_admin_privilege_granted_alert_configured.rules_client"
            ) as mock_rules_client,
        ):
            from prowler.providers.googleworkspace.services.rules.rules_admin_privilege_granted_alert_configured.rules_admin_privilege_granted_alert_configured import (
                rules_admin_privilege_granted_alert_configured,
            )

            mock_rules_client.provider = mock_provider
            mock_rules_client.policies_fetched = True
            mock_rules_client.system_defined_alerts = [
                SystemDefinedAlert(
                    display_name=RULE_NAME,
                    state="ACTIVE",
                    severity="MEDIUM",
                    email_notifications_enabled=True,
                    all_super_admins=False,
                )
            ]

            check = rules_admin_privilege_granted_alert_configured()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert (
                "do not include all super administrators" in findings[0].status_extended
            )

    def test_no_findings_when_fetch_failed(self):
        """Test no findings returned when the API fetch failed."""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.rules.rules_admin_privilege_granted_alert_configured.rules_admin_privilege_granted_alert_configured.rules_client"
            ) as mock_rules_client,
        ):
            from prowler.providers.googleworkspace.services.rules.rules_admin_privilege_granted_alert_configured.rules_admin_privilege_granted_alert_configured import (
                rules_admin_privilege_granted_alert_configured,
            )

            mock_rules_client.provider = mock_provider
            mock_rules_client.policies_fetched = False
            mock_rules_client.system_defined_alerts = []

            check = rules_admin_privilege_granted_alert_configured()
            findings = check.execute()

            assert len(findings) == 0
