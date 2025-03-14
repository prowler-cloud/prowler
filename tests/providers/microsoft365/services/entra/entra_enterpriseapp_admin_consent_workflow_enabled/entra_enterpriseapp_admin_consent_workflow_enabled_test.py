from unittest import mock

from prowler.providers.microsoft365.services.entra.entra_service import (
    AdminConsentPolicy,
)
from tests.providers.microsoft365.microsoft365_fixtures import (
    DOMAIN,
    set_mocked_microsoft365_provider,
)


class Test_entra_enterpriseapp_admin_consent_workflow_enabled:
    def test_admin_consent_enabled(self):
        """
        Test when admin_consent_enabled is True:
        The check should PASS because the admin consent workflow is enabled.
        """
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_enterpriseapp_admin_consent_workflow_enabled.entra_enterpriseapp_admin_consent_workflow_enabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_enterpriseapp_admin_consent_workflow_enabled.entra_enterpriseapp_admin_consent_workflow_enabled import (
                entra_enterpriseapp_admin_consent_workflow_enabled,
            )

            entra_client.admin_consent_policy = AdminConsentPolicy(
                admin_consent_enabled=True,
                notify_reviewers=True,
                email_reminders_to_reviewers=False,
                duration_in_days=30,
            )
            entra_client.tenant_domain = DOMAIN

            check = entra_enterpriseapp_admin_consent_workflow_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "The admin consent workflow is enabled in Microsoft Entra, allowing users to request admin approval for applications. Reviewers will be notified."
            )
            assert result[0].resource_id == DOMAIN
            assert result[0].location == "global"
            assert result[0].resource_name == "Admin Consent Policy"
            assert result[0].resource == entra_client.admin_consent_policy.dict()

    def test_admin_consent_enabled_without_notifications(self):
        """
        Test when admin_consent_enabled is True:
        The check should PASS because the admin consent workflow is enabled.
        """
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_enterpriseapp_admin_consent_workflow_enabled.entra_enterpriseapp_admin_consent_workflow_enabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_enterpriseapp_admin_consent_workflow_enabled.entra_enterpriseapp_admin_consent_workflow_enabled import (
                entra_enterpriseapp_admin_consent_workflow_enabled,
            )

            entra_client.admin_consent_policy = AdminConsentPolicy(
                admin_consent_enabled=True,
                notify_reviewers=False,
                email_reminders_to_reviewers=False,
                duration_in_days=30,
            )
            entra_client.tenant_domain = DOMAIN

            check = entra_enterpriseapp_admin_consent_workflow_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "The admin consent workflow is enabled in Microsoft Entra, allowing users to request admin approval for applications. Reviewers will not be notified, we recommend notifying them."
            )
            assert result[0].resource_id == DOMAIN
            assert result[0].location == "global"
            assert result[0].resource_name == "Admin Consent Policy"
            assert result[0].resource == entra_client.admin_consent_policy.dict()

    def test_admin_consent_disabled(self):
        """
        Test when admin_consent_enabled is False:
        The check should FAIL because the admin consent workflow is not enabled.
        """
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_enterpriseapp_admin_consent_workflow_enabled.entra_enterpriseapp_admin_consent_workflow_enabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_enterpriseapp_admin_consent_workflow_enabled.entra_enterpriseapp_admin_consent_workflow_enabled import (
                entra_enterpriseapp_admin_consent_workflow_enabled,
            )

            entra_client.admin_consent_policy = AdminConsentPolicy(
                admin_consent_enabled=False,
                notify_reviewers=True,
                email_reminders_to_reviewers=False,
                duration_in_days=30,
            )
            entra_client.tenant_domain = DOMAIN

            check = entra_enterpriseapp_admin_consent_workflow_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "The admin consent workflow is not enabled in Microsoft Entra; users may be blocked from accessing applications that require admin consent."
            )
            assert result[0].resource_id == DOMAIN
            assert result[0].location == "global"
            assert result[0].resource_name == "Admin Consent Policy"
            assert result[0].resource == entra_client.admin_consent_policy.dict()

    def test_no_policy(self):
        """
        Test when entra_client.admin_consent_policy is None:
        The check should return an empty list of findings.
        """
        entra_client = mock.MagicMock()
        entra_client.admin_consent_policy = None
        entra_client.tenant_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_enterpriseapp_admin_consent_workflow_enabled.entra_enterpriseapp_admin_consent_workflow_enabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_enterpriseapp_admin_consent_workflow_enabled.entra_enterpriseapp_admin_consent_workflow_enabled import (
                entra_enterpriseapp_admin_consent_workflow_enabled,
            )

            check = entra_enterpriseapp_admin_consent_workflow_enabled()
            result = check.execute()

            assert len(result) == 0
            assert result == []
