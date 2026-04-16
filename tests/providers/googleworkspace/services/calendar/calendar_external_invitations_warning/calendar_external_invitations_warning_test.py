from unittest.mock import patch

from prowler.providers.googleworkspace.services.calendar.calendar_service import (
    CalendarPolicies,
)
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    DOMAIN,
    set_mocked_googleworkspace_provider,
)


class TestCalendarExternalInvitationsWarning:
    def test_pass_warnings_enabled(self):
        """Test PASS when external invitation warnings are enabled"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.calendar.calendar_external_invitations_warning.calendar_external_invitations_warning.calendar_client"
            ) as mock_calendar_client,
        ):
            from prowler.providers.googleworkspace.services.calendar.calendar_external_invitations_warning.calendar_external_invitations_warning import (
                calendar_external_invitations_warning,
            )

            mock_calendar_client.provider = mock_provider
            mock_calendar_client.policies_fetched = True
            mock_calendar_client.policies = CalendarPolicies(
                external_invitations_warning=True
            )

            check = calendar_external_invitations_warning()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "enabled" in findings[0].status_extended
            assert findings[0].resource_name == DOMAIN
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_warnings_disabled(self):
        """Test FAIL when external invitation warnings are disabled"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.calendar.calendar_external_invitations_warning.calendar_external_invitations_warning.calendar_client"
            ) as mock_calendar_client,
        ):
            from prowler.providers.googleworkspace.services.calendar.calendar_external_invitations_warning.calendar_external_invitations_warning import (
                calendar_external_invitations_warning,
            )

            mock_calendar_client.provider = mock_provider
            mock_calendar_client.policies_fetched = True
            mock_calendar_client.policies = CalendarPolicies(
                external_invitations_warning=False
            )

            check = calendar_external_invitations_warning()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "disabled" in findings[0].status_extended

    def test_pass_using_default(self):
        """Test PASS when no explicit policy is set (None) — Google default is secure (enabled)"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.calendar.calendar_external_invitations_warning.calendar_external_invitations_warning.calendar_client"
            ) as mock_calendar_client,
        ):
            from prowler.providers.googleworkspace.services.calendar.calendar_external_invitations_warning.calendar_external_invitations_warning import (
                calendar_external_invitations_warning,
            )

            mock_calendar_client.provider = mock_provider
            mock_calendar_client.policies_fetched = True
            mock_calendar_client.policies = CalendarPolicies(
                external_invitations_warning=None
            )

            check = calendar_external_invitations_warning()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "secure default" in findings[0].status_extended

    def test_no_findings_when_fetch_failed(self):
        """Test no findings returned when the API fetch failed"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.calendar.calendar_external_invitations_warning.calendar_external_invitations_warning.calendar_client"
            ) as mock_calendar_client,
        ):
            from prowler.providers.googleworkspace.services.calendar.calendar_external_invitations_warning.calendar_external_invitations_warning import (
                calendar_external_invitations_warning,
            )

            mock_calendar_client.provider = mock_provider
            mock_calendar_client.policies_fetched = False
            mock_calendar_client.policies = CalendarPolicies()

            check = calendar_external_invitations_warning()
            findings = check.execute()

            assert len(findings) == 0
