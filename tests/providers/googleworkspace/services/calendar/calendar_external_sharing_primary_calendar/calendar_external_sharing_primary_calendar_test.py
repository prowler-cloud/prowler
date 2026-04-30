from unittest.mock import patch

from prowler.providers.googleworkspace.services.calendar.calendar_service import (
    CalendarPolicies,
)
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    DOMAIN,
    set_mocked_googleworkspace_provider,
)


class TestCalendarExternalSharingPrimaryCalendar:
    def test_pass_free_busy_only(self):
        """Test PASS when external sharing is restricted to free/busy only"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.calendar.calendar_external_sharing_primary_calendar.calendar_external_sharing_primary_calendar.calendar_client"
            ) as mock_calendar_client,
        ):
            from prowler.providers.googleworkspace.services.calendar.calendar_external_sharing_primary_calendar.calendar_external_sharing_primary_calendar import (
                calendar_external_sharing_primary_calendar,
            )

            mock_calendar_client.provider = mock_provider
            mock_calendar_client.policies_fetched = True
            mock_calendar_client.policies = CalendarPolicies(
                primary_calendar_external_sharing="EXTERNAL_FREE_BUSY_ONLY"
            )

            check = calendar_external_sharing_primary_calendar()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "free/busy information only" in findings[0].status_extended
            assert findings[0].resource_name == DOMAIN
            assert findings[0].resource_id == CUSTOMER_ID
            assert findings[0].customer_id == CUSTOMER_ID
            assert findings[0].resource == mock_provider.domain_resource.dict()

    def test_fail_read_only(self):
        """Test FAIL when external sharing allows read-only access"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.calendar.calendar_external_sharing_primary_calendar.calendar_external_sharing_primary_calendar.calendar_client"
            ) as mock_calendar_client,
        ):
            from prowler.providers.googleworkspace.services.calendar.calendar_external_sharing_primary_calendar.calendar_external_sharing_primary_calendar import (
                calendar_external_sharing_primary_calendar,
            )

            mock_calendar_client.provider = mock_provider
            mock_calendar_client.policies_fetched = True
            mock_calendar_client.policies = CalendarPolicies(
                primary_calendar_external_sharing="EXTERNAL_ALL_INFO_READ_ONLY"
            )

            check = calendar_external_sharing_primary_calendar()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "EXTERNAL_ALL_INFO_READ_ONLY" in findings[0].status_extended
            assert "free/busy information only" in findings[0].status_extended

    def test_fail_read_write(self):
        """Test FAIL when external sharing allows read-write access"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.calendar.calendar_external_sharing_primary_calendar.calendar_external_sharing_primary_calendar.calendar_client"
            ) as mock_calendar_client,
        ):
            from prowler.providers.googleworkspace.services.calendar.calendar_external_sharing_primary_calendar.calendar_external_sharing_primary_calendar import (
                calendar_external_sharing_primary_calendar,
            )

            mock_calendar_client.provider = mock_provider
            mock_calendar_client.policies_fetched = True
            mock_calendar_client.policies = CalendarPolicies(
                primary_calendar_external_sharing="EXTERNAL_ALL_INFO_READ_WRITE"
            )

            check = calendar_external_sharing_primary_calendar()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "EXTERNAL_ALL_INFO_READ_WRITE" in findings[0].status_extended

    def test_pass_using_default(self):
        """Test PASS when no explicit policy is set (None) — Google default is secure (free/busy only)"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.calendar.calendar_external_sharing_primary_calendar.calendar_external_sharing_primary_calendar.calendar_client"
            ) as mock_calendar_client,
        ):
            from prowler.providers.googleworkspace.services.calendar.calendar_external_sharing_primary_calendar.calendar_external_sharing_primary_calendar import (
                calendar_external_sharing_primary_calendar,
            )

            mock_calendar_client.provider = mock_provider
            mock_calendar_client.policies_fetched = True
            mock_calendar_client.policies = CalendarPolicies(
                primary_calendar_external_sharing=None
            )

            check = calendar_external_sharing_primary_calendar()
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
                "prowler.providers.googleworkspace.services.calendar.calendar_external_sharing_primary_calendar.calendar_external_sharing_primary_calendar.calendar_client"
            ) as mock_calendar_client,
        ):
            from prowler.providers.googleworkspace.services.calendar.calendar_external_sharing_primary_calendar.calendar_external_sharing_primary_calendar import (
                calendar_external_sharing_primary_calendar,
            )

            mock_calendar_client.provider = mock_provider
            mock_calendar_client.policies_fetched = False
            mock_calendar_client.policies = CalendarPolicies()

            check = calendar_external_sharing_primary_calendar()
            findings = check.execute()

            assert len(findings) == 0
