from unittest.mock import PropertyMock, patch

from prowler.providers.googleworkspace.services.security.security_service import (
    SecurityPolicies,
)
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    set_mocked_googleworkspace_provider,
)


class TestSecuritySessionDurationLimited:
    def test_pass_session_12_hours(self):
        """Test PASS when session duration is set to 12 hours"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_session_duration_limited.security_session_duration_limited.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_session_duration_limited.security_session_duration_limited import (
                security_session_duration_limited,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(web_session_duration="43200s")

            check = security_session_duration_limited()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "12 hours" in findings[0].status_extended
            assert findings[0].resource_name == "Security Policies"
            assert findings[0].resource_id == "securityPolicies"
            assert findings[0].customer_id == CUSTOMER_ID

    def test_pass_does_not_read_the_editions(self):
        """A passing tenant must not trigger the Licensing API lookup"""
        mock_provider = set_mocked_googleworkspace_provider()
        type(mock_provider).editions = PropertyMock(
            side_effect=AssertionError("editions read on a passing finding")
        )

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_session_duration_limited.security_session_duration_limited.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_session_duration_limited.security_session_duration_limited import (
                security_session_duration_limited,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(web_session_duration="43200s")

            findings = security_session_duration_limited().execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"

    def test_fail_long_session_duration(self):
        """Test FAIL when session duration is too long (336 hours)"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_session_duration_limited.security_session_duration_limited.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_session_duration_limited.security_session_duration_limited import (
                security_session_duration_limited,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(web_session_duration="1209600s")

            check = security_session_duration_limited()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "336 hours" in findings[0].status_extended

    def test_fail_none_not_configured(self):
        """Test FAIL when session duration is not explicitly configured (None)"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_session_duration_limited.security_session_duration_limited.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_session_duration_limited.security_session_duration_limited import (
                security_session_duration_limited,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(web_session_duration=None)

            check = security_session_duration_limited()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "not explicitly configured" in findings[0].status_extended

    def test_fail_on_an_edition_without_session_control_says_so(self):
        """Google sells session control from Business Plus up; the default-duration finding names the edition"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.editions = ["Business Starter"]

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_session_duration_limited.security_session_duration_limited.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_session_duration_limited.security_session_duration_limited import (
                security_session_duration_limited,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(web_session_duration=None)

            findings = security_session_duration_limited().execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert findings[0].status_extended.endswith(
                "Web session duration should be 12 hours or less. This may be "
                "expected because Google session control is not available on the "
                "Google Workspace Business Starter edition."
            )

    def test_fail_long_session_on_an_edition_without_session_control_says_so(self):
        """The explicit-duration finding carries the same edition explanation"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.editions = ["Business Standard"]

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_session_duration_limited.security_session_duration_limited.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_session_duration_limited.security_session_duration_limited import (
                security_session_duration_limited,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(web_session_duration="1209600s")

            findings = security_session_duration_limited().execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "336 hours" in findings[0].status_extended
            assert findings[0].status_extended.endswith(
                "This may be expected because Google session control is not "
                "available on the Google Workspace Business Standard edition."
            )

    def test_fail_with_cloud_identity_premium_gives_no_excuse(self):
        """Cloud Identity Premium brings session control to any Workspace edition"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.editions = ["Business Starter", "Cloud Identity Premium"]

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_session_duration_limited.security_session_duration_limited.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_session_duration_limited.security_session_duration_limited import (
                security_session_duration_limited,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(web_session_duration=None)

            findings = security_session_duration_limited().execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "This may be expected" not in findings[0].status_extended

    def test_fail_unparseable_duration(self):
        """Test FAIL when session duration has an unexpected format instead of crashing"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_session_duration_limited.security_session_duration_limited.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_session_duration_limited.security_session_duration_limited import (
                security_session_duration_limited,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(web_session_duration="invalid")

            check = security_session_duration_limited()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "not parseable" in findings[0].status_extended

    def test_no_findings_when_fetch_failed(self):
        """Test no findings returned when the API fetch failed"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_session_duration_limited.security_session_duration_limited.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_session_duration_limited.security_session_duration_limited import (
                security_session_duration_limited,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = False
            mock_client.policies = SecurityPolicies()

            check = security_session_duration_limited()
            findings = check.execute()

            assert len(findings) == 0
