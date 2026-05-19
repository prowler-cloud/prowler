from unittest import mock

from tests.providers.okta.okta_fixtures import OKTA_ORG_DOMAIN, set_mocked_okta_provider

CHECK_PATH = (
    "prowler.providers.okta.services.signon."
    "signon_dod_warning_banner_configured."
    "signon_dod_warning_banner_configured.signon_client"
)


def _build_signon_client(audit_config: dict = None):
    """Build a mock signon_client."""
    client = mock.MagicMock()
    client.global_session_policies = {}
    client.provider = set_mocked_okta_provider()
    client.audit_config = audit_config or {}
    return client


class Test_signon_dod_warning_banner_configured:
    """Tests for the signon_dod_warning_banner_configured check.

    This check always returns MANUAL because the DOD warning banner
    configuration cannot be fully verified via the Okta API.
    """

    def test_returns_manual_status(self):
        """MANUAL is always returned since banner cannot be fully verified via API."""
        signon_client = _build_signon_client()
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_okta_provider(),
            ),
            mock.patch(CHECK_PATH, new=signon_client),
        ):
            from prowler.providers.okta.services.signon.signon_dod_warning_banner_configured.signon_dod_warning_banner_configured import (
                signon_dod_warning_banner_configured,
            )

            findings = signon_dod_warning_banner_configured().execute()
            assert len(findings) == 1
            assert findings[0].status == "MANUAL"
            assert "DOD Notice and Consent Banner" in findings[0].status_extended
            assert "DTM-08-060" in findings[0].status_extended

    def test_resource_id_is_org_domain(self):
        """The resource ID and name should be the org domain."""
        signon_client = _build_signon_client()
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_okta_provider(),
            ),
            mock.patch(CHECK_PATH, new=signon_client),
        ):
            from prowler.providers.okta.services.signon.signon_dod_warning_banner_configured.signon_dod_warning_banner_configured import (
                signon_dod_warning_banner_configured,
            )

            findings = signon_dod_warning_banner_configured().execute()
            assert len(findings) == 1
            assert findings[0].resource_id == OKTA_ORG_DOMAIN
            assert findings[0].resource_name == OKTA_ORG_DOMAIN

    def test_single_finding_returned(self):
        """Only one finding should be returned per execution."""
        signon_client = _build_signon_client()
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_okta_provider(),
            ),
            mock.patch(CHECK_PATH, new=signon_client),
        ):
            from prowler.providers.okta.services.signon.signon_dod_warning_banner_configured.signon_dod_warning_banner_configured import (
                signon_dod_warning_banner_configured,
            )

            findings = signon_dod_warning_banner_configured().execute()
            assert len(findings) == 1
            assert "cannot be fully verified" in findings[0].status_extended

    def test_status_extended_mentions_org_domain(self):
        """The status_extended message should reference the org domain."""
        signon_client = _build_signon_client()
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_okta_provider(),
            ),
            mock.patch(CHECK_PATH, new=signon_client),
        ):
            from prowler.providers.okta.services.signon.signon_dod_warning_banner_configured.signon_dod_warning_banner_configured import (
                signon_dod_warning_banner_configured,
            )

            findings = signon_dod_warning_banner_configured().execute()
            assert len(findings) == 1
            assert OKTA_ORG_DOMAIN in findings[0].status_extended

    def test_status_extended_full_message(self):
        """Verify the exact status_extended message content."""
        signon_client = _build_signon_client()
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_okta_provider(),
            ),
            mock.patch(CHECK_PATH, new=signon_client),
        ):
            from prowler.providers.okta.services.signon.signon_dod_warning_banner_configured.signon_dod_warning_banner_configured import (
                signon_dod_warning_banner_configured,
            )

            findings = signon_dod_warning_banner_configured().execute()
            assert len(findings) == 1
            expected_message = (
                f"Okta organization '{OKTA_ORG_DOMAIN}' sign-in page customization "
                "cannot be fully verified via the API. Manually confirm that the "
                "Standard Mandatory DOD Notice and Consent Banner (DTM-08-060) "
                "is displayed before the login prompt."
            )
            assert findings[0].status_extended == expected_message

    def test_manual_status_regardless_of_policies(self):
        """MANUAL status is returned even when policies exist (check is API-limited)."""
        signon_client = _build_signon_client()
        # Simulate having policies — should not affect the MANUAL outcome.
        signon_client.global_session_policies = {"pol-1": mock.MagicMock()}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_okta_provider(),
            ),
            mock.patch(CHECK_PATH, new=signon_client),
        ):
            from prowler.providers.okta.services.signon.signon_dod_warning_banner_configured.signon_dod_warning_banner_configured import (
                signon_dod_warning_banner_configured,
            )

            findings = signon_dod_warning_banner_configured().execute()
            assert len(findings) == 1
            assert findings[0].status == "MANUAL"
