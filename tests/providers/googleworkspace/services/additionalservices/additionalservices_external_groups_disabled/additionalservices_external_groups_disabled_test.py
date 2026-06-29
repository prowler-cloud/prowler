from unittest.mock import patch

from prowler.providers.googleworkspace.services.additionalservices.additionalservices_service import (
    AdditionalServicesPolicies,
)
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    set_mocked_googleworkspace_provider,
)


class TestAdditionalServicesExternalGroupsDisabled:
    def test_pass_groups_disabled(self):
        """Test PASS when external Google Groups access is disabled"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.additionalservices.additionalservices_external_groups_disabled.additionalservices_external_groups_disabled.additionalservices_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.additionalservices.additionalservices_external_groups_disabled.additionalservices_external_groups_disabled import (
                additionalservices_external_groups_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = AdditionalServicesPolicies(
                groups_service_state="DISABLED"
            )

            check = additionalservices_external_groups_disabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "disabled" in findings[0].status_extended
            assert findings[0].resource_name == "Additional Services Policies"
            assert findings[0].resource_id == "additionalServicesPolicies"
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_groups_enabled(self):
        """Test FAIL when external Google Groups access is enabled"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.additionalservices.additionalservices_external_groups_disabled.additionalservices_external_groups_disabled.additionalservices_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.additionalservices.additionalservices_external_groups_disabled.additionalservices_external_groups_disabled import (
                additionalservices_external_groups_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = AdditionalServicesPolicies(
                groups_service_state="ENABLED"
            )

            check = additionalservices_external_groups_disabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "enabled" in findings[0].status_extended

    def test_fail_no_policy_set(self):
        """Test FAIL when no explicit policy is set (None) - Google default is ON (insecure)"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.additionalservices.additionalservices_external_groups_disabled.additionalservices_external_groups_disabled.additionalservices_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.additionalservices.additionalservices_external_groups_disabled.additionalservices_external_groups_disabled import (
                additionalservices_external_groups_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = AdditionalServicesPolicies(groups_service_state=None)

            check = additionalservices_external_groups_disabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "not explicitly configured" in findings[0].status_extended

    def test_no_findings_when_fetch_failed(self):
        """Test no findings returned when the API fetch failed"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.additionalservices.additionalservices_external_groups_disabled.additionalservices_external_groups_disabled.additionalservices_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.additionalservices.additionalservices_external_groups_disabled.additionalservices_external_groups_disabled import (
                additionalservices_external_groups_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = False
            mock_client.policies = AdditionalServicesPolicies()

            check = additionalservices_external_groups_disabled()
            findings = check.execute()

            assert len(findings) == 0
