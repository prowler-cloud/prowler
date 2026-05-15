from unittest.mock import patch

from prowler.providers.googleworkspace.services.groups.groups_service import (
    GroupsPolicies,
)
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    set_mocked_googleworkspace_provider,
)


class TestGroupsExternalAccessRestricted:
    def test_pass_domain_users_only(self):
        """Test PASS when external access is set to DOMAIN_USERS_ONLY"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.groups.groups_external_access_restricted.groups_external_access_restricted.groups_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.groups.groups_external_access_restricted.groups_external_access_restricted import (
                groups_external_access_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GroupsPolicies(
                collaboration_capability="DOMAIN_USERS_ONLY"
            )

            check = groups_external_access_restricted()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "private" in findings[0].status_extended
            assert findings[0].resource_name == "Groups Policies"
            assert findings[0].resource_id == "groupsPolicies"
            assert findings[0].customer_id == CUSTOMER_ID
            assert (
                findings[0].resource
                == GroupsPolicies(collaboration_capability="DOMAIN_USERS_ONLY").dict()
            )

    def test_fail_anyone_can_access(self):
        """Test FAIL when external access is set to ANYONE_CAN_ACCESS"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.groups.groups_external_access_restricted.groups_external_access_restricted.groups_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.groups.groups_external_access_restricted.groups_external_access_restricted import (
                groups_external_access_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GroupsPolicies(
                collaboration_capability="ANYONE_CAN_ACCESS"
            )

            check = groups_external_access_restricted()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "ANYONE_CAN_ACCESS" in findings[0].status_extended

    def test_pass_no_policy_set(self):
        """Test PASS when no explicit policy is set (None) - Google default is DOMAIN_USERS_ONLY (secure)"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.groups.groups_external_access_restricted.groups_external_access_restricted.groups_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.groups.groups_external_access_restricted.groups_external_access_restricted import (
                groups_external_access_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GroupsPolicies(collaboration_capability=None)

            check = groups_external_access_restricted()
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
                "prowler.providers.googleworkspace.services.groups.groups_external_access_restricted.groups_external_access_restricted.groups_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.groups.groups_external_access_restricted.groups_external_access_restricted import (
                groups_external_access_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = False
            mock_client.policies = GroupsPolicies()

            check = groups_external_access_restricted()
            findings = check.execute()

            assert len(findings) == 0
