from unittest.mock import patch

from prowler.providers.googleworkspace.services.groups.groups_service import (
    GroupsPolicies,
)
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    set_mocked_googleworkspace_provider,
)


class TestGroupsViewConversationsRestricted:
    def test_pass_group_members(self):
        """Test PASS when view conversations is set to GROUP_MEMBERS"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.groups.groups_view_conversations_restricted.groups_view_conversations_restricted.groups_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.groups.groups_view_conversations_restricted.groups_view_conversations_restricted import (
                groups_view_conversations_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GroupsPolicies(
                view_topics_default_access_level="GROUP_MEMBERS"
            )

            check = groups_view_conversations_restricted()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "group members" in findings[0].status_extended
            assert findings[0].resource_name == "Groups Policies"
            assert findings[0].resource_id == "groupsPolicies"
            assert findings[0].customer_id == CUSTOMER_ID
            assert (
                findings[0].resource
                == GroupsPolicies(
                    view_topics_default_access_level="GROUP_MEMBERS"
                ).dict()
            )

    def test_fail_domain_users(self):
        """Test FAIL when view conversations is set to DOMAIN_USERS"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.groups.groups_view_conversations_restricted.groups_view_conversations_restricted.groups_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.groups.groups_view_conversations_restricted.groups_view_conversations_restricted import (
                groups_view_conversations_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GroupsPolicies(
                view_topics_default_access_level="DOMAIN_USERS"
            )

            check = groups_view_conversations_restricted()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "DOMAIN_USERS" in findings[0].status_extended

    def test_fail_anyone_can_view(self):
        """Test FAIL when view conversations is set to ANYONE_CAN_VIEW_TOPICS"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.groups.groups_view_conversations_restricted.groups_view_conversations_restricted.groups_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.groups.groups_view_conversations_restricted.groups_view_conversations_restricted import (
                groups_view_conversations_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GroupsPolicies(
                view_topics_default_access_level="ANYONE_CAN_VIEW_TOPICS"
            )

            check = groups_view_conversations_restricted()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "ANYONE_CAN_VIEW_TOPICS" in findings[0].status_extended

    def test_fail_no_policy_set(self):
        """Test FAIL when no explicit policy is set (None) - Google default is DOMAIN_USERS (insecure)"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.groups.groups_view_conversations_restricted.groups_view_conversations_restricted.groups_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.groups.groups_view_conversations_restricted.groups_view_conversations_restricted import (
                groups_view_conversations_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GroupsPolicies(view_topics_default_access_level=None)

            check = groups_view_conversations_restricted()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "default" in findings[0].status_extended
            assert "all organization users" in findings[0].status_extended

    def test_no_findings_when_fetch_failed(self):
        """Test no findings returned when the API fetch failed"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.groups.groups_view_conversations_restricted.groups_view_conversations_restricted.groups_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.groups.groups_view_conversations_restricted.groups_view_conversations_restricted import (
                groups_view_conversations_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = False
            mock_client.policies = GroupsPolicies()

            check = groups_view_conversations_restricted()
            findings = check.execute()

            assert len(findings) == 0
