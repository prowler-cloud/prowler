from unittest.mock import patch

from prowler.providers.googleworkspace.services.groups.groups_service import (
    GroupsForBusinessPolicies,
)
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    set_mocked_googleworkspace_provider,
)


class TestGroupsCreationRestricted:
    def test_pass_all_restricted(self):
        """Test PASS when all creation settings are secure"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.groups.groups_creation_restricted.groups_creation_restricted.groups_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.groups.groups_creation_restricted.groups_creation_restricted import (
                groups_creation_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GroupsForBusinessPolicies(
                create_groups_access_level="ADMIN_ONLY",
                owners_can_allow_external_members=False,
                owners_can_allow_incoming_mail_from_public=False,
            )

            check = groups_creation_restricted()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "properly restricted" in findings[0].status_extended
            assert findings[0].resource_name == "Groups Policies"
            assert findings[0].resource_id == "groupsPolicies"
            assert findings[0].customer_id == CUSTOMER_ID
            assert (
                findings[0].resource
                == GroupsForBusinessPolicies(
                    create_groups_access_level="ADMIN_ONLY",
                    owners_can_allow_external_members=False,
                    owners_can_allow_incoming_mail_from_public=False,
                ).dict()
            )

    def test_fail_users_in_domain(self):
        """Test FAIL when anyone in org can create groups"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.groups.groups_creation_restricted.groups_creation_restricted.groups_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.groups.groups_creation_restricted.groups_creation_restricted import (
                groups_creation_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GroupsForBusinessPolicies(
                create_groups_access_level="USERS_IN_DOMAIN",
                owners_can_allow_external_members=False,
                owners_can_allow_incoming_mail_from_public=False,
            )

            check = groups_creation_restricted()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "USERS_IN_DOMAIN" in findings[0].status_extended

    def test_fail_external_members_allowed(self):
        """Test FAIL when external members are allowed"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.groups.groups_creation_restricted.groups_creation_restricted.groups_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.groups.groups_creation_restricted.groups_creation_restricted import (
                groups_creation_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GroupsForBusinessPolicies(
                create_groups_access_level="ADMIN_ONLY",
                owners_can_allow_external_members=True,
                owners_can_allow_incoming_mail_from_public=False,
            )

            check = groups_creation_restricted()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "external members" in findings[0].status_extended

    def test_fail_incoming_mail_allowed(self):
        """Test FAIL when incoming email from outside is allowed"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.groups.groups_creation_restricted.groups_creation_restricted.groups_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.groups.groups_creation_restricted.groups_creation_restricted import (
                groups_creation_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GroupsForBusinessPolicies(
                create_groups_access_level="ADMIN_ONLY",
                owners_can_allow_external_members=False,
                owners_can_allow_incoming_mail_from_public=True,
            )

            check = groups_creation_restricted()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "incoming email" in findings[0].status_extended

    def test_fail_all_defaults_none(self):
        """Test FAIL when all settings are None (defaults: USERS_IN_DOMAIN, false, true — mixed insecure)"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.groups.groups_creation_restricted.groups_creation_restricted.groups_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.groups.groups_creation_restricted.groups_creation_restricted import (
                groups_creation_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GroupsForBusinessPolicies()

            check = groups_creation_restricted()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            # Should report both insecure defaults
            assert "ADMIN_ONLY" in findings[0].status_extended
            assert "incoming email" in findings[0].status_extended

    def test_fail_multiple_issues(self):
        """Test FAIL with all three sub-settings non-compliant"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.groups.groups_creation_restricted.groups_creation_restricted.groups_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.groups.groups_creation_restricted.groups_creation_restricted import (
                groups_creation_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GroupsForBusinessPolicies(
                create_groups_access_level="ANYONE_CAN_CREATE",
                owners_can_allow_external_members=True,
                owners_can_allow_incoming_mail_from_public=True,
            )

            check = groups_creation_restricted()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "ANYONE_CAN_CREATE" in findings[0].status_extended
            assert "external members" in findings[0].status_extended
            assert "incoming email" in findings[0].status_extended

    def test_no_findings_when_fetch_failed(self):
        """Test no findings returned when the API fetch failed"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.groups.groups_creation_restricted.groups_creation_restricted.groups_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.groups.groups_creation_restricted.groups_creation_restricted import (
                groups_creation_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = False
            mock_client.policies = GroupsForBusinessPolicies()

            check = groups_creation_restricted()
            findings = check.execute()

            assert len(findings) == 0
