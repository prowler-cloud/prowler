from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    B2BCollaborationPolicy,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_policy_guest_invitations_restricted_to_allowed_domains.entra_policy_guest_invitations_restricted_to_allowed_domains"


class Test_entra_policy_guest_invitations_restricted_to_allowed_domains:
    def _run(self, policy):
        entra_client = mock.MagicMock
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_policy_guest_invitations_restricted_to_allowed_domains.entra_policy_guest_invitations_restricted_to_allowed_domains import (
                entra_policy_guest_invitations_restricted_to_allowed_domains,
            )

            entra_client.b2b_collaboration_policy = policy
            return (
                entra_policy_guest_invitations_restricted_to_allowed_domains().execute()
            )

    def test_no_policy(self):
        assert self._run(None) == []

    def test_restricted(self):
        result = self._run(
            B2BCollaborationPolicy(
                invitations_restricted_to_allowed_domains=True,
                allowed_domains=["partner.com"],
            )
        )
        assert result[0].status == "PASS"

    def test_not_restricted(self):
        result = self._run(
            B2BCollaborationPolicy(
                invitations_restricted_to_allowed_domains=False,
                allowed_domains=[],
            )
        )
        assert result[0].status == "FAIL"
