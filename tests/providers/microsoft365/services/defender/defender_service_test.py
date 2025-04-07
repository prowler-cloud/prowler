from unittest.mock import patch

from prowler.providers.microsoft365.models import Microsoft365IdentityInfo
from prowler.providers.microsoft365.services.defender.defender_service import (
    Defender,
    DefenderMalwarePolicy,
)
from tests.providers.microsoft365.microsoft365_fixtures import (
    DOMAIN,
    set_mocked_microsoft365_provider,
)


def mock_defender_get_malware_filter_policy(_):
    return [
        DefenderMalwarePolicy(
            enable_file_filter=False,
            identity="Policy1",
            enable_internal_sender_admin_notifications=False,
            internal_sender_admin_address="",
        ),
        DefenderMalwarePolicy(
            enable_file_filter=True,
            identity="Policy2",
            enable_internal_sender_admin_notifications=True,
            internal_sender_admin_address="security@example.com",
        ),
    ]


@patch(
    "prowler.providers.microsoft365.services.defender.defender_service.Defender._get_malware_filter_policy",
    new=mock_defender_get_malware_filter_policy,
)
class Test_Defender_Service:
    def test_get_client(self):
        defender_client = Defender(
            set_mocked_microsoft365_provider(
                identity=Microsoft365IdentityInfo(tenant_domain=DOMAIN)
            )
        )
        assert defender_client.client.__class__.__name__ == "GraphServiceClient"

    def test__get_malware_filter_policy(self):
        defender_client = Defender(set_mocked_microsoft365_provider())
        malware_policies = defender_client.malware_policies
        assert malware_policies[0].enable_file_filter is False
        assert malware_policies[0].identity == "Policy1"
        assert malware_policies[0].enable_internal_sender_admin_notifications is False
        assert malware_policies[0].internal_sender_admin_address == ""
        assert malware_policies[1].enable_file_filter is True
        assert malware_policies[1].identity == "Policy2"
        assert malware_policies[1].enable_internal_sender_admin_notifications is True
        assert (
            malware_policies[1].internal_sender_admin_address == "security@example.com"
        )
