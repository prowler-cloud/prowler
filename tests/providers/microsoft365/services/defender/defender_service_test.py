from unittest.mock import patch

from prowler.providers.microsoft365.models import Microsoft365IdentityInfo
from prowler.providers.microsoft365.services.defender.defender_service import (
    Defender,
    DefenderInboundSpamPolicy,
    DefenderMalwarePolicy,
)
from tests.providers.microsoft365.microsoft365_fixtures import (
    DOMAIN,
    set_mocked_microsoft365_provider,
)


def mock_defender_get_malware_filter_policy(_):
    return [
        DefenderMalwarePolicy(enable_file_filter=False, identity="Policy1"),
        DefenderMalwarePolicy(enable_file_filter=True, identity="Policy2"),
    ]


def mock_defender_get_inbound_spam_policy(_):
    return [
        DefenderInboundSpamPolicy(
            identity="Policy1",
            allowed_sender_domains=[],
        ),
        DefenderInboundSpamPolicy(
            identity="Policy2",
            allowed_sender_domains=["example.com"],
        ),
    ]


@patch(
    "prowler.providers.microsoft365.services.defender.defender_service.Defender._get_malware_filter_policy",
    new=mock_defender_get_malware_filter_policy,
)
@patch(
    "prowler.providers.microsoft365.services.defender.defender_service.Defender._get_inbound_spam_filter_policy",
    new=mock_defender_get_inbound_spam_policy,
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
        assert malware_policies[1].enable_file_filter is True
        assert malware_policies[1].identity == "Policy2"

    def test__get_inbound_spam_filter_policy(self):
        defender_client = Defender(set_mocked_microsoft365_provider())
        inbound_spam_policies = defender_client.inbound_spam_policies
        assert inbound_spam_policies[0].allowed_sender_domains == []
        assert inbound_spam_policies[0].identity == "Policy1"
        assert inbound_spam_policies[1].allowed_sender_domains == ["example.com"]
        assert inbound_spam_policies[1].identity == "Policy2"
