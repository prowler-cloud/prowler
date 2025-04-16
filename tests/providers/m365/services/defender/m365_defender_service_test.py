from unittest import mock
from unittest.mock import patch

from prowler.providers.m365.models import M365IdentityInfo
from prowler.providers.m365.services.defender.defender_service import (
    Defender,
    DefenderMalwarePolicy,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


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


class Test_Defender_Service:
    def test_get_client(self):
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
        ):
            defender_client = Defender(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )
            assert defender_client.client.__class__.__name__ == "GraphServiceClient"
            assert defender_client.powershell.__class__.__name__ == "M365PowerShell"
            defender_client.powershell.close()

    @patch(
        "prowler.providers.m365.services.defender.defender_service.Defender._get_malware_filter_policy",
        new=mock_defender_get_malware_filter_policy,
    )
    def test__get_malware_filter_policy(self):
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
        ):
            defender_client = Defender(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )
            malware_policies = defender_client.malware_policies
            assert malware_policies[0].enable_file_filter is False
            assert malware_policies[0].identity == "Policy1"
            assert (
                malware_policies[0].enable_internal_sender_admin_notifications is False
            )
            assert malware_policies[0].internal_sender_admin_address == ""
            assert malware_policies[1].enable_file_filter is True
            assert malware_policies[1].identity == "Policy2"
            assert (
                malware_policies[1].enable_internal_sender_admin_notifications is True
            )
            assert (
                malware_policies[1].internal_sender_admin_address
                == "security@example.com"
            )
