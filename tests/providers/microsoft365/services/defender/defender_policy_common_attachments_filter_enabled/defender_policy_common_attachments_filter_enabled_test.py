from unittest import mock

from tests.providers.microsoft365.microsoft365_fixtures import (
    DOMAIN,
    set_mocked_microsoft365_provider,
)


class Test_defender_policy_common_attachments_filter_enabled:
    def test_enable_file_filter_disabled(self):
        defender_client = mock.MagicMock
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.defender.defender_policy_common_attachments_filter_enabled.defender_policy_common_attachments_filter_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.microsoft365.services.defender.defender_policy_common_attachments_filter_enabled.defender_policy_common_attachments_filter_enabled import (
                defender_policy_common_attachments_filter_enabled,
            )
            from prowler.providers.microsoft365.services.defender.defender_service import (
                DefenderMalwarePolicy,
            )

            defender_client = mock.MagicMock
            defender_client.malware_policy = DefenderMalwarePolicy(
                enable_file_filter=False,
                identity="Default",
                enable_internal_sender_admin_notifications=False,
                internal_sender_admin_address="",
            )

            check = defender_policy_common_attachments_filter_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Common Attachment Types Filter is not enabled in the Defender anti-malware policy."
            )
            assert result[0].resource == defender_client.malware_policy.dict()
            assert result[0].resource_name == "Defender Malware Policy"
            assert result[0].resource_id == "defenderMalwarePolicy"
            assert result[0].location == "global"

    def test_enable_file_filter_enabled(self):
        defender_client = mock.MagicMock
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.defender.defender_policy_common_attachments_filter_enabled.defender_policy_common_attachments_filter_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.microsoft365.services.defender.defender_policy_common_attachments_filter_enabled.defender_policy_common_attachments_filter_enabled import (
                defender_policy_common_attachments_filter_enabled,
            )
            from prowler.providers.microsoft365.services.defender.defender_service import (
                DefenderMalwarePolicy,
            )

            defender_client = mock.MagicMock
            defender_client.malware_policy = DefenderMalwarePolicy(
                enable_file_filter=True,
                identity="Default",
                enable_internal_sender_admin_notifications=False,
                internal_sender_admin_address="",
            )

            check = defender_policy_common_attachments_filter_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Common Attachment Types Filter is enabled in the Defender anti-malware policy."
            )
            assert result[0].resource == defender_client.malware_policy.dict()
            assert result[0].resource_name == "Defender Malware Policy"
            assert result[0].resource_id == "defenderMalwarePolicy"
            assert result[0].location == "global"
