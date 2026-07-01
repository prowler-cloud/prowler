from unittest import mock

from prowler.providers.m365.services.defender.defender_service import (
    AdvancedThreatProtectionPolicy,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_defender_atp_safe_attachments_and_docs_configured:
    """Tests for defender_atp_safe_attachments_and_docs_configured check."""

    def test_no_atp_policy(self):
        """Test when no ATP policy exists (advanced_threat_protection_policy is None)."""
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN
        defender_client.advanced_threat_protection_policy = None

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_atp_safe_attachments_and_docs_configured.defender_atp_safe_attachments_and_docs_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_atp_safe_attachments_and_docs_configured.defender_atp_safe_attachments_and_docs_configured import (
                defender_atp_safe_attachments_and_docs_configured,
            )

            check = defender_atp_safe_attachments_and_docs_configured()
            result = check.execute()

            assert len(result) == 0

    def test_atp_policy_all_settings_compliant(self):
        """Test when ATP policy is properly configured (PASS case)."""
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN
        defender_client.advanced_threat_protection_policy = (
            AdvancedThreatProtectionPolicy(
                identity="Default",
                enable_atp_for_spo_teams_odb=True,
                enable_safe_docs=True,
                allow_safe_docs_open=False,
            )
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_atp_safe_attachments_and_docs_configured.defender_atp_safe_attachments_and_docs_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_atp_safe_attachments_and_docs_configured.defender_atp_safe_attachments_and_docs_configured import (
                defender_atp_safe_attachments_and_docs_configured,
            )

            check = defender_atp_safe_attachments_and_docs_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "ATP policy Default has Safe Attachments for SharePoint, OneDrive, and Teams properly configured with Safe Documents enabled and click-through blocked."
            )
            assert result[0].resource_id == "Default"
            assert result[0].resource_name == "Default"
            assert result[0].location == "global"

    def test_atp_policy_spo_teams_odb_disabled(self):
        """Test when Safe Attachments for SPO/OneDrive/Teams is disabled (FAIL case)."""
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN
        defender_client.advanced_threat_protection_policy = (
            AdvancedThreatProtectionPolicy(
                identity="Default",
                enable_atp_for_spo_teams_odb=False,
                enable_safe_docs=True,
                allow_safe_docs_open=False,
            )
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_atp_safe_attachments_and_docs_configured.defender_atp_safe_attachments_and_docs_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_atp_safe_attachments_and_docs_configured.defender_atp_safe_attachments_and_docs_configured import (
                defender_atp_safe_attachments_and_docs_configured,
            )

            check = defender_atp_safe_attachments_and_docs_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "ATP policy Default is not properly configured: Safe Attachments for SPO/OneDrive/Teams is disabled."
            )
            assert result[0].resource_id == "Default"
            assert result[0].resource_name == "Default"
            assert result[0].location == "global"

    def test_atp_policy_safe_docs_disabled(self):
        """Test when Safe Documents is disabled (FAIL case)."""
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN
        defender_client.advanced_threat_protection_policy = (
            AdvancedThreatProtectionPolicy(
                identity="Default",
                enable_atp_for_spo_teams_odb=True,
                enable_safe_docs=False,
                allow_safe_docs_open=False,
            )
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_atp_safe_attachments_and_docs_configured.defender_atp_safe_attachments_and_docs_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_atp_safe_attachments_and_docs_configured.defender_atp_safe_attachments_and_docs_configured import (
                defender_atp_safe_attachments_and_docs_configured,
            )

            check = defender_atp_safe_attachments_and_docs_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "ATP policy Default is not properly configured: Safe Documents is disabled."
            )
            assert result[0].resource_id == "Default"
            assert result[0].resource_name == "Default"
            assert result[0].location == "global"

    def test_atp_policy_safe_docs_open_allowed(self):
        """Test when users can bypass Protected View for malicious files (FAIL case)."""
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN
        defender_client.advanced_threat_protection_policy = (
            AdvancedThreatProtectionPolicy(
                identity="Default",
                enable_atp_for_spo_teams_odb=True,
                enable_safe_docs=True,
                allow_safe_docs_open=True,
            )
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_atp_safe_attachments_and_docs_configured.defender_atp_safe_attachments_and_docs_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_atp_safe_attachments_and_docs_configured.defender_atp_safe_attachments_and_docs_configured import (
                defender_atp_safe_attachments_and_docs_configured,
            )

            check = defender_atp_safe_attachments_and_docs_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "ATP policy Default is not properly configured: users can bypass Protected View for malicious files."
            )
            assert result[0].resource_id == "Default"
            assert result[0].resource_name == "Default"
            assert result[0].location == "global"

    def test_atp_policy_all_settings_non_compliant(self):
        """Test when all three settings are non-compliant (FAIL case)."""
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN
        defender_client.advanced_threat_protection_policy = (
            AdvancedThreatProtectionPolicy(
                identity="Default",
                enable_atp_for_spo_teams_odb=False,
                enable_safe_docs=False,
                allow_safe_docs_open=True,
            )
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_atp_safe_attachments_and_docs_configured.defender_atp_safe_attachments_and_docs_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_atp_safe_attachments_and_docs_configured.defender_atp_safe_attachments_and_docs_configured import (
                defender_atp_safe_attachments_and_docs_configured,
            )

            check = defender_atp_safe_attachments_and_docs_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "ATP policy Default is not properly configured: Safe Attachments for SPO/OneDrive/Teams is disabled; Safe Documents is disabled; users can bypass Protected View for malicious files."
            )
            assert result[0].resource_id == "Default"
            assert result[0].resource_name == "Default"
            assert result[0].location == "global"

    def test_atp_policy_custom_identity(self):
        """Test with a custom policy identity name."""
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN
        defender_client.advanced_threat_protection_policy = (
            AdvancedThreatProtectionPolicy(
                identity="CustomPolicy",
                enable_atp_for_spo_teams_odb=True,
                enable_safe_docs=True,
                allow_safe_docs_open=False,
            )
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_atp_safe_attachments_and_docs_configured.defender_atp_safe_attachments_and_docs_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_atp_safe_attachments_and_docs_configured.defender_atp_safe_attachments_and_docs_configured import (
                defender_atp_safe_attachments_and_docs_configured,
            )

            check = defender_atp_safe_attachments_and_docs_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "ATP policy CustomPolicy has Safe Attachments for SharePoint, OneDrive, and Teams properly configured with Safe Documents enabled and click-through blocked."
            )
            assert result[0].resource_id == "CustomPolicy"
            assert result[0].resource_name == "CustomPolicy"
            assert result[0].location == "global"
