from unittest import mock

from tests.providers.m365.m365_fixtures import set_mocked_m365_provider


class TestPurviewAuditLogSearchEnabledFixer:
    def test_fix_success(self):
        purview_client = mock.MagicMock()
        purview_client.powershell.set_audit_log_config.return_value = None
        purview_client.powershell.close.return_value = None

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.purview.purview_audit_log_search_enabled.purview_audit_log_search_enabled_fixer.purview_client",
                new=purview_client,
            ),
        ):
            from prowler.providers.m365.services.purview.purview_audit_log_search_enabled.purview_audit_log_search_enabled_fixer import (
                PurviewAuditLogSearchEnabledFixer,
            )

            fixer = PurviewAuditLogSearchEnabledFixer()
            result = fixer.fix()
            assert result is True
            purview_client.powershell.set_audit_log_config.assert_called_once()
            purview_client.powershell.close.assert_called()

    def test_fix_exception(self):
        purview_client = mock.MagicMock()
        purview_client.powershell.set_audit_log_config.side_effect = Exception("fail")
        purview_client.powershell.close.return_value = None

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.purview.purview_audit_log_search_enabled.purview_audit_log_search_enabled_fixer.purview_client",
                new=purview_client,
            ),
        ):
            from prowler.providers.m365.services.purview.purview_audit_log_search_enabled.purview_audit_log_search_enabled_fixer import (
                PurviewAuditLogSearchEnabledFixer,
            )

            fixer = PurviewAuditLogSearchEnabledFixer()
            result = fixer.fix()
            assert result is False
            purview_client.powershell.set_audit_log_config.assert_called_once()
            purview_client.powershell.close.assert_called()
