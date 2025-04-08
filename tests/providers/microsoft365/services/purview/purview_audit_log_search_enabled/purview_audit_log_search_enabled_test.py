from unittest import mock

from tests.providers.microsoft365.microsoft365_fixtures import (
    DOMAIN,
    set_mocked_microsoft365_provider,
)


class Test_purview_audit_log_search_enabled:
    def test_audit_log_search_disabled(self):
        purview_client = mock.MagicMock()
        purview_client.audited_tenant = "audited_tenant"
        purview_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.lib.powershell.powershell.PowerShellSession.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.purview.purview_audit_log_search_enabled.purview_audit_log_search_enabled.purview_client",
                new=purview_client,
            ),
        ):
            from prowler.providers.microsoft365.services.purview.purview_audit_log_search_enabled.purview_audit_log_search_enabled import (
                purview_audit_log_search_enabled,
            )
            from prowler.providers.microsoft365.services.purview.purview_service import (
                AuditLogConfig,
            )

            purview_client.audit_log_config = AuditLogConfig(audit_log_search=False)

            check = purview_audit_log_search_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended == "Purview audit log search is not enabled."
            )
            assert result[0].resource == purview_client.audit_log_config.dict()
            assert result[0].resource_name == "Purview Settings"
            assert result[0].resource_id == "purviewSettings"
            assert result[0].location == "global"

    def test_audit_log_search_enabled(self):
        purview_client = mock.MagicMock()
        purview_client.audited_tenant = "audited_tenant"
        purview_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.lib.powershell.powershell.PowerShellSession.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.purview.purview_audit_log_search_enabled.purview_audit_log_search_enabled.purview_client",
                new=purview_client,
            ),
        ):
            from prowler.providers.microsoft365.services.purview.purview_audit_log_search_enabled.purview_audit_log_search_enabled import (
                purview_audit_log_search_enabled,
            )
            from prowler.providers.microsoft365.services.purview.purview_service import (
                AuditLogConfig,
            )

            purview_client = mock.MagicMock
            purview_client.audit_log_config = AuditLogConfig(audit_log_search=True)

            check = purview_audit_log_search_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == "Purview audit log search is enabled."
            assert result[0].resource == purview_client.audit_log_config.dict()
            assert result[0].resource_name == "Purview Settings"
            assert result[0].resource_id == "purviewSettings"
            assert result[0].location == "global"
