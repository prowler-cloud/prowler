from unittest import mock
from unittest.mock import patch

from prowler.providers.m365.models import M365IdentityInfo
from prowler.providers.m365.services.purview.purview_service import (
    AuditLogConfig,
    Purview,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


def mock_get_audit_log_config(_):
    return AuditLogConfig(audit_log_search=True)


class Test_Purview_Service:
    def test_get_client(self):
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
        ):
            purview_client = Purview(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )
            assert purview_client.client.__class__.__name__ == "GraphServiceClient"
            assert purview_client.powershell.__class__.__name__ == "M365PowerShell"
            purview_client.powershell.close()

    @patch(
        "prowler.providers.m365.services.purview.purview_service.Purview._get_audit_log_config",
        new=mock_get_audit_log_config,
    )
    def test_get_settings(self):
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
        ):
            purview_client = Purview(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )
            assert purview_client.audit_log_config == AuditLogConfig(
                audit_log_search=True
            )
            purview_client.powershell.close()
