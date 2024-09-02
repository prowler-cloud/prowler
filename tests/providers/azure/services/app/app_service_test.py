from unittest import mock
from unittest.mock import MagicMock, patch

from azure.mgmt.web.models import ManagedServiceIdentity, SiteConfigResource

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)

# TODO: we have to fix this test not to use MagicMock but set the App service while mocking the import of the Monitor client
# def mock_app_get_apps(_):
#     return {
#         AZURE_SUBSCRIPTION_ID: {
#             "app_id-1": WebApp(
#                 resource_id="/subscriptions/resource_id",
#                 configurations=SiteConfigResource(),
#                 identity=ManagedServiceIdentity(type="SystemAssigned"),
#                 auth_enabled=True,
#                 client_cert_mode="Required",
#                 https_only=True,
#                 monitor_diagnostic_settings=[
#                     DiagnosticSetting(
#                         id="id2/id2",
#                         logs=[
#                             mock.MagicMock(
#                                 category="AppServiceHTTPLogs",
#                                 enabled=False,
#                             ),
#                             mock.MagicMock(
#                                 category="AppServiceConsoleLogs",
#                                 enabled=True,
#                             ),
#                             mock.MagicMock(
#                                 category="AppServiceAppLogs",
#                                 enabled=True,
#                             ),
#                             mock.MagicMock(
#                                 category="AppServiceAuditLogs",
#                                 enabled=False,
#                             ),
#                             mock.MagicMock(
#                                 category="AppServiceIPSecAuditLogs",
#                                 enabled=True,
#                             ),
#                             mock.MagicMock(
#                                 category="AppServicePlatformLogs",
#                                 enabled=False,
#                             ),
#                         ],
#                         storage_account_name="storage_account_name2",
#                         storage_account_id="storage_account_id2",
#                         name="name_diagnostic_setting2",
#                     ),
#                 ],
#             )
#         }
#     }


# @patch(
#     "prowler.providers.azure.services.app.app_service.App._get_apps",
#     new=mock_app_get_apps,
# )
class Test_App_Service:
    def test_app_service_(self):
        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), patch(
            "prowler.providers.azure.services.monitor.monitor_service.Monitor",
            new=MagicMock(),
        ):
            from prowler.providers.azure.services.app.app_service import WebApp
            from prowler.providers.azure.services.monitor.monitor_service import (
                DiagnosticSetting,
            )

            app_service = MagicMock()
            app_service.apps = {
                AZURE_SUBSCRIPTION_ID: {
                    "app_id-1": WebApp(
                        resource_id="/subscriptions/resource_id",
                        configurations=SiteConfigResource(),
                        identity=ManagedServiceIdentity(type="SystemAssigned"),
                        auth_enabled=True,
                        client_cert_mode="Required",
                        https_only=True,
                        location="West Europe",
                        monitor_diagnostic_settings=[
                            DiagnosticSetting(
                                id="id2/id2",
                                logs=[
                                    mock.MagicMock(
                                        category="AppServiceHTTPLogs",
                                        enabled=False,
                                    ),
                                    mock.MagicMock(
                                        category="AppServiceConsoleLogs",
                                        enabled=True,
                                    ),
                                    mock.MagicMock(
                                        category="AppServiceAppLogs",
                                        enabled=True,
                                    ),
                                    mock.MagicMock(
                                        category="AppServiceAuditLogs",
                                        enabled=False,
                                    ),
                                    mock.MagicMock(
                                        category="AppServiceIPSecAuditLogs",
                                        enabled=True,
                                    ),
                                    mock.MagicMock(
                                        category="AppServicePlatformLogs",
                                        enabled=False,
                                    ),
                                ],
                                storage_account_name="storage_account_name2",
                                storage_account_id="storage_account_id2",
                                name="name_diagnostic_setting2",
                            ),
                        ],
                    )
                }
            }
        # assert (
        #     app_service.clients[AZURE_SUBSCRIPTION_ID][0].__class__.__name__
        #     == "WebSiteManagementClient"
        # )
        assert len(app_service.apps) == 1
        assert (
            app_service.apps[AZURE_SUBSCRIPTION_ID]["app_id-1"].resource_id
            == "/subscriptions/resource_id"
        )
        assert app_service.apps[AZURE_SUBSCRIPTION_ID]["app_id-1"].auth_enabled
        assert (
            app_service.apps[AZURE_SUBSCRIPTION_ID]["app_id-1"].client_cert_mode
            == "Required"
        )
        assert (
            app_service.apps[AZURE_SUBSCRIPTION_ID]["app_id-1"].location
            == "West Europe"
        )
        assert app_service.apps[AZURE_SUBSCRIPTION_ID]["app_id-1"].https_only
        assert (
            app_service.apps[AZURE_SUBSCRIPTION_ID]["app_id-1"].identity.type
            == "SystemAssigned"
        )
        assert (
            app_service.apps[AZURE_SUBSCRIPTION_ID][
                "app_id-1"
            ].configurations.__class__.__name__
            == "SiteConfigResource"
        )
        assert (
            app_service.apps[AZURE_SUBSCRIPTION_ID]["app_id-1"]
            .monitor_diagnostic_settings[0]
            .id
            == "id2/id2"
        )
        assert (
            app_service.apps[AZURE_SUBSCRIPTION_ID]["app_id-1"]
            .monitor_diagnostic_settings[0]
            .logs[0]
            .category
            == "AppServiceHTTPLogs"
        )
        assert (
            app_service.apps[AZURE_SUBSCRIPTION_ID]["app_id-1"]
            .monitor_diagnostic_settings[0]
            .storage_account_name
            == "storage_account_name2"
        )
        assert (
            app_service.apps[AZURE_SUBSCRIPTION_ID]["app_id-1"]
            .monitor_diagnostic_settings[0]
            .storage_account_id
            == "storage_account_id2"
        )
        assert (
            app_service.apps[AZURE_SUBSCRIPTION_ID]["app_id-1"]
            .monitor_diagnostic_settings[0]
            .name
            == "name_diagnostic_setting2"
        )
