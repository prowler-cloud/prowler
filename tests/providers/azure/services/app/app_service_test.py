from unittest import mock
from unittest.mock import patch

from azure.mgmt.web.models import ManagedServiceIdentity, SiteConfigResource

from prowler.providers.azure.services.app.app_service import App, WebApp
from prowler.providers.azure.services.monitor.monitor_service import DiagnosticSetting
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION,
    set_mocked_azure_audit_info,
)


def mock_app_get_apps(self):
    return {
        AZURE_SUBSCRIPTION: {
            "app_id-1": WebApp(
                resource_id="/subscriptions/resource_id",
                configurations=SiteConfigResource(),
                identity=ManagedServiceIdentity(type="SystemAssigned"),
                auth_enabled=True,
                client_cert_mode="Required",
                https_only=True,
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


@patch(
    "prowler.providers.azure.services.app.app_service.App.__get_apps__",
    new=mock_app_get_apps,
)
class Test_App_Service:
    def test__get_client__(self):
        app_service = App(set_mocked_azure_audit_info())
        assert (
            app_service.clients[AZURE_SUBSCRIPTION].__class__.__name__
            == "WebSiteManagementClient"
        )

    def test__get_subscriptions__(self):
        app_service = App(set_mocked_azure_audit_info())
        assert app_service.subscriptions.__class__.__name__ == "dict"

    def test__get_apps__(self):
        app_service = App(set_mocked_azure_audit_info())
        assert len(app_service.apps) == 1
        assert (
            app_service.apps[AZURE_SUBSCRIPTION]["app_id-1"].resource_id
            == "/subscriptions/resource_id"
        )
        assert app_service.apps[AZURE_SUBSCRIPTION]["app_id-1"].auth_enabled
        assert (
            app_service.apps[AZURE_SUBSCRIPTION]["app_id-1"].client_cert_mode
            == "Required"
        )
        assert app_service.apps[AZURE_SUBSCRIPTION]["app_id-1"].https_only
        assert (
            app_service.apps[AZURE_SUBSCRIPTION]["app_id-1"].identity.type
            == "SystemAssigned"
        )
        assert (
            app_service.apps[AZURE_SUBSCRIPTION][
                "app_id-1"
            ].configurations.__class__.__name__
            == "SiteConfigResource"
        )

    def test__get_client_cert_mode__(self):
        app_service = App(set_mocked_azure_audit_info())
        assert (
            app_service.__get_client_cert_mode__(False, "OptionalInteractiveUser")
            == "Ignore"
        )
        assert (
            app_service.__get_client_cert_mode__(True, "OptionalInteractiveUser")
            == "Optional"
        )
        assert app_service.__get_client_cert_mode__(True, "Optional") == "Allow"
        assert app_service.__get_client_cert_mode__(True, "Required") == "Required"
        assert app_service.__get_client_cert_mode__(True, "Foo") == "Ignore"

    def test__get_app_monitor_settings(self):
        app_service = App(set_mocked_azure_audit_info())
        assert (
            app_service.apps[AZURE_SUBSCRIPTION]["app_id-1"]
            .monitor_diagnostic_settings[0]
            .id
            == "id2/id2"
        )
        assert (
            app_service.apps[AZURE_SUBSCRIPTION]["app_id-1"]
            .monitor_diagnostic_settings[0]
            .logs[0]
            .category
            == "AppServiceHTTPLogs"
        )
        assert (
            app_service.apps[AZURE_SUBSCRIPTION]["app_id-1"]
            .monitor_diagnostic_settings[0]
            .storage_account_name
            == "storage_account_name2"
        )
        assert (
            app_service.apps[AZURE_SUBSCRIPTION]["app_id-1"]
            .monitor_diagnostic_settings[0]
            .storage_account_id
            == "storage_account_id2"
        )
        assert (
            app_service.apps[AZURE_SUBSCRIPTION]["app_id-1"]
            .monitor_diagnostic_settings[0]
            .name
            == "name_diagnostic_setting2"
        )
