from unittest import mock

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_app_http_logs_enabled:

    def test_app_http_logs_enabled_no_subscriptions(self):
        app_client = mock.MagicMock
        app_client.apps = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_http_logs_enabled.app_http_logs_enabled.app_client",
            new=app_client,
        ):

            from prowler.providers.azure.services.app.app_http_logs_enabled.app_http_logs_enabled import (
                app_http_logs_enabled,
            )

            check = app_http_logs_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_app_subscriptions_empty(self):
        app_client = mock.MagicMock
        app_client.apps = {AZURE_SUBSCRIPTION_ID: {}}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_register_with_identity.app_register_with_identity.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_register_with_identity.app_register_with_identity import (
                app_register_with_identity,
            )

            check = app_register_with_identity()
            result = check.execute()
            assert len(result) == 0

    def test_no_diagnostics_settings(self):
        app_client = mock.MagicMock()
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_http_logs_enabled.app_http_logs_enabled.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_http_logs_enabled.app_http_logs_enabled import (
                app_http_logs_enabled,
            )
            from prowler.providers.azure.services.app.app_service import WebApp

            app_client.apps = {
                AZURE_SUBSCRIPTION_ID: {
                    "app1": WebApp(
                        resource_id="resource_id",
                        auth_enabled=True,
                        configurations=None,
                        client_cert_mode="Ignore",
                        https_only=False,
                        identity=None,
                        kind="webapps",
                        location="West Europe",
                    )
                }
            }

            check = app_http_logs_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_name == "app1"
            assert result[0].resource_id == "resource_id"
            assert (
                result[0].status_extended
                == f"App app1 does not have a diagnostic setting in subscription {AZURE_SUBSCRIPTION_ID}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_diagnostic_setting_configured(self):
        app_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_http_logs_enabled.app_http_logs_enabled.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_http_logs_enabled.app_http_logs_enabled import (
                app_http_logs_enabled,
            )
            from prowler.providers.azure.services.app.app_service import WebApp
            from prowler.providers.azure.services.monitor.monitor_service import (
                DiagnosticSetting,
            )

            app_client.apps = {
                AZURE_SUBSCRIPTION_ID: {
                    "app_id-1": WebApp(
                        resource_id="resource_id1",
                        auth_enabled=True,
                        configurations=None,
                        client_cert_mode="Ignore",
                        https_only=False,
                        kind="functionapp",
                        identity=mock.MagicMock,
                        location="West Europe",
                        monitor_diagnostic_settings=[
                            DiagnosticSetting(
                                id="id1/id1",
                                logs=[
                                    mock.MagicMock(
                                        category="AppServiceHTTPLogs",
                                        enabled=True,
                                    ),
                                    mock.MagicMock(
                                        category="AppServiceConsoleLogs",
                                        enabled=False,
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
                                        enabled=False,
                                    ),
                                    mock.MagicMock(
                                        category="AppServicePlatformLogs",
                                        enabled=False,
                                    ),
                                ],
                                storage_account_name="storage_account_name1",
                                storage_account_id="storage_account_id1",
                                name="name_diagnostic_setting1",
                            ),
                        ],
                    ),
                    "app_id-2": WebApp(
                        resource_id="resource_id2",
                        auth_enabled=True,
                        configurations=None,
                        client_cert_mode="Ignore",
                        https_only=False,
                        kind="WebApp",
                        identity=mock.MagicMock,
                        location="West Europe",
                        monitor_diagnostic_settings=[
                            DiagnosticSetting(
                                id="id2/id2",
                                logs=[
                                    mock.MagicMock(
                                        category="AppServiceHTTPLogs",
                                        enabled=True,
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
                    ),
                }
            }
            check = app_http_logs_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "app_id-2"
            assert result[0].resource_id == "resource_id2"
            assert (
                result[0].status_extended
                == f"App app_id-2 has HTTP Logs enabled in diagnostic setting name_diagnostic_setting2 in subscription {AZURE_SUBSCRIPTION_ID}"
            )
