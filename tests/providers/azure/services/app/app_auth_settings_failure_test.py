from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

import pytest
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from azure.mgmt.web.models import SiteConfigResource

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    RESOURCE_GROUP,
    set_mocked_azure_provider,
)


class Test_App_Auth_Settings_Failure:
    @pytest.fixture(autouse=True)
    def mocked_provider(self):
        """Keep lazy service-client imports isolated in every test order."""
        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            patch(
                "prowler.providers.azure.services.monitor.monitor_service.Monitor",
                new=MagicMock(),
            ),
        ):
            yield

    @pytest.mark.parametrize("scoped", [False, True])
    @pytest.mark.parametrize("failed_index", [0, 1])
    def test_auth_settings_error_retains_apps(self, scoped, failed_index):
        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            patch(
                "prowler.providers.azure.services.monitor.monitor_service.Monitor",
                new=MagicMock(),
            ),
        ):
            from prowler.providers.azure.services.app.app_service import App

            app = object.__new__(App)
            client = MagicMock()
            sites = [
                SimpleNamespace(
                    id=f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.Web/sites/app-{index}",
                    name=f"app-{index}",
                    resource_group=RESOURCE_GROUP,
                    kind="app",
                    location="westeurope",
                    https_only=False,
                )
                for index in range(2)
            ]
            client.web_apps.list.return_value = sites
            client.web_apps.list_by_resource_group.return_value = sites
            client.web_apps.get_configuration.return_value = SiteConfigResource(
                min_tls_version="1.2"
            )
            auth_results = [
                SimpleNamespace(platform=SimpleNamespace(enabled=True)) for _ in sites
            ]
            auth_results[failed_index] = HttpResponseError(
                message="AuthorizationFailed"
            )
            client.web_apps.get_auth_settings_v2.side_effect = auth_results
            app.clients = {AZURE_SUBSCRIPTION_ID: client}
            app.resource_groups = (
                {AZURE_SUBSCRIPTION_ID: [RESOURCE_GROUP]} if scoped else None
            )
            with patch.object(App, "_get_app_monitor_settings", return_value=[]):
                result = app._get_apps()[AZURE_SUBSCRIPTION_ID]
            app.apps = {AZURE_SUBSCRIPTION_ID: result}
            app.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
            with (
                patch(
                    "prowler.providers.azure.services.app.app_service.App",
                    return_value=app,
                ),
                patch(
                    "prowler.providers.azure.services.app.app_ensure_http_is_redirected_to_https.app_ensure_http_is_redirected_to_https.app_client",
                    new=app,
                ),
            ):
                from prowler.providers.azure.services.app.app_ensure_http_is_redirected_to_https.app_ensure_http_is_redirected_to_https import (
                    app_ensure_http_is_redirected_to_https,
                )

                findings = app_ensure_http_is_redirected_to_https().execute()

        assert set(result) == {site.id for site in sites}
        assert result[sites[failed_index].id].auth_enabled is None
        assert result[sites[1 - failed_index].id].auth_enabled is True
        assert all(not site.https_only for site in result.values())
        assert client.web_apps.get_auth_settings_v2.call_args_list == [
            call(resource_group_name=site.resource_group, name=site.name)
            for site in sites
        ]
        assert {finding.resource_id for finding in findings} == set(result)
        assert [finding.status for finding in findings] == ["FAIL", "FAIL"]

    @pytest.mark.parametrize("unknown_count", [1, 2])
    def test_auth_check_reports_one_manual_per_subscription(self, unknown_count):
        client = MagicMock()
        client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            patch(
                "prowler.providers.azure.services.app.app_service.App",
                return_value=client,
            ),
            patch(
                "prowler.providers.azure.services.app.app_ensure_auth_is_set_up.app_ensure_auth_is_set_up.app_client",
                new=client,
            ),
        ):
            from prowler.providers.azure.services.app.app_ensure_auth_is_set_up.app_ensure_auth_is_set_up import (
                app_ensure_auth_is_set_up,
            )
            from prowler.providers.azure.services.app.app_service import WebApp

            client.apps = {
                AZURE_SUBSCRIPTION_ID: {
                    f"app-{index}": WebApp(
                        resource_id=f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.Web/sites/app-{index}",
                        name=f"app-{index}",
                        configurations=MagicMock(),
                        identity=None,
                        location="westeurope",
                        auth_enabled=enabled,
                    )
                    for index, enabled in enumerate(
                        [None] * unknown_count + [True, False]
                    )
                }
            }
            findings = app_ensure_auth_is_set_up().execute()

        assert [finding.status for finding in findings] == ["MANUAL", "PASS", "FAIL"]
        assert findings[0].resource_id == f"/subscriptions/{AZURE_SUBSCRIPTION_ID}"
        assert findings[0].subscription == AZURE_SUBSCRIPTION_ID
        for index in range(unknown_count):
            assert (
                client.apps[AZURE_SUBSCRIPTION_ID][f"app-{index}"].resource_id
                in findings[0].status_extended
            )
        assert (
            "authentication settings could not be retrieved"
            in findings[0].status_extended
        )
        assert findings[1].resource_name == f"app-{unknown_count}"
        assert findings[2].resource_name == f"app-{unknown_count + 1}"

    @pytest.mark.parametrize(
        "response, expected",
        [
            (SimpleNamespace(platform=SimpleNamespace(enabled=True)), True),
            (SimpleNamespace(platform=SimpleNamespace(enabled=False)), False),
            (SimpleNamespace(platform=None), False),
            (ResourceNotFoundError(message="Not configured"), False),
            (HttpResponseError(message="AuthorizationFailed"), None),
        ],
    )
    def test_get_app_auth_enabled(self, response, expected):
        from prowler.providers.azure.services.app.app_service import App

        app = object.__new__(App)
        client = MagicMock()
        app.clients = {AZURE_SUBSCRIPTION_ID: client}
        if isinstance(response, Exception):
            client.web_apps.get_auth_settings_v2.side_effect = response
        else:
            client.web_apps.get_auth_settings_v2.return_value = response

        assert (
            app._get_app_auth_enabled(AZURE_SUBSCRIPTION_ID, RESOURCE_GROUP, "app-0")
            is expected
        )
        client.web_apps.get_auth_settings_v2.assert_called_once_with(
            resource_group_name=RESOURCE_GROUP, name="app-0"
        )
