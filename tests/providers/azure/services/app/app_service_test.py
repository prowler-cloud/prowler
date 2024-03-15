from unittest.mock import patch

from azure.mgmt.web.models import ManagedServiceIdentity, SiteConfigResource

from prowler.providers.azure.services.app.app_service import App, WebApp
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION,
    set_mocked_azure_provider,
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
            )
        }
    }


@patch(
    "prowler.providers.azure.services.app.app_service.App.__get_apps__",
    new=mock_app_get_apps,
)
class Test_App_Service:
    def test__get_client__(self):
        app_service = App(set_mocked_azure_provider())
        assert (
            app_service.clients[AZURE_SUBSCRIPTION].__class__.__name__
            == "WebSiteManagementClient"
        )

    def test__get_subscriptions__(self):
        app_service = App(set_mocked_azure_provider())
        assert app_service.subscriptions.__class__.__name__ == "dict"

    def test__get_apps__(self):
        app_service = App(set_mocked_azure_provider())
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
        app_service = App(set_mocked_azure_provider())
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
