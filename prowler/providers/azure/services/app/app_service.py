from dataclasses import dataclass
from typing import Dict

from azure.mgmt.web import WebSiteManagementClient
from azure.mgmt.web.models import ManagedServiceIdentity, SiteConfigResource

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService
from prowler.providers.azure.services.monitor.monitor_client import monitor_client
from prowler.providers.azure.services.monitor.monitor_service import DiagnosticSetting


class App(AzureService):
    def __init__(self, provider: AzureProvider):
        super().__init__(WebSiteManagementClient, provider)
        self.apps = self._get_apps()
        self.functions = self._get_functions()

    def _get_apps(self):
        logger.info("App - Getting apps...")
        apps = {}

        for subscription_name, client in self.clients.items():
            try:
                apps_list = client.web_apps.list()
                apps.update({subscription_name: {}})

                for app in apps_list:
                    # Filter function apps
                    if getattr(app, "kind", "app").startswith("app"):
                        platform_auth = getattr(
                            client.web_apps.get_auth_settings_v2(
                                resource_group_name=app.resource_group, name=app.name
                            ),
                            "platform",
                            None,
                        )

                        apps[subscription_name].update(
                            {
                                app.name: WebApp(
                                    resource_id=app.id,
                                    auth_enabled=(
                                        getattr(platform_auth, "enabled", False)
                                        if platform_auth
                                        else False
                                    ),
                                    configurations=client.web_apps.get_configuration(
                                        resource_group_name=app.resource_group,
                                        name=app.name,
                                    ),
                                    client_cert_mode=self._get_client_cert_mode(
                                        getattr(app, "client_cert_enabled", False),
                                        getattr(app, "client_cert_mode", "Ignore"),
                                    ),
                                    monitor_diagnostic_settings=self._get_app_monitor_settings(
                                        app.name, app.resource_group, subscription_name
                                    ),
                                    https_only=getattr(app, "https_only", False),
                                    identity=getattr(app, "identity", None),
                                    location=app.location,
                                    kind=app.kind,
                                )
                            }
                        )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        return apps

    def _get_functions(self):
        logger.info("Function - Getting functions...")
        functions = {}

        for subscription_name, client in self.clients.items():
            try:
                functions_list = client.web_apps.list()
                functions.update({subscription_name: {}})

                for function in functions_list:
                    # Filter function apps
                    if getattr(function, "kind", "").startswith("functionapp"):
                        # List host keys
                        host_keys = client.web_apps.list_host_keys(
                            resource_group_name=function.resource_group,
                            name=function.name,
                        )  # Need to add role 'Logic App Contributor' to the service principal to get the host keys or add to the reader role the permission 'Microsoft.Web/sites/host/listkeys'

                        function_config = client.web_apps.get_configuration(
                            resource_group_name=function.resource_group,
                            name=function.name,
                        )

                        functions[subscription_name].update(
                            {
                                function.id: FunctionApp(
                                    name=function.name,
                                    location=function.location,
                                    kind=function.kind,
                                    function_keys=getattr(
                                        host_keys, "function_keys", {}
                                    ),
                                    enviroment_variables=getattr(
                                        client.web_apps.list_application_settings(
                                            resource_group_name=function.resource_group,
                                            name=function.name,
                                        ),
                                        "properties",
                                        {},
                                    ),
                                    identity=getattr(function, "identity", None),
                                    public_access=(
                                        False
                                        if getattr(
                                            function, "public_network_access", ""
                                        )
                                        == "Disabled"
                                        else True
                                    ),
                                    vnet_subnet_id=getattr(
                                        function,
                                        "virtual_network_subnet_id",
                                        "",
                                    ),
                                    ftps_state=getattr(
                                        function_config, "ftps_state", ""
                                    ),
                                )
                            }
                        )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        return functions

    def _get_client_cert_mode(self, client_cert_enabled: bool, client_cert_mode: str):
        cert_mode = "Ignore"
        if not client_cert_enabled and client_cert_mode == "OptionalInteractiveUser":
            cert_mode = "Ignore"
        elif client_cert_enabled and client_cert_mode == "OptionalInteractiveUser":
            cert_mode = "Optional"
        elif client_cert_enabled and client_cert_mode == "Optional":
            cert_mode = "Allow"
        elif client_cert_enabled and client_cert_mode == "Required":
            cert_mode = "Required"
        else:
            cert_mode = "Ignore"

        return cert_mode

    def _get_app_monitor_settings(self, app_name, resource_group, subscription):
        logger.info(f"App - Getting monitor diagnostics settings for {app_name}...")
        monitor_diagnostics_settings = []
        try:
            monitor_diagnostics_settings = monitor_client.diagnostic_settings_with_uri(
                self.subscriptions[subscription],
                f"subscriptions/{self.subscriptions[subscription]}/resourceGroups/{resource_group}/providers/Microsoft.Web/sites/{app_name}",
                monitor_client.clients[subscription],
            )
        except Exception as error:
            logger.error(
                f"Subscription name: {self.subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return monitor_diagnostics_settings


@dataclass
class WebApp:
    resource_id: str
    configurations: SiteConfigResource
    identity: ManagedServiceIdentity
    location: str
    client_cert_mode: str = "Ignore"
    auth_enabled: bool = False
    https_only: bool = False
    monitor_diagnostic_settings: list[DiagnosticSetting] = None
    kind: str = "app"


@dataclass
class FunctionApp:
    name: str
    location: str
    kind: str
    function_keys: Dict[str, str]
    enviroment_variables: Dict[str, str]
    identity: ManagedServiceIdentity
    public_access: bool
    vnet_subnet_id: str
    ftps_state: str
