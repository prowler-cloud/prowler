from dataclasses import dataclass, field
from typing import Dict, List, Optional

from azure.mgmt.web import WebSiteManagementClient

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

                        # Get app configurations
                        app_configurations = client.web_apps.get_configuration(
                            resource_group_name=app.resource_group, name=app.name
                        )

                        apps[subscription_name].update(
                            {
                                app.id: WebApp(
                                    resource_id=app.id,
                                    name=app.name,
                                    auth_enabled=(
                                        getattr(platform_auth, "enabled", False)
                                        if platform_auth
                                        else False
                                    ),
                                    configurations=SiteConfigResource(
                                        id=app_configurations.id,
                                        name=app_configurations.name,
                                        linux_fx_version=getattr(
                                            app_configurations, "linux_fx_version", ""
                                        ),
                                        java_version=getattr(
                                            app_configurations, "java_version", ""
                                        ),
                                        php_version=getattr(
                                            app_configurations, "php_version", ""
                                        ),
                                        python_version=getattr(
                                            app_configurations, "python_version", ""
                                        ),
                                        http20_enabled=getattr(
                                            app_configurations, "http20_enabled", False
                                        ),
                                        ftps_state=getattr(
                                            app_configurations, "ftps_state", ""
                                        ),
                                        min_tls_version=getattr(
                                            app_configurations, "min_tls_version", ""
                                        ),
                                    ),
                                    client_cert_mode=self._get_client_cert_mode(
                                        getattr(app, "client_cert_enabled", False),
                                        getattr(app, "client_cert_mode", "Ignore"),
                                    ),
                                    monitor_diagnostic_settings=self._get_app_monitor_settings(
                                        app.name, app.resource_group, subscription_name
                                    ),
                                    https_only=getattr(app, "https_only", False),
                                    identity=ManagedServiceIdentity(
                                        principal_id=getattr(
                                            getattr(app, "identity", {}),
                                            "principal_id",
                                            "",
                                        ),
                                        tenant_id=getattr(
                                            getattr(app, "identity", {}),
                                            "tenant_id",
                                            "",
                                        ),
                                        type=getattr(
                                            getattr(app, "identity", {}), "type", ""
                                        ),
                                    ),
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
                        host_keys = self._get_function_host_keys(
                            subscription_name, function.resource_group, function.name
                        )
                        if host_keys is not None:
                            function_keys = getattr(host_keys, "function_keys", {})
                        else:
                            function_keys = None

                        application_settings = self._list_application_settings(
                            subscription_name, function.resource_group, function.name
                        )

                        function_config = self._get_function_config(
                            subscription_name,
                            function.resource_group,
                            function.name,
                        )

                        functions[subscription_name].update(
                            {
                                function.id: FunctionApp(
                                    id=function.id,
                                    name=function.name,
                                    location=function.location,
                                    kind=function.kind,
                                    function_keys=function_keys,
                                    enviroment_variables=getattr(
                                        application_settings, "properties", None
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
                                        function_config, "ftps_state", None
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

    def _get_function_host_keys(self, subscription, resource_group, name):
        try:
            return self.clients[subscription].web_apps.list_host_keys(
                resource_group_name=resource_group,
                name=name,
            )
        except Exception as error:
            logger.error(
                f"Error getting host keys for {name} in {resource_group}: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None

    def _get_function_config(self, subscription, resource_group, name):
        try:
            return self.clients[subscription].web_apps.get_configuration(
                resource_group_name=resource_group,
                name=name,
            )
        except Exception as error:
            logger.error(
                f"Error getting configuration for {name} in {resource_group}: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None

    def _list_application_settings(self, subscription, resource_group, name):
        try:
            return self.clients[subscription].web_apps.list_application_settings(
                resource_group_name=resource_group,
                name=name,
            )
        except Exception as error:
            logger.error(
                f"Error getting application settings for {name} in {resource_group}: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None


@dataclass
class ManagedServiceIdentity:
    principal_id: str
    tenant_id: str
    type: str


@dataclass
class SiteConfigResource:
    id: str
    name: str
    linux_fx_version: str
    java_version: str
    php_version: str
    python_version: str
    http20_enabled: bool
    ftps_state: str
    min_tls_version: str


@dataclass
class WebApp:
    resource_id: str
    name: str
    configurations: SiteConfigResource
    identity: ManagedServiceIdentity
    location: str
    client_cert_mode: str = "Ignore"
    auth_enabled: bool = False
    https_only: bool = False
    monitor_diagnostic_settings: List[DiagnosticSetting] = field(default_factory=list)
    kind: str = "app"


@dataclass
class FunctionApp:
    id: str
    name: str
    location: str
    kind: str
    function_keys: Optional[Dict[str, str]]
    enviroment_variables: Optional[Dict[str, str]]
    identity: ManagedServiceIdentity
    public_access: bool
    vnet_subnet_id: str
    ftps_state: Optional[str]
