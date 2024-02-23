from dataclasses import dataclass

from azure.mgmt.web import WebSiteManagementClient
from azure.mgmt.web.models import ManagedServiceIdentity, SiteConfigResource

from prowler.lib.logger import logger
from prowler.providers.azure.lib.audit_info.models import Azure_Audit_Info
from prowler.providers.azure.lib.service.service import AzureService


########################## App
class App(AzureService):
    def __init__(self, audit_info: Azure_Audit_Info):
        super().__init__(WebSiteManagementClient, audit_info)
        self.apps = self.__get_apps__()

    def __get_apps__(self):
        logger.info("App - Getting apps...")
        apps = {}

        for subscription_name, client in self.clients.items():
            try:
                apps_list = client.web_apps.list()
                apps.update({subscription_name: {}})

                for app in apps_list:
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
                                client_cert_mode=self.__get_client_cert_mode__(
                                    getattr(app, "client_cert_enabled", False),
                                    getattr(app, "client_cert_mode", "Ignore"),
                                ),
                                https_only=getattr(app, "https_only", False),
                                identity=getattr(app, "identity", None),
                            )
                        }
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        return apps

    def __get_client_cert_mode__(
        self, client_cert_enabled: bool, client_cert_mode: str
    ):
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


@dataclass
class WebApp:
    resource_id: str
    configurations: SiteConfigResource
    identity: ManagedServiceIdentity
    client_cert_mode: str = "Ignore"
    auth_enabled: bool = False
    https_only: bool = False
