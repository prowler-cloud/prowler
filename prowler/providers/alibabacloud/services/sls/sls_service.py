from alibabacloud_sls20201230 import models as sls_models
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.alibabacloud.lib.service.service import AlibabaCloudService


class Alert(BaseModel):
    name: str
    display_name: str
    state: str
    schedule: dict
    configuration: dict
    project: str
    region: str
    arn: str = ""


class LogStore(BaseModel):
    name: str
    project: str
    retention_forever: bool
    retention_days: int
    region: str
    arn: str = ""


class Sls(AlibabaCloudService):
    def __init__(self, provider):
        super().__init__("sls", provider)
        self.alerts = []
        self.log_stores = []
        self._get_alerts()
        self._get_log_stores()

    def _get_alerts(self):
        for region in self.regional_clients:
            client = self.regional_clients[region]
            try:
                # List Projects
                list_project_request = sls_models.ListProjectRequest(offset=0, size=500)
                projects_resp = client.list_project(list_project_request)

                if projects_resp.body and projects_resp.body.projects:
                    for project in projects_resp.body.projects:
                        project_name = project.project_name

                        # List Alerts for each project
                        list_alert_request = sls_models.ListAlertsRequest(
                            offset=0, size=500
                        )
                        try:
                            alerts_resp = client.list_alerts(
                                project_name, list_alert_request
                            )
                            if alerts_resp.body and alerts_resp.body.results:
                                for alert in alerts_resp.body.results:
                                    self.alerts.append(
                                        Alert(
                                            name=alert.name,
                                            display_name=alert.display_name,
                                            state=alert.state,
                                            schedule=(
                                                alert.schedule.to_map()
                                                if alert.schedule
                                                else {}
                                            ),
                                            configuration=(
                                                alert.configuration.to_map()
                                                if alert.configuration
                                                else {}
                                            ),
                                            project=project_name,
                                            region=region,
                                            arn=f"acs:log:{region}:{self.audited_account}:project/{project_name}/alert/{alert.name}",
                                        )
                                    )
                        except Exception as e:
                            logger.error(
                                f"{region} -- {e.__class__.__name__}[{e.__traceback__.tb_lineno}]: {e}"
                            )
            except Exception as error:
                logger.error(
                    f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_log_stores(self):
        for region in self.regional_clients:
            client = self.regional_clients[region]
            try:
                # List Projects
                list_project_request = sls_models.ListProjectRequest(offset=0, size=500)
                projects_resp = client.list_project(list_project_request)

                if projects_resp.body and projects_resp.body.projects:
                    for project in projects_resp.body.projects:
                        project_name = project.project_name

                        # List LogStores for each project
                        list_logstores_request = sls_models.ListLogStoresRequest(
                            offset=0, size=500
                        )
                        try:
                            logstores_resp = client.list_log_stores(
                                project_name, list_logstores_request
                            )
                            if logstores_resp.body and logstores_resp.body.logstores:
                                for logstore_name in logstores_resp.body.logstores:
                                    try:
                                        logstore_resp = client.get_log_store(
                                            project_name, logstore_name
                                        )
                                        if logstore_resp.body:
                                            self.log_stores.append(
                                                LogStore(
                                                    name=logstore_name,
                                                    project=project_name,
                                                    retention_forever=False,
                                                    retention_days=logstore_resp.body.ttl,
                                                    region=region,
                                                    arn=f"acs:log:{region}:{self.audited_account}:project/{project_name}/logstore/{logstore_name}",
                                                )
                                            )
                                    except Exception as e:
                                        logger.error(
                                            f"{region} -- {e.__class__.__name__}[{e.__traceback__.tb_lineno}]: {e}"
                                        )

                        except Exception as e:
                            logger.error(
                                f"{region} -- {e.__class__.__name__}[{e.__traceback__.tb_lineno}]: {e}"
                            )

            except Exception as error:
                logger.error(
                    f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
