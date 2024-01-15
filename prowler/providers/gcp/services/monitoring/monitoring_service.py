from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.lib.service.service import GCPService


################## Monitoring
class Monitoring(GCPService):
    def __init__(self, provider):
        super().__init__(__class__.__name__, provider, api_version="v3")
        self.alert_policies = []
        self.__get_alert_policies__()

    def __get_alert_policies__(self):
        for project_id in self.project_ids:
            try:
                request = (
                    self.client.projects()
                    .alertPolicies()
                    .list(name=f"projects/{project_id}")
                )
                while request is not None:
                    response = request.execute()

                    for policy in response.get("alertPolicies", []):
                        filters = []
                        for condition in policy["conditions"]:
                            filters.append(condition["conditionThreshold"]["filter"])
                        self.alert_policies.append(
                            AlertPolicy(
                                name=policy["name"],
                                display_name=policy["displayName"],
                                enabled=policy["enabled"],
                                filters=filters,
                                project_id=project_id,
                            )
                        )

                    request = (
                        self.client.projects()
                        .alertPolicies()
                        .list_next(previous_request=request, previous_response=response)
                    )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class AlertPolicy(BaseModel):
    name: str
    display_name: str
    filters: list[str]
    enabled: bool
    project_id: str
