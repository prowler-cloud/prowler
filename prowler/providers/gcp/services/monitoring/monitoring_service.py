import datetime

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.lib.service.service import GCPService


class Monitoring(GCPService):
    def __init__(self, provider: GcpProvider):
        super().__init__(__class__.__name__, provider, api_version="v3")
        self.alert_policies = []
        self.sa_keys_metrics = set()
        self._get_alert_policies()
        self._get_sa_keys_metrics(
            "iam.googleapis.com/service_account/key/authn_events_count"
        )

    def _get_alert_policies(self):
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

    def _get_sa_keys_metrics(self, metric_type):
        end_time = (
            datetime.datetime.now(datetime.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
        )
        start_time = (
            (
                datetime.datetime.now(datetime.timezone.utc)
                - datetime.timedelta(days=180)
            )
            .replace(microsecond=0)
            .isoformat()
        )
        for project_id in self.project_ids:
            try:
                request = (
                    self.client.projects()
                    .timeSeries()
                    .list(
                        name=f"projects/{project_id}",
                        filter=f'metric.type = "{metric_type}"',
                        interval_startTime=start_time,
                        interval_endTime=end_time,
                        view="HEADERS",
                    )
                )
                response = request.execute()

                for metric in response.get("timeSeries", []):
                    key_id = metric["metric"]["labels"].get("key_id")
                    if key_id:
                        self.sa_keys_metrics.add(key_id)

                # return self.sa_keys_metrics

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
