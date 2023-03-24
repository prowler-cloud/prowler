from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.gcp_provider import generate_client


################## Logging
class Logging:
    def __init__(self, audit_info):
        self.service = "logging"
        self.api_version = "v2"
        self.region = "global"
        self.project_id = audit_info.project_id
        self.client = generate_client(self.service, self.api_version, audit_info)
        self.sinks = []
        self.metrics = []
        self.__get_sinks__()
        self.__get_metrics__()

    def __get_sinks__(self):
        try:
            request = self.client.sinks().list(parent=f"projects/{self.project_id}")
            while request is not None:
                response = request.execute()

                for sink in response.get("sinks", []):
                    self.sinks.append(
                        Sink(
                            name=sink["name"],
                            destination=sink["destination"],
                            filter=sink.get("filter", "all"),
                        )
                    )

                request = self.client.sinks().list_next(
                    previous_request=request, previous_response=response
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_metrics__(self):
        try:
            request = (
                self.client.projects()
                .metrics()
                .list(parent=f"projects/{self.project_id}")
            )
            while request is not None:
                response = request.execute()

                for metric in response.get("metrics", []):
                    self.metrics.append(
                        Metric(
                            name=metric["name"],
                            type=metric["metricDescriptor"]["type"],
                            filter=metric["filter"],
                        )
                    )

                request = (
                    self.client.projects()
                    .metrics()
                    .list_next(previous_request=request, previous_response=response)
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Sink(BaseModel):
    name: str
    destination: str
    filter: str


class Metric(BaseModel):
    name: str
    type: str
    filter: str
