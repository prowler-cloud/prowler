from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.lib.service.service import GCPService


################## Logging
class Logging(GCPService):
    def __init__(self, provider: GcpProvider):
        super().__init__(__class__.__name__, provider, api_version="v2")
        self.sinks = []
        self.metrics = []
        self.__get_sinks__()
        self.__get_metrics__()

    def __get_sinks__(self):
        for project_id in self.project_ids:
            try:
                request = self.client.sinks().list(parent=f"projects/{project_id}")
                while request is not None:
                    response = request.execute()

                    for sink in response.get("sinks", []):
                        self.sinks.append(
                            Sink(
                                name=sink["name"],
                                destination=sink["destination"],
                                filter=sink.get("filter", "all"),
                                project_id=project_id,
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
        for project_id in self.project_ids:
            try:
                request = (
                    self.client.projects()
                    .metrics()
                    .list(parent=f"projects/{project_id}")
                )
                while request is not None:
                    response = request.execute()

                    for metric in response.get("metrics", []):
                        self.metrics.append(
                            Metric(
                                name=metric["name"],
                                type=metric["metricDescriptor"]["type"],
                                filter=metric["filter"],
                                project_id=project_id,
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
    project_id: str


class Metric(BaseModel):
    name: str
    type: str
    filter: str
    project_id: str
