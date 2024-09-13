from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.lib.service.service import GCPService


################## ServiceUsage
class ServiceUsage(GCPService):
    def __init__(self, provider: GcpProvider):
        super().__init__(__class__.__name__, provider)
        self.active_services = {}
        self._get_active_services()

    def _get_active_services(self):
        for project_id in self.project_ids:
            self.active_services[project_id] = []
            try:
                request = self.client.services().list(
                    parent="projects/" + project_id, filter="state:ENABLED"
                )
                while request is not None:
                    response = request.execute()
                    for service in response["services"]:
                        self.active_services[project_id].append(
                            Service(
                                name=service["name"].split("/")[-1],
                                title=service["config"]["title"],
                                project_id=project_id,
                            )
                        )

                    request = self.client.services().list_next(
                        previous_request=request, previous_response=response
                    )
            except Exception as error:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class Service(BaseModel):
    name: str
    title: str
    project_id: str
