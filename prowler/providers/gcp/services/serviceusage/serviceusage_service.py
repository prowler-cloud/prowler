from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.gcp_provider import generate_client


################## ServiceUsage
class ServiceUsage:
    def __init__(self, audit_info):
        self.service = "serviceusage"
        self.api_version = "v1"
        self.region = "global"
        self.project_ids = audit_info.project_ids
        self.client = generate_client(self.service, self.api_version, audit_info)
        self.active_services = {}
        self.__get_active_services__()

    def __get_client__(self):
        return self.client

    def __get_active_services__(self):
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
