from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.gcp_provider import generate_client
from prowler.providers.gcp.services.compute.compute_client import compute_client


################## Dataproc
class Dataproc:
    def __init__(self, audit_info):
        self.service = "dataproc"
        self.api_version = "v1"
        self.project_id = audit_info.project_id
        self.client = generate_client(self.service, self.api_version, audit_info)
        self.clusters = []
        self.__get_clusters__()

    def __get_clusters__(self):
        try:
            for region in compute_client.regions:
                request = (
                    self.client.projects()
                    .regions()
                    .clusters()
                    .list(projectId=self.project_id, region=region)
                )
                while request is not None:
                    response = request.execute()

                    for cluster in response.get("clusters", []):
                        self.clusters.append(
                            Cluster(
                                name=cluster["clusterName"],
                                id=cluster["clusterUuid"],
                                encryption_config=cluster["config"]["encryptionConfig"],
                            )
                        )

                    request = (
                        self.client.projects()
                        .regions()
                        .clusters()
                        .list_next(previous_request=request, previous_response=response)
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Cluster(BaseModel):
    name: str
    id: str
    encryption_config: dict
