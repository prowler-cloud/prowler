import threading

import google_auth_httplib2
import httplib2
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.lib.service.service import GCPService
from prowler.providers.gcp.services.compute.compute_client import compute_client


################## Dataproc
class Dataproc(GCPService):
    def __init__(self, audit_info):
        super().__init__(__class__.__name__, audit_info)
        self.credentials = audit_info.credentials
        self.clusters = []
        self.__threading_call__(self.__get_clusters__)

    def __threading_call__(self, call):
        threads = []
        for region in compute_client.regions:
            threads.append(threading.Thread(target=call, args=(region,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def __get_clusters__(self, region):
        for project_id in self.project_ids:
            try:
                request = (
                    self.client.projects()
                    .regions()
                    .clusters()
                    .list(projectId=project_id, region=region)
                )
                http = google_auth_httplib2.AuthorizedHttp(
                    self.credentials, http=httplib2.Http()
                )
                while request is not None:
                    response = request.execute(http=http)

                    for cluster in response.get("clusters", []):
                        self.clusters.append(
                            Cluster(
                                name=cluster["clusterName"],
                                id=cluster["clusterUuid"],
                                encryption_config=cluster["config"]["encryptionConfig"],
                                project_id=project_id,
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
    project_id: str
