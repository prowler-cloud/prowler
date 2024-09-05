from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.lib.service.service import GCPService


################## GKE
class GKE(GCPService):
    def __init__(self, provider: GcpProvider):
        super().__init__("container", provider, api_version="v1beta1")
        self.locations = []
        self._get_locations()
        self.clusters = {}
        self.__threading_call__(self._get_clusters, self.locations)

    def _get_locations(self):
        for project_id in self.project_ids:
            try:
                request = (
                    self.client.projects()
                    .locations()
                    .list(parent="projects/" + project_id)
                )
                response = request.execute()

                for location in response["locations"]:
                    self.locations.append(
                        Location(name=location["name"], project_id=project_id)
                    )

            except Exception as error:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_clusters(self, location):
        try:
            request = (
                self.client.projects()
                .locations()
                .clusters()
                .list(
                    parent=f"projects/{location.project_id}/locations/{location.name}"
                )
            )
            response = request.execute(http=self.__get_AuthorizedHttp_client__())
            for cluster in response.get("clusters", []):
                node_pools = []
                for node_pool in cluster["nodePools"]:
                    node_pools.append(
                        NodePool(
                            name=node_pool["name"],
                            locations=node_pool["locations"],
                            service_account=node_pool["config"]["serviceAccount"],
                            project_id=location.project_id,
                        )
                    )
                self.clusters[cluster["id"]] = Cluster(
                    name=cluster["name"],
                    id=cluster["id"],
                    location=cluster["location"],
                    service_account=cluster["nodeConfig"]["serviceAccount"],
                    node_pools=node_pools,
                    project_id=location.project_id,
                )
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Location(BaseModel):
    name: str
    project_id: str


class NodePool(BaseModel):
    name: str
    locations: list
    service_account: str
    project_id: str


class Cluster(BaseModel):
    name: str
    id: str
    location: str
    service_account: str
    node_pools: list[NodePool]
    project_id: str
