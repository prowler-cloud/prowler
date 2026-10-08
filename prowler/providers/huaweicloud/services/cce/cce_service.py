from typing import List

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


class CCE(HuaweiCloudService):
    """
    CCE (Cloud Container Engine) service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud CCE service
    to retrieve Kubernetes clusters and their security configuration.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)

        self.clusters: List[CCECluster] = []

        if self.session.is_mock:
            self._load_mock_data()
            return

        self._list_clusters()

    def _load_mock_data(self):
        """Load mock data for testing."""
        region = "la-south-2"
        self.clusters = [
            CCECluster(
                cluster_id="cce-mock-001",
                name="cluster-secure",
                status="Available",
                version="v1.28",
                has_public_endpoint=False,
                region=region,
            ),
            CCECluster(
                cluster_id="cce-mock-002",
                name="cluster-insecure",
                status="Available",
                version="v1.21",
                has_public_endpoint=True,
                region=region,
            ),
        ]

    def _list_clusters(self):
        """List all CCE clusters across regions."""
        if not self.regional_clients:
            return

        for region, client in self.regional_clients.items():
            logger.info(f"CCE - Listing Clusters in {region}...")

            try:
                from huaweicloudsdkcce.v3 import ListClustersRequest

                request = ListClustersRequest()
                response = self._call_with_retries(client.list_clusters, request)

                if response and response.items:
                    for cluster in response.items:
                        name = ""
                        cluster_id = ""
                        if cluster.metadata:
                            name = getattr(cluster.metadata, "name", "")
                            cluster_id = getattr(cluster.metadata, "uid", "")

                        version = ""
                        if cluster.spec:
                            version = getattr(cluster.spec, "version", "")

                        status = ""
                        if cluster.status:
                            status = getattr(cluster.status, "phase", "")

                        has_public = False
                        if cluster.status and cluster.status.endpoints:
                            for ep in cluster.status.endpoints:
                                ep_type = getattr(ep, "type", "")
                                ep_url = getattr(ep, "url", "")
                                if ep_type == "External" or "external" in str(
                                    ep_url or ""
                                ):
                                    has_public = True
                                    break

                        self.clusters.append(
                            CCECluster(
                                cluster_id=cluster_id,
                                name=name,
                                status=status,
                                version=version,
                                has_public_endpoint=has_public,
                                region=region,
                            )
                        )

            except Exception as error:
                logger.error(
                    f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class CCECluster(BaseModel):
    """CCE cluster model."""

    cluster_id: str
    name: str = ""
    status: str = ""
    version: str = ""
    has_public_endpoint: bool = False
    region: str = ""
