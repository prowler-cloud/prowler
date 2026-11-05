from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.e2enetworks.lib.service.service import E2eNetworksService


def _has_public_ip(public_ip_address: str | None) -> bool:
    if not public_ip_address:
        return False
    value = str(public_ip_address).strip()
    if not value or value.lower() in ("[]", "null", "none"):
        return False
    return True


class Database(E2eNetworksService):
    """Service class for E2E Networks DBaaS (RDS) resources."""

    def __init__(self, provider):
        super().__init__("database", provider)
        self.clusters: list[DatabaseCluster] = []
        self.instances: list[DatabaseInstance] = []
        self._fetch_clusters()

    def _fetch_clusters(self):
        for location in self.provider.session.locations:
            try:
                cluster_list = self.client.get_data("/rds/cluster/", location=location)
                if not isinstance(cluster_list, list):
                    continue

                for item in cluster_list:
                    cluster_id = str(item.get("id", ""))
                    detail = self._get_cluster_detail(cluster_id, location)
                    merged = {**item, **detail}

                    master_node = merged.get("master_node", {}) or {}
                    database_info = master_node.get("database", {}) or {}
                    software = (
                        merged.get("software", {})
                        or master_node.get("plan", {}).get("software", {})
                        or {}
                    )

                    cluster = DatabaseCluster(
                        id=cluster_id,
                        name=merged.get("name", ""),
                        location=location,
                        status=merged.get("status", ""),
                        software_name=software.get("name", ""),
                        software_version=software.get("version", ""),
                        backup_enabled=bool(merged.get("backup_enabled", False)),
                        whitelisted_ips=merged.get("whitelisted_ips", []) or [],
                        master_ssl_enabled=bool(master_node.get("ssl", False)),
                        master_public_ip=master_node.get("public_ip_address"),
                        master_username=database_info.get("username", ""),
                        master_has_public_ip=_has_public_ip(
                            master_node.get("public_ip_address")
                        ),
                    )
                    self.clusters.append(cluster)

                    self.instances.append(
                        DatabaseInstance(
                            id=str(master_node.get("instance_id", cluster_id)),
                            name=master_node.get("node_name", merged.get("name", "")),
                            cluster_id=cluster_id,
                            cluster_name=cluster.name,
                            location=location,
                            role="master",
                            public_ip_address=master_node.get("public_ip_address"),
                            has_public_ip=_has_public_ip(
                                master_node.get("public_ip_address")
                            ),
                            ssl_enabled=bool(master_node.get("ssl", False)),
                            username=database_info.get("username", ""),
                        )
                    )

                    for slave in merged.get("slave_nodes", []) or []:
                        if not isinstance(slave, dict):
                            continue
                        slave_db = slave.get("database", {}) or {}
                        self.instances.append(
                            DatabaseInstance(
                                id=str(slave.get("instance_id", "")),
                                name=slave.get("node_name", ""),
                                cluster_id=cluster_id,
                                cluster_name=cluster.name,
                                location=location,
                                role="replica",
                                public_ip_address=slave.get("public_ip_address"),
                                has_public_ip=_has_public_ip(
                                    slave.get("public_ip_address")
                                ),
                                ssl_enabled=bool(slave.get("ssl", False)),
                                username=slave_db.get("username", ""),
                            )
                        )
            except Exception as error:
                logger.error(
                    f"database - Error fetching clusters in {location} -- "
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_cluster_detail(self, cluster_id: str, location: str) -> dict:
        if not cluster_id:
            return {}
        try:
            data = self.client.get_data(
                f"/rds/cluster/{cluster_id}/",
                location=location,
            )
            return data if isinstance(data, dict) else {}
        except Exception as error:
            logger.error(
                f"database - Error fetching cluster detail {cluster_id} -- "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return {}


class DatabaseCluster(BaseModel):
    id: str
    name: str
    location: str
    status: str = ""
    software_name: str = ""
    software_version: str = ""
    backup_enabled: bool = False
    whitelisted_ips: list = []
    master_ssl_enabled: bool = False
    master_public_ip: str | None = None
    master_username: str = ""
    master_has_public_ip: bool = False

    @property
    def resource_id(self) -> str:
        return self.id

    @property
    def resource_name(self) -> str:
        return self.name


class DatabaseInstance(BaseModel):
    id: str
    name: str
    cluster_id: str
    cluster_name: str
    location: str
    role: str
    public_ip_address: str | None = None
    has_public_ip: bool = False
    ssl_enabled: bool = False
    username: str = ""

    @property
    def resource_id(self) -> str:
        return self.id

    @property
    def resource_name(self) -> str:
        return self.name
