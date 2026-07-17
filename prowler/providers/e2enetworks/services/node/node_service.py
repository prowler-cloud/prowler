from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.e2enetworks.lib.service.service import E2eNetworksService


def _has_public_ip(public_ip_address: str | None) -> bool:
    if not public_ip_address:
        return False
    value = str(public_ip_address).strip()
    if not value or value in ("[]", "null", "None"):
        return False
    return True


class Nodes(E2eNetworksService):
    """Service class for E2E Networks compute nodes."""

    def __init__(self, provider):
        super().__init__("node", provider)
        self.nodes: list[Node] = []
        self._fetch_nodes()

    def _fetch_nodes(self):
        for location in self.provider.session.locations:
            try:
                node_list = self.client.get_data("/nodes/", location=location)
                if not isinstance(node_list, list):
                    continue

                for item in node_list:
                    node_id = str(item.get("id", ""))
                    detail = self._get_node_detail(node_id, location)
                    merged = {**item, **detail}

                    self.nodes.append(
                        Node(
                            id=node_id,
                            name=merged.get("name", ""),
                            status=merged.get("status", ""),
                            location=location,
                            vm_id=str(merged.get("vm_id", merged.get("id", ""))),
                            public_ip_address=merged.get("public_ip_address"),
                            private_ip_address=merged.get("private_ip_address", ""),
                            is_accidental_protection=bool(
                                merged.get("is_accidental_protection", False)
                            ),
                            is_encryption_enabled=bool(
                                merged.get("isEncryptionEnabled", False)
                            ),
                            is_locked=bool(merged.get("is_locked", False)),
                            rescue_mode_status=merged.get(
                                "rescue_mode_status", "Disabled"
                            ),
                            is_node_compliance=bool(
                                merged.get("is_node_compliance", False)
                            ),
                            is_vpc_attached=bool(merged.get("is_vpc_attached", False)),
                            has_public_ip=_has_public_ip(
                                merged.get("public_ip_address")
                            ),
                        )
                    )
            except Exception as error:
                logger.error(
                    f"node - Error fetching nodes in {location} -- "
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_node_detail(self, node_id: str, location: str) -> dict:
        if not node_id:
            return {}
        try:
            data = self.client.get_data(
                f"/nodes/{node_id}/",
                location=location,
            )
            return data if isinstance(data, dict) else {}
        except Exception as error:
            logger.error(
                f"node - Error fetching node detail {node_id} -- "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return {}


class Node(BaseModel):
    id: str
    name: str
    status: str
    location: str
    vm_id: str
    public_ip_address: str | None = None
    private_ip_address: str = ""
    is_accidental_protection: bool = False
    is_encryption_enabled: bool = False
    is_locked: bool = False
    rescue_mode_status: str = "Disabled"
    is_node_compliance: bool = False
    is_vpc_attached: bool = False
    has_public_ip: bool = False

    @property
    def resource_id(self) -> str:
        return self.id

    @property
    def resource_name(self) -> str:
        return self.name
