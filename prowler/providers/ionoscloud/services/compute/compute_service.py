from typing import List

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.ionoscloud.lib.service.service import IonosCloudService


class Compute(IonosCloudService):
    """
    IONOS Cloud Compute service.

    Fetches Virtual Data Centers (VDCs), their Servers, and the associated
    Network Interface Cards (NICs) so that checks can reason about network
    exposure.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.datacenters: List[DataCenter] = []
        self.servers: List[Server] = []
        self._list_datacenters()
        self.__threading_call__(self._list_servers, self.datacenters)

    # ------------------------------------------------------------------
    # Data-fetching helpers
    # ------------------------------------------------------------------

    def _list_datacenters(self):
        """Fetch all VDCs accessible to the authenticated account."""
        logger.info("Compute - Listing Data Centers ...")
        try:
            import ionoscloud

            dc_api = ionoscloud.DataCentersApi(self.api_client)
            response = dc_api.datacenters_get(depth=1)
            items = getattr(response, "items", []) or []

            for item in items:
                dc_id = getattr(item, "id", "") or ""
                props = getattr(item, "properties", None)
                if not props:
                    continue

                dc_name = getattr(props, "name", "") or ""
                location = getattr(props, "location", "") or ""
                description = getattr(props, "description", "") or ""

                if not self.audit_resources or is_resource_filtered(
                    dc_id, self.audit_resources
                ):
                    self.datacenters.append(
                        DataCenter(
                            id=dc_id,
                            name=dc_name,
                            location=location,
                            description=description,
                        )
                    )

        except Exception as error:
            body = getattr(error, "body", "") or ""
            if "318" in str(body):
                logger.warning(
                    "Compute - No IONOS Cloud contract for this account; "
                    "no Data Centers will be audited."
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _list_servers(self, datacenter: "DataCenter"):
        """Fetch all servers inside a single data center."""
        logger.info(
            f"Compute - Listing Servers in DataCenter {datacenter.name} ({datacenter.id}) ..."
        )
        try:
            import ionoscloud

            servers_api = ionoscloud.ServersApi(self.api_client)
            response = servers_api.datacenters_servers_get(
                datacenter_id=datacenter.id, depth=2
            )
            items = getattr(response, "items", []) or []

            for item in items:
                server_id = getattr(item, "id", "") or ""
                props = getattr(item, "properties", None)
                if not props:
                    continue

                server_name = getattr(props, "name", "") or ""
                vm_state = getattr(props, "vm_state", "") or ""
                cores = getattr(props, "cores", 0) or 0
                ram = getattr(props, "ram", 0) or 0

                # Extract NICs from the embedded entities
                nics: List[Nic] = []
                entities = getattr(item, "entities", None)
                if entities:
                    nics_container = getattr(entities, "nics", None)
                    if nics_container:
                        nic_items = getattr(nics_container, "items", []) or []
                        for nic_item in nic_items:
                            nic_id = getattr(nic_item, "id", "") or ""
                            nic_props = getattr(nic_item, "properties", None)
                            if not nic_props:
                                continue
                            nic_name = getattr(nic_props, "name", "") or ""
                            nic_ips = list(getattr(nic_props, "ips", []) or [])
                            lan_id = getattr(nic_props, "lan", None)
                            firewall_active = (
                                getattr(nic_props, "firewall_active", False) or False
                            )
                            nics.append(
                                Nic(
                                    id=nic_id,
                                    name=nic_name,
                                    ips=nic_ips,
                                    lan_id=str(lan_id) if lan_id is not None else "",
                                    firewall_active=firewall_active,
                                )
                            )

                if not self.audit_resources or is_resource_filtered(
                    server_id, self.audit_resources
                ):
                    self.servers.append(
                        Server(
                            id=server_id,
                            name=server_name,
                            datacenter_id=datacenter.id,
                            datacenter_name=datacenter.name,
                            location=datacenter.location,
                            vm_state=vm_state,
                            cores=cores,
                            ram=ram,
                            nics=nics,
                        )
                    )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


# ------------------------------------------------------------------
# Pydantic models
# ------------------------------------------------------------------


class Nic(BaseModel):
    """A Network Interface Card attached to a server."""

    id: str
    name: str
    ips: List[str] = []
    lan_id: str = ""
    firewall_active: bool = False


class Server(BaseModel):
    """An IONOS Cloud virtual server."""

    id: str
    name: str
    datacenter_id: str
    datacenter_name: str
    location: str
    vm_state: str = ""
    cores: int = 0
    ram: int = 0
    nics: List[Nic] = []

    class Config:
        frozen = True


class DataCenter(BaseModel):
    """An IONOS Cloud Virtual Data Center."""

    id: str
    name: str
    location: str
    description: str = ""

    class Config:
        frozen = True
