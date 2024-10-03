from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.lib.service.service import GCPService


################## Compute
class Compute(GCPService):
    def __init__(self, provider: GcpProvider):
        super().__init__(__class__.__name__, provider)
        self.regions = set()
        self.zones = set()
        self.instances = []
        self.networks = []
        self.subnets = []
        self.addresses = []
        self.firewalls = []
        self.projects = []
        self.load_balancers = []
        self._get_url_maps()
        self._describe_backend_service()
        self._get_regions()
        self._get_projects()
        self._get_zones()
        self.__threading_call__(self._get_instances, self.zones)
        self._get_networks()
        self.__threading_call__(self._get_subnetworks, self.regions)
        self._get_firewalls()
        self.__threading_call__(self._get_addresses, self.regions)

    def _get_regions(self):
        for project_id in self.project_ids:
            try:
                request = self.client.regions().list(project=project_id)
                while request is not None:
                    response = request.execute()

                    for region in response.get("items", []):
                        self.regions.add(region["name"])

                    request = self.client.regions().list_next(
                        previous_request=request, previous_response=response
                    )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_zones(self):
        for project_id in self.project_ids:
            try:
                request = self.client.zones().list(project=project_id)
                while request is not None:
                    response = request.execute()

                    for zone in response.get("items", []):
                        self.zones.add(zone["name"])

                    request = self.client.zones().list_next(
                        previous_request=request, previous_response=response
                    )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_projects(self):
        for project_id in self.project_ids:
            try:
                enable_oslogin = False
                response = self.client.projects().get(project=project_id).execute()
                for item in response["commonInstanceMetadata"].get("items", []):
                    if item["key"] == "enable-oslogin" and item["value"] == "TRUE":
                        enable_oslogin = True
                self.projects.append(
                    Project(id=project_id, enable_oslogin=enable_oslogin)
                )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_instances(self, zone):
        for project_id in self.project_ids:
            try:
                request = self.client.instances().list(project=project_id, zone=zone)
                while request is not None:
                    response = request.execute(
                        http=self.__get_AuthorizedHttp_client__()
                    )

                    for instance in response.get("items", []):
                        public_ip = False
                        for interface in instance.get("networkInterfaces", []):
                            for config in interface.get("accessConfigs", []):
                                if "natIP" in config:
                                    public_ip = True
                        self.instances.append(
                            Instance(
                                name=instance["name"],
                                id=instance["id"],
                                zone=zone,
                                public_ip=public_ip,
                                metadata=instance.get("metadata", {}),
                                shielded_enabled_vtpm=instance.get(
                                    "shieldedInstanceConfig", {}
                                ).get("enableVtpm", False),
                                shielded_enabled_integrity_monitoring=instance.get(
                                    "shieldedInstanceConfig", {}
                                ).get("enableIntegrityMonitoring", False),
                                confidential_computing=instance.get(
                                    "confidentialInstanceConfig", {}
                                ).get("enableConfidentialCompute", False),
                                service_accounts=instance.get("serviceAccounts", []),
                                ip_forward=instance.get("canIpForward", False),
                                disks_encryption=[
                                    (
                                        disk["deviceName"],
                                        (
                                            True
                                            if disk.get("diskEncryptionKey", {}).get(
                                                "sha256"
                                            )
                                            else False
                                        ),
                                    )
                                    for disk in instance.get("disks", [])
                                ],
                                project_id=project_id,
                            )
                        )

                    request = self.client.instances().list_next(
                        previous_request=request, previous_response=response
                    )
            except Exception as error:
                logger.error(
                    f"{zone} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_networks(self):
        for project_id in self.project_ids:
            try:
                request = self.client.networks().list(project=project_id)
                while request is not None:
                    response = request.execute()
                    for network in response.get("items", []):
                        subnet_mode = (
                            "legacy"
                            if "autoCreateSubnetworks" not in network
                            else (
                                "auto" if network["autoCreateSubnetworks"] else "custom"
                            )
                        )
                        self.networks.append(
                            Network(
                                name=network["name"],
                                id=network["id"],
                                subnet_mode=subnet_mode,
                                project_id=project_id,
                            )
                        )

                    request = self.client.networks().list_next(
                        previous_request=request, previous_response=response
                    )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_subnetworks(self, region):
        for project_id in self.project_ids:
            try:
                request = self.client.subnetworks().list(
                    project=project_id, region=region
                )
                while request is not None:
                    response = request.execute(
                        http=self.__get_AuthorizedHttp_client__()
                    )
                    for subnet in response.get("items", []):
                        self.subnets.append(
                            Subnet(
                                name=subnet["name"],
                                id=subnet["id"],
                                project_id=project_id,
                                flow_logs=subnet.get("enableFlowLogs", False),
                                network=subnet["network"].split("/")[-1],
                                region=region,
                            )
                        )

                    request = self.client.subnetworks().list_next(
                        previous_request=request, previous_response=response
                    )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_addresses(self, region):
        for project_id in self.project_ids:
            try:
                request = self.client.addresses().list(
                    project=project_id, region=region
                )
                while request is not None:
                    response = request.execute(
                        http=self.__get_AuthorizedHttp_client__()
                    )
                    for address in response.get("items", []):
                        self.addresses.append(
                            Address(
                                name=address["name"],
                                id=address["id"],
                                project_id=project_id,
                                type=address.get("addressType", "EXTERNAL"),
                                ip=address["address"],
                                region=region,
                            )
                        )

                    request = self.client.subnetworks().list_next(
                        previous_request=request, previous_response=response
                    )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_firewalls(self):
        for project_id in self.project_ids:
            try:
                request = self.client.firewalls().list(project=project_id)
                while request is not None:
                    response = request.execute()

                    for firewall in response.get("items", []):
                        self.firewalls.append(
                            Firewall(
                                name=firewall["name"],
                                id=firewall["id"],
                                source_ranges=firewall.get("sourceRanges", []),
                                direction=firewall["direction"],
                                allowed_rules=firewall.get("allowed", []),
                                project_id=project_id,
                            )
                        )

                    request = self.client.firewalls().list_next(
                        previous_request=request, previous_response=response
                    )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_url_maps(self):
        for project_id in self.project_ids:
            try:
                request = self.client.urlMaps().list(project=project_id)
                while request is not None:
                    response = request.execute()
                    for urlmap in response.get("items", []):
                        self.load_balancers.append(
                            LoadBalancer(
                                name=urlmap["name"],
                                id=urlmap["id"],
                                service=urlmap.get("defaultService", ""),
                                project_id=project_id,
                            )
                        )

                    request = self.client.urlMaps().list_next(
                        previous_request=request, previous_response=response
                    )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _describe_backend_service(self):
        for balancer in self.load_balancers:
            if balancer.service:
                try:
                    response = (
                        self.client.backendServices()
                        .get(
                            project=balancer.project_id,
                            backendService=balancer.service.split("/")[-1],
                        )
                        .execute()
                    )
                    balancer.logging = response.get("logConfig", {}).get(
                        "enable", False
                    )
                except Exception as error:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )


class Instance(BaseModel):
    name: str
    id: str
    zone: str
    public_ip: bool
    project_id: str
    metadata: dict
    shielded_enabled_vtpm: bool
    shielded_enabled_integrity_monitoring: bool
    confidential_computing: bool
    service_accounts: list
    ip_forward: bool
    disks_encryption: list


class Network(BaseModel):
    name: str
    id: str
    subnet_mode: str
    project_id: str


class Subnet(BaseModel):
    name: str
    id: str
    network: str
    project_id: str
    flow_logs: bool
    region: str


class Address(BaseModel):
    name: str
    id: str
    ip: str
    type: str
    project_id: str
    region: str


class Firewall(BaseModel):
    name: str
    id: str
    source_ranges: list
    direction: str
    allowed_rules: list
    project_id: str


class Project(BaseModel):
    id: str
    enable_oslogin: bool


class LoadBalancer(BaseModel):
    name: str
    id: str
    service: str
    logging: bool = False
    project_id: str
