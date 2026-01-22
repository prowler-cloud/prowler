from datetime import datetime
from typing import Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.config import DEFAULT_RETRY_ATTEMPTS
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.lib.service.service import GCPService


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
        self.compute_projects = []
        self.load_balancers = []
        self.instance_groups = []
        self.images = []
        self.snapshots = []
        self._get_regions()
        self._get_projects()
        self._get_url_maps()
        self._describe_backend_service()
        self._get_zones()
        self.__threading_call__(self._get_instances, self.zones)
        self._get_networks()
        self.__threading_call__(self._get_subnetworks, self.regions)
        self._get_firewalls()
        self.__threading_call__(self._get_addresses, self.regions)
        self.__threading_call__(self._get_regional_instance_groups, self.regions)
        self.__threading_call__(self._get_zonal_instance_groups, self.zones)
        self._associate_migs_with_load_balancers()
        self._get_images()
        self._get_snapshots()

    def _get_regions(self):
        for project_id in self.project_ids:
            try:
                request = self.client.regions().list(project=project_id)
                while request is not None:
                    response = request.execute(num_retries=DEFAULT_RETRY_ATTEMPTS)

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
                    response = request.execute(num_retries=DEFAULT_RETRY_ATTEMPTS)

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
                enable_oslogin_2fa = False
                response = (
                    self.client.projects()
                    .get(project=project_id)
                    .execute(num_retries=DEFAULT_RETRY_ATTEMPTS)
                )
                for item in response["commonInstanceMetadata"].get("items", []):
                    if item["key"] == "enable-oslogin" and item["value"] == "TRUE":
                        enable_oslogin = True
                    if item["key"] == "enable-oslogin-2fa" and item["value"] == "TRUE":
                        enable_oslogin_2fa = True
                self.compute_projects.append(
                    Project(
                        id=project_id,
                        enable_oslogin=enable_oslogin,
                        enable_oslogin_2fa=enable_oslogin_2fa,
                    )
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
                        http=self.__get_AuthorizedHttp_client__(),
                        num_retries=DEFAULT_RETRY_ATTEMPTS,
                    )

                    for instance in response.get("items", []):
                        public_ip = False
                        network_interfaces_raw = instance.get("networkInterfaces", [])

                        network_interfaces = []
                        for interface in network_interfaces_raw:
                            for config in interface.get("accessConfigs", []):
                                if "natIP" in config:
                                    public_ip = True

                            network_interfaces.append(
                                NetworkInterface(
                                    name=interface.get("name", ""),
                                    network=(
                                        interface.get("network", "").split("/")[-1]
                                        if interface.get("network")
                                        else ""
                                    ),
                                    subnetwork=(
                                        interface.get("subnetwork", "").split("/")[-1]
                                        if interface.get("subnetwork")
                                        else ""
                                    ),
                                )
                            )

                        self.instances.append(
                            Instance(
                                name=instance["name"],
                                id=instance["id"],
                                zone=zone,
                                region=zone.rsplit("-", 1)[0],
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
                                disks=[
                                    Disk(
                                        name=disk["deviceName"],
                                        auto_delete=disk.get("autoDelete", False),
                                        boot=disk.get("boot", False),
                                        encryption=bool(
                                            disk.get("diskEncryptionKey", {}).get(
                                                "sha256"
                                            )
                                        ),
                                    )
                                    for disk in instance.get("disks", [])
                                ],
                                automatic_restart=instance.get("scheduling", {}).get(
                                    "automaticRestart", False
                                ),
                                provisioning_model=instance.get("scheduling", {}).get(
                                    "provisioningModel", "STANDARD"
                                ),
                                project_id=project_id,
                                preemptible=instance.get("scheduling", {}).get(
                                    "preemptible", False
                                ),
                                deletion_protection=instance.get(
                                    "deletionProtection", False
                                ),
                                network_interfaces=network_interfaces,
                                on_host_maintenance=instance.get("scheduling", {}).get(
                                    "onHostMaintenance", "MIGRATE"
                                ),
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
                    response = request.execute(num_retries=DEFAULT_RETRY_ATTEMPTS)
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
                        http=self.__get_AuthorizedHttp_client__(),
                        num_retries=DEFAULT_RETRY_ATTEMPTS,
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
                        http=self.__get_AuthorizedHttp_client__(),
                        num_retries=DEFAULT_RETRY_ATTEMPTS,
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
                    response = request.execute(num_retries=DEFAULT_RETRY_ATTEMPTS)

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
                # Global URL maps
                request = self.client.urlMaps().list(project=project_id)
                while request is not None:
                    response = request.execute(num_retries=DEFAULT_RETRY_ATTEMPTS)
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
            try:
                # Regional URL maps
                for region in self.regions:
                    request = self.client.regionUrlMaps().list(
                        project=project_id, region=region
                    )
                    while request is not None:
                        response = request.execute(num_retries=DEFAULT_RETRY_ATTEMPTS)
                        for urlmap in response.get("items", []):
                            self.load_balancers.append(
                                LoadBalancer(
                                    name=urlmap["name"],
                                    id=urlmap["id"],
                                    service=urlmap.get("defaultService", ""),
                                    project_id=project_id,
                                )
                            )

                        request = self.client.regionUrlMaps().list_next(
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
                    backend_service_name = balancer.service.split("/")[-1]
                    is_regional = "/regions/" in balancer.service
                    if is_regional:
                        region = balancer.service.split("/regions/")[1].split("/")[0]
                        response = (
                            self.client.regionBackendServices()
                            .get(
                                project=balancer.project_id,
                                region=region,
                                backendService=backend_service_name,
                            )
                            .execute(num_retries=DEFAULT_RETRY_ATTEMPTS)
                        )
                    else:
                        response = (
                            self.client.backendServices()
                            .get(
                                project=balancer.project_id,
                                backendService=backend_service_name,
                            )
                            .execute(num_retries=DEFAULT_RETRY_ATTEMPTS)
                        )

                    balancer.logging = response.get("logConfig", {}).get(
                        "enable", False
                    )
                except Exception as error:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )

    def _get_regional_instance_groups(self, region: str) -> None:
        for project_id in self.project_ids:
            try:
                request = self.client.regionInstanceGroupManagers().list(
                    project=project_id, region=region
                )
                while request is not None:
                    response = request.execute(
                        http=self.__get_AuthorizedHttp_client__(),
                        num_retries=DEFAULT_RETRY_ATTEMPTS,
                    )

                    for mig in response.get("items", []):
                        zones = [
                            zone_info["zone"].split("/")[-1]
                            for zone_info in mig.get("distributionPolicy", {}).get(
                                "zones", []
                            )
                            if zone_info.get("zone")
                        ]

                        auto_healing_policies = [
                            AutoHealingPolicy(
                                health_check=(
                                    policy.get("healthCheck", "").split("/")[-1]
                                    if policy.get("healthCheck")
                                    else None
                                ),
                                initial_delay_sec=policy.get("initialDelaySec"),
                            )
                            for policy in mig.get("autoHealingPolicies", [])
                        ]

                        self.instance_groups.append(
                            ManagedInstanceGroup(
                                name=mig.get("name", ""),
                                id=mig.get("id", ""),
                                region=region,
                                zone=None,
                                zones=zones,
                                is_regional=True,
                                target_size=mig.get("targetSize", 0),
                                project_id=project_id,
                                auto_healing_policies=auto_healing_policies,
                            )
                        )

                    request = self.client.regionInstanceGroupManagers().list_next(
                        previous_request=request, previous_response=response
                    )
            except Exception as error:
                logger.error(
                    f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_zonal_instance_groups(self, zone: str) -> None:
        for project_id in self.project_ids:
            try:
                request = self.client.instanceGroupManagers().list(
                    project=project_id, zone=zone
                )
                while request is not None:
                    response = request.execute(
                        http=self.__get_AuthorizedHttp_client__(),
                        num_retries=DEFAULT_RETRY_ATTEMPTS,
                    )

                    for mig in response.get("items", []):
                        mig_zone = mig.get("zone", zone).split("/")[-1]
                        mig_region = mig_zone.rsplit("-", 1)[0]

                        auto_healing_policies = [
                            AutoHealingPolicy(
                                health_check=(
                                    policy.get("healthCheck", "").split("/")[-1]
                                    if policy.get("healthCheck")
                                    else None
                                ),
                                initial_delay_sec=policy.get("initialDelaySec"),
                            )
                            for policy in mig.get("autoHealingPolicies", [])
                        ]

                        self.instance_groups.append(
                            ManagedInstanceGroup(
                                name=mig.get("name", ""),
                                id=mig.get("id", ""),
                                region=mig_region,
                                zone=mig_zone,
                                zones=[mig_zone],
                                is_regional=False,
                                target_size=mig.get("targetSize", 0),
                                project_id=project_id,
                                auto_healing_policies=auto_healing_policies,
                            )
                        )

                    request = self.client.instanceGroupManagers().list_next(
                        previous_request=request, previous_response=response
                    )
            except Exception as error:
                logger.error(
                    f"{zone} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _associate_migs_with_load_balancers(self) -> None:
        load_balanced_groups = set()

        for project_id in self.project_ids:
            try:
                request = self.client.backendServices().list(project=project_id)
                while request is not None:
                    response = request.execute(num_retries=DEFAULT_RETRY_ATTEMPTS)
                    for backend_service in response.get("items", []):
                        for backend in backend_service.get("backends", []):
                            group_url = backend.get("group", "")
                            if group_url:
                                group_name = group_url.split("/")[-1]
                                load_balanced_groups.add((project_id, group_name))
                    request = self.client.backendServices().list_next(
                        previous_request=request, previous_response=response
                    )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

            for region in self.regions:
                try:
                    request = self.client.regionBackendServices().list(
                        project=project_id, region=region
                    )
                    while request is not None:
                        response = request.execute(num_retries=DEFAULT_RETRY_ATTEMPTS)
                        for backend_service in response.get("items", []):
                            for backend in backend_service.get("backends", []):
                                group_url = backend.get("group", "")
                                if group_url:
                                    group_name = group_url.split("/")[-1]
                                    load_balanced_groups.add((project_id, group_name))
                        request = self.client.regionBackendServices().list_next(
                            previous_request=request, previous_response=response
                        )
                except Exception as error:
                    logger.error(
                        f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )

        for mig in self.instance_groups:
            if (mig.project_id, mig.name) in load_balanced_groups:
                mig.load_balanced = True

    def _get_images(self) -> None:
        for project_id in self.project_ids:
            try:
                request = self.client.images().list(project=project_id)
                while request is not None:
                    response = request.execute(num_retries=DEFAULT_RETRY_ATTEMPTS)
                    for image in response.get("items", []):
                        publicly_shared = False
                        try:
                            iam_policy = (
                                self.client.images()
                                .getIamPolicy(
                                    project=project_id, resource=image["name"]
                                )
                                .execute(num_retries=DEFAULT_RETRY_ATTEMPTS)
                            )
                            for binding in iam_policy.get("bindings", []):
                                # allUsers cannot be assigned to Compute Engine images (API restriction).
                                # Only allAuthenticatedUsers can be set, which is the security risk.
                                if "allAuthenticatedUsers" in binding.get(
                                    "members", []
                                ):
                                    publicly_shared = True
                                    break
                        except Exception as error:
                            logger.error(
                                f"{project_id}/{image['name']} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                            )

                        self.images.append(
                            Image(
                                name=image["name"],
                                id=image["id"],
                                project_id=project_id,
                                publicly_shared=publicly_shared,
                            )
                        )

                    request = self.client.images().list_next(
                        previous_request=request, previous_response=response
                    )
            except Exception as error:
                logger.error(
                    f"{project_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_snapshots(self) -> None:
        for project_id in self.project_ids:
            try:
                request = self.client.snapshots().list(project=project_id)
                while request is not None:
                    response = request.execute(num_retries=DEFAULT_RETRY_ATTEMPTS)
                    for snapshot in response.get("items", []):
                        # Parse creation timestamp to datetime
                        creation_timestamp_str = snapshot.get("creationTimestamp", "")
                        creation_timestamp = None
                        if creation_timestamp_str:
                            try:
                                # GCP timestamps are in RFC 3339 format
                                creation_timestamp = datetime.fromisoformat(
                                    creation_timestamp_str.replace("Z", "+00:00")
                                )
                            except ValueError:
                                logger.error(
                                    f"Could not parse timestamp {creation_timestamp_str} for snapshot {snapshot['name']}"
                                )

                        # Extract source disk name from the full URL
                        source_disk_url = snapshot.get("sourceDisk", "")
                        source_disk = (
                            source_disk_url.split("/")[-1] if source_disk_url else ""
                        )

                        self.snapshots.append(
                            Snapshot(
                                name=snapshot["name"],
                                id=snapshot["id"],
                                project_id=project_id,
                                creation_timestamp=creation_timestamp,
                                source_disk=source_disk,
                                source_disk_id=snapshot.get("sourceDiskId"),
                                disk_size_gb=int(snapshot.get("diskSizeGb", 0)),
                                storage_bytes=int(snapshot.get("storageBytes", 0)),
                                storage_locations=snapshot.get("storageLocations", []),
                                status=snapshot.get("status", ""),
                                auto_created=snapshot.get("autoCreated", False),
                            )
                        )

                    request = self.client.snapshots().list_next(
                        previous_request=request, previous_response=response
                    )
            except Exception as error:
                logger.error(
                    f"{project_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class NetworkInterface(BaseModel):
    name: str
    network: str = ""
    subnetwork: str = ""


class Disk(BaseModel):
    name: str
    auto_delete: bool = False
    boot: bool
    encryption: bool = False


class Instance(BaseModel):
    name: str
    id: str
    zone: str
    region: str
    public_ip: bool
    project_id: str
    metadata: dict
    shielded_enabled_vtpm: bool
    shielded_enabled_integrity_monitoring: bool
    confidential_computing: bool
    service_accounts: list
    ip_forward: bool
    disks_encryption: list
    disks: list[Disk] = []
    automatic_restart: bool = False
    preemptible: bool = False
    provisioning_model: str = "STANDARD"
    deletion_protection: bool = False
    network_interfaces: list[NetworkInterface] = []
    on_host_maintenance: str = "MIGRATE"


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
    enable_oslogin_2fa: bool = False


class LoadBalancer(BaseModel):
    name: str
    id: str
    service: str
    logging: bool = False
    project_id: str


class AutoHealingPolicy(BaseModel):
    health_check: Optional[str] = None
    initial_delay_sec: Optional[int] = None


class ManagedInstanceGroup(BaseModel):
    name: str
    id: str
    region: str
    zone: Optional[str]
    zones: list
    is_regional: bool
    target_size: int
    project_id: str
    auto_healing_policies: list[AutoHealingPolicy] = []
    load_balanced: bool = False


class Image(BaseModel):
    name: str
    id: str
    project_id: str
    publicly_shared: bool = False


class Snapshot(BaseModel):
    name: str
    id: str
    project_id: str
    creation_timestamp: Optional[datetime] = None
    source_disk: str = ""
    source_disk_id: Optional[str] = None
    disk_size_gb: int = 0
    storage_bytes: int = 0
    storage_locations: list[str] = []
    status: str = ""
    auto_created: bool = False
