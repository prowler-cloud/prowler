from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.lib.service.service import GCPService
from google.cloud import compute_v1


################## Compute
class Compute(GCPService):
    def __init__(self, audit_info):
        super().__init__(__class__.__name__, audit_info)
        self.regions = set()
        self.zones = set()
        self.instances = []
        self.networks = []
        self.subnets = []
        self.firewalls = []
        self.projects = []
        self.load_balancers = []
        self.__get_url_maps__()
        self.__describe_backend_service__()
        self.__get_regions__()
        self.__get_projects__()
        self.__get_zones__()
        self.__threading_call__(self.__get_instances__, self.zones)
        self.__get_networks__()
        self.__threading_call__(self.__get_subnetworks__, self.regions)
        self.__get_firewalls__()

    def __get_regions__(self):
        for project_id in self.project_ids:
            try:
                regions_client = compute_v1.RegionsClient()
                request = compute_v1.ListRegionsRequest(
                    project=project_id,
                )
                page_result = regions_client.list(request=request)
                for region in page_result:
                        self.regions.add(region.name)
                # request = self.client.regions().list(project=project_id)
                # while request is not None:
                #     response = request.execute()

                #     for region in response.get("items", []):
                #         self.regions.add(region["name"])

                #     request = self.client.regions().list_next(
                #         previous_request=request, previous_response=response
                #     )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def __get_zones__(self):
        for project_id in self.project_ids:
            try:
                zones_client = compute_v1.ZonesClient()
                request = compute_v1.ListZonesRequest(
                    project=project_id,
                )
                page_result = zones_client.list(request=request)
                for zone in page_result:
                        self.zones.add(zone.name)
                # request = self.client.zones().list(project=project_id)
                # while request is not None:
                #     response = request.execute()

                #     for zone in response.get("items", []):
                #         self.zones.add(zone["name"])

                #     request = self.client.zones().list_next(
                #         previous_request=request, previous_response=response
                #     )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def __get_projects__(self):
        for project_id in self.project_ids:
            try:
                enable_oslogin = False
                project_client = compute_v1.ProjectsClient()
                request = compute_v1.GetProjectRequest(project=project_id)
                response = project_client.get(request=request)
                for item in response.common_instance_metadata.items:
                    if item["key"] == "enable-oslogin" and item["value"] == "TRUE":
                        enable_oslogin = True
                # enable_oslogin = False
                # response = self.client.projects().get(project=project_id).execute()
                # for item in response["commonInstanceMetadata"].get("items", []):
                #     if item["key"] == "enable-oslogin" and item["value"] == "TRUE":
                #         enable_oslogin = True
                self.projects.append(
                    Project(id=project_id, enable_oslogin=enable_oslogin)
                )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def __get_instances__(self, zone):
        for project_id in self.project_ids:
            try:
                instances_client = compute_v1.InstancesClient()
                request = compute_v1.ListInstancesRequest(
                    project=project_id,
                    zone=zone,
                )
                page_result = instances_client.list(request=request)
                for instance in page_result:
                    public_ip = False
                    for interface in instance.network_interfaces:
                        for config in interface.access_configs:
                            if hasattr(config, "nat_i_p"):
                                public_ip = True
                        self.instances.append(
                            Instance(
                                name=instance.name,
                                id=instance.id,
                                zone=zone,
                                public_ip=public_ip,
                                metadata=instance.metadata,
                                shielded_enabled_vtpm=instance.shielded_instance_config.enable_vtpm,
                                shielded_enabled_integrity_monitoring=instance.shielded_instance_config.enable_integrity_monitoring,
                                confidential_computing=getattr(getattr(instance, "confidential_instance_config", None), "enable_confidential_compute", False),
                                service_accounts=getattr(instance, "service_accounts", []),
                                ip_forward=getattr(instance, "can_ip_forward", False),
                                disks_encryption=[
                                    (
                                        disk.device_name,
                                        True
                                        if getattr(getattr(disk, "disk_encryption_key", None), "sha256")
                                        else False,
                                    )
                                    for disk in instance.disks
                                ],
                                project_id=project_id,
                            )
                        )

                # request = self.client.instances().list(project=project_id, zone=zone)
                # while request is not None:
                #     response = request.execute(
                #         http=self.__get_AuthorizedHttp_client__()
                #     )

                #     for instance in response.get("items", []):
                #         public_ip = False
                #         for interface in instance["networkInterfaces"]:
                #             for config in interface.get("accessConfigs", []):
                #                 if "natIP" in config:
                #                     public_ip = True
                #         self.instances.append(
                #             Instance(
                #                 name=instance["name"],
                #                 id=instance["id"],
                #                 zone=zone,
                #                 public_ip=public_ip,
                #                 metadata=instance["metadata"],
                #                 shielded_enabled_vtpm=instance[
                #                     "shieldedInstanceConfig"
                #                 ]["enableVtpm"],
                #                 shielded_enabled_integrity_monitoring=instance[
                #                     "shieldedInstanceConfig"
                #                 ]["enableIntegrityMonitoring"],
                #                 confidential_computing=instance.get(
                #                     "confidentialInstanceConfig", {}
                #                 ).get("enableConfidentialCompute", False),
                #                 service_accounts=instance.get("serviceAccounts", []),
                #                 ip_forward=instance.get("canIpForward", False),
                #                 disks_encryption=[
                #                     (
                #                         disk["deviceName"],
                #                         True
                #                         if disk.get("diskEncryptionKey", {}).get(
                #                             "sha256"
                #                         )
                #                         else False,
                #                     )
                #                     for disk in instance["disks"]
                #                 ],
                #                 project_id=project_id,
                #             )
                #         )

                #     request = self.client.instances().list_next(
                #         previous_request=request, previous_response=response
                #     )
            except Exception as error:
                logger.error(
                    f"{zone} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def __get_networks__(self):
        for project_id in self.project_ids:
            try:
                networks_client = compute_v1.NetworksClient()
                request = compute_v1.ListNetworksRequest(
                    project=project_id,
                )
                page_result = networks_client.list(request=request)
                for network in page_result:
                    subnet_mode = (
                            "legacy"
                            if not hasattr(network, "auto_create_subnetworks")
                            else "auto"
                            if hasattr(network, "auto_create_subnetworks")
                            else "custom"
                        )
                    self.networks.append(
                            Network(
                                name=network.name,
                                id=network.id,
                                subnet_mode=subnet_mode,
                                project_id=project_id,
                            )
                        )
                # request = self.client.networks().list(project=project_id)
                # while request is not None:
                #     response = request.execute()
                #     for network in response.get("items", []):
                #         subnet_mode = (
                #             "legacy"
                #             if "autoCreateSubnetworks" not in network
                #             else "auto"
                #             if network["autoCreateSubnetworks"]
                #             else "custom"
                #         )
                #         self.networks.append(
                #             Network(
                #                 name=network["name"],
                #                 id=network["id"],
                #                 subnet_mode=subnet_mode,
                #                 project_id=project_id,
                #             )
                #         )

                #     request = self.client.networks().list_next(
                #         previous_request=request, previous_response=response
                #     )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def __get_subnetworks__(self, region):
        for project_id in self.project_ids:
            try:
                subnet_client = compute_v1.SubnetworksClient()
                request = compute_v1.ListSubnetworksRequest(
                    project=project_id,
                    region=region,
                )
                page_result = subnet_client.list(request=request)
                for subnet in page_result:
                    self.subnets.append(
                            Subnet(
                                name=subnet.name,
                                id=subnet.id,
                                project_id=project_id,
                                flow_logs=getattr(subnet,"enable_flow_logs", False),
                                network=subnet.network.split("/")[-1],
                                region=region,
                            )
                    )

                # request = self.client.subnetworks().list(
                #     project=project_id, region=region
                # )
                # while request is not None:
                #     response = request.execute(
                #         http=self.__get_AuthorizedHttp_client__()
                #     )
                #     for subnet in response.get("items", []):
                #         self.subnets.append(
                #             Subnet(
                #                 name=subnet["name"],
                #                 id=subnet["id"],
                #                 project_id=project_id,
                #                 flow_logs=subnet.get("enableFlowLogs", False),
                #                 network=subnet["network"].split("/")[-1],
                #                 #region=region,
                #             )
                #         )

                #     request = self.client.subnetworks().list_next(
                #         previous_request=request, previous_response=response
                #     )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def __get_firewalls__(self):
        for project_id in self.project_ids:
            try:
                firewall_client = compute_v1.FirewallsClient()
                request = compute_v1.ListFirewallsRequest(
                    project=project_id,
                )
                page_result = firewall_client.list(request=request)
                for firewall in page_result:
                    self.firewalls.append(
                            Firewall(
                                name=firewall.name,
                                id=firewall.id,
                                source_ranges=list(getattr(firewall, "source_ranges", [])),
                                direction=firewall.direction,
                                allowed_rules=list(getattr(firewall, "allowed", [])),
                                project_id=project_id,
                            )
                        )


                # request = self.client.firewalls().list(project=project_id)
                # while request is not None:
                #     response = request.execute()

                #     for firewall in response.get("items", []):
                #         self.firewalls.append(
                #             Firewall(
                #                 name=firewall["name"],
                #                 id=firewall["id"],
                #                 source_ranges=firewall.get("sourceRanges", []),
                #                 direction=firewall["direction"],
                #                 allowed_rules=firewall.get("allowed", []),
                #                 project_id=project_id,
                #             )
                #         )

                #     request = self.client.firewalls().list_next(
                #         previous_request=request, previous_response=response
                #     )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def __get_url_maps__(self):
        for project_id in self.project_ids:
            try:
                # Create a client
                url_maps_client = compute_v1.UrlMapsClient()
                request = compute_v1.ListUrlMapsRequest(
                    project=project_id,
                )
                page_result = url_maps_client.list(request=request)
                for urlmap in page_result:
                    self.load_balancers.append(
                            LoadBalancer(
                                name=urlmap.name,
                                id=urlmap.id,
                                service=getattr(urlmap, "default_service", ""),
                                project_id=project_id,
                            )
                        )


                # request = self.client.urlMaps().list(project=project_id)
                # while request is not None:
                #     response = request.execute()
                #     for urlmap in response.get("items", []):
                #         self.load_balancers.append(
                #             LoadBalancer(
                #                 name=urlmap["name"],
                #                 id=urlmap["id"],
                #                 service=urlmap.get("defaultService", ""),
                #                 project_id=project_id,
                #             )
                #         )

                #     request = self.client.urlMaps().list_next(
                #         previous_request=request, previous_response=response
                #     )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def __describe_backend_service__(self):
        for balancer in self.load_balancers:
            try:
                client = compute_v1.BackendServicesClient()
                request = compute_v1.GetBackendServiceRequest(
                    backend_service=balancer.service.split("/")[-1],
                    project=balancer.project_id,
                )
                response = client.get(request=request)
                balancer.logging = getattr(getattr(response, "log_config", None), "enable", False)
                # response = (
                #     self.client.backendServices()
                #     .get(
                #         project=balancer.project_id,
                #         backendService=balancer.service.split("/")[-1],
                #     )
                #     .execute()
                # )
                # balancer.logging = response.get("logConfig", {}).get("enable", False)
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
