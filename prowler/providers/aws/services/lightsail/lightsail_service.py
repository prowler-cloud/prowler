from typing import Dict, List

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class Lightsail(AWSService):
    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.instances = {}
        self.__threading_call__(self._get_instances)
        self.databases = {}
        self.__threading_call__(self._get_databases)
        self.static_ips = {}
        self.__threading_call__(self._get_static_ips)

    def _get_instances(self, regional_client):
        logger.info("Lightsail - Getting instances...")
        try:
            instance_paginator = regional_client.get_paginator("get_instances")
            for page in instance_paginator.paginate():
                for instance in page["instances"]:
                    arn = instance.get(
                        "arn",
                        f"arn:{self.audited_partition}:lightsail:{regional_client.region}:{self.audited_account}:Instance",
                    )

                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        ports = []

                        for port_range in instance.get("networking", {}).get(
                            "ports", []
                        ):
                            ports.append(
                                PortRange(
                                    range=(
                                        (
                                            port_range.get("fromPort", "")
                                            if port_range.get("fromPort", "")
                                            == port_range.get("toPort", "")
                                            else f"{port_range.get('fromPort', '')}-{port_range.get('toPort', '')}"
                                        )
                                        if port_range.get("fromPort", "")
                                        else ""
                                    ),
                                    protocol=port_range.get("protocol", ""),
                                    access_from=port_range.get("accessFrom", ""),
                                    access_type=port_range.get("accessType", ""),
                                )
                            )

                        auto_snapshot_enabled = False
                        for add_on in instance.get("addOns", []):
                            if (
                                add_on.get("name") == "AutoSnapshot"
                                and add_on.get("status") == "Enabled"
                            ):
                                auto_snapshot_enabled = True
                                break

                        self.instances[arn] = Instance(
                            name=instance.get("name", ""),
                            id=instance.get("supportCode", ""),
                            tags=instance.get("tags", []),
                            region=instance.get(
                                "location", {"regionName": regional_client.region}
                            ).get("regionName", ""),
                            availability_zone=instance.get("location", {}).get(
                                "availabilityZone", ""
                            ),
                            static_ip=instance.get("isStaticIp", True),
                            public_ip=instance.get("publicIpAddress", ""),
                            private_ip=instance.get("privateIpAddress", ""),
                            ipv6_addresses=instance.get("ipv6Addresses", []),
                            ip_address_type=instance.get("ipAddressType", "ipv4"),
                            ports=ports,
                            auto_snapshot=auto_snapshot_enabled,
                        )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_databases(self, regional_client):
        logger.info("Lightsail - Getting databases...")
        try:
            databases_paginator = regional_client.get_paginator(
                "get_relational_databases"
            )
            for page in databases_paginator.paginate():
                for database in page["relationalDatabases"]:
                    arn = database.get(
                        "arn",
                        f"arn:{self.audited_partition}:lightsail:{regional_client.region}:{self.audited_account}:RelationalDatabase",
                    )

                    if not self.audit_resources or is_resource_filtered(
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        self.databases[arn] = Database(
                            name=database.get("name", ""),
                            id=database.get("supportCode", ""),
                            tags=database.get("tags", []),
                            region=database.get(
                                "location", {"regionName": regional_client.region}
                            ).get("regionName", ""),
                            availability_zone=database.get("location", {}).get(
                                "availabilityZone", ""
                            ),
                            engine=database.get("engine", ""),
                            engine_version=database.get("engineVersion", ""),
                            status=database.get("state", "unknown"),
                            master_username=database.get("masterUsername", "admin"),
                            public_access=database.get("publiclyAccessible", True),
                        )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_static_ips(self, regional_client):
        logger.info("Lightsail - Getting static IPs...")
        try:
            static_ips_paginator = regional_client.get_paginator("get_static_ips")
            for page in static_ips_paginator.paginate():
                for static_ip in page["staticIps"]:
                    arn = static_ip.get(
                        "arn",
                        f"arn:{self.audited_partition}:lightsail:{regional_client.region}:{self.audited_account}:StaticIp",
                    )

                    if not self.audit_resources or is_resource_filtered(
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        self.static_ips[arn] = StaticIP(
                            name=static_ip.get("name", ""),
                            id=static_ip.get("supportCode", ""),
                            region=static_ip.get(
                                "location", {"regionName": regional_client.region}
                            ).get("regionName", ""),
                            availability_zone=static_ip.get("location", {}).get(
                                "availabilityZone", ""
                            ),
                            ip_address=static_ip.get("ipAddress", ""),
                            is_attached=static_ip.get("isAttached", True),
                            attached_to=static_ip.get("attachedTo", ""),
                        )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class PortRange(BaseModel):
    range: str
    protocol: str
    access_from: str
    access_type: str


class Instance(BaseModel):
    name: str
    id: str
    tags: List[Dict[str, str]]
    region: str
    availability_zone: str
    static_ip: bool
    public_ip: str
    private_ip: str
    ipv6_addresses: List[str]
    ip_address_type: str
    ports: List[PortRange]
    auto_snapshot: bool


class Database(BaseModel):
    name: str
    id: str
    tags: List[Dict[str, str]]
    region: str
    availability_zone: str
    engine: str
    engine_version: str
    status: str
    master_username: str
    public_access: bool


class StaticIP(BaseModel):
    name: str
    id: str
    region: str
    availability_zone: str
    ip_address: str
    is_attached: bool
    attached_to: str
