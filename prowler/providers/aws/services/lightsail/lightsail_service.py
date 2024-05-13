from typing import Dict, List

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.lib.service.service import AWSService


class Lightsail(AWSService):
    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.instances = {}
        self.__threading_call__(self.__get_instances__)
        self.databases = {}
        self.__threading_call__(self.__get_databases__)

    def __get_instances__(self, regional_client):
        logger.info("Lightsail - Getting instances...")
        try:
            instance_paginator = regional_client.get_paginator("get_instances")
            for page in instance_paginator.paginate():
                for instance in page["instances"]:
                    ports = []

                    for port_range in instance.get("networking", {}).get("ports", []):
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

                    self.instances[
                        instance.get(
                            "arn",
                            f"arn:{self.audited_partition}:lightsail:{regional_client.region}:{self.audited_account}:Instance",
                        )
                    ] = Instance(
                        name=instance.get("name", ""),
                        tags=instance.get("tags", []),
                        location=instance.get("location", regional_client.region),
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

    def __get_databases__(self, regional_client):
        logger.info("Lightsail - Getting databases...")
        try:
            databases_paginator = regional_client.get_paginator(
                "get_relational_databases"
            )
            for page in databases_paginator.paginate():
                for database in page["relationalDatabases"]:
                    self.databases[
                        database.get(
                            "arn",
                            f"arn:{self.audited_partition}:lightsail:{regional_client.region}:{self.audited_account}:RelationalDatabase",
                        )
                    ] = Database(
                        name=database.get("name", ""),
                        tags=database.get("tags", []),
                        location=database.get("location", regional_client.region),
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


class PortRange(BaseModel):
    range: str
    protocol: str
    access_from: str
    access_type: str


class Instance(BaseModel):
    name: str
    tags: List[Dict[str, str]]
    location: dict
    static_ip: bool
    public_ip: str
    private_ip: str
    ipv6_addresses: List[str]
    ip_address_type: str
    ports: List[PortRange]
    auto_snapshot: bool


class Database(BaseModel):
    name: str
    tags: List[Dict[str, str]]
    location: dict
    engine: str
    engine_version: str
    status: str
    master_username: str
    public_access: bool
