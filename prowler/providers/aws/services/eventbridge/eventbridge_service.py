import json
from typing import Optional

from botocore.exceptions import ClientError
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class EventBridge(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__("events", provider)
        self.buses = {}
        self.endpoints = {}
        self.__threading_call__(self._list_event_buses)
        self.__threading_call__(self._describe_event_bus)
        self.__threading_call__(self._list_endpoints)
        self._list_tags_for_resource()

    def _list_event_buses(self, regional_client):
        logger.info("EventBridge - Listing Event Buses...")
        try:
            next_token = None
            while True:
                params = {"NextToken": next_token} if next_token else {}
                page = regional_client.list_event_buses(**params)
                for bus in page["EventBuses"]:
                    bus_arn = bus["Arn"]
                    if not self.audit_resources or (
                        is_resource_filtered(bus_arn, self.audit_resources)
                    ):
                        self.buses[bus_arn] = Bus(
                            name=bus.get("Name", ""),
                            arn=bus_arn,
                            region=regional_client.region,
                        )
                next_token = page.get("NextToken")
                if not next_token:
                    break
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_event_bus(self, regional_client):
        logger.info("EventBridge - Describing Event Buses...")
        try:
            for bus in self.buses.values():
                if bus.region == regional_client.region:
                    try:
                        response = regional_client.describe_event_bus(Name=bus.name)
                        bus.kms_key_id = response.get("KmsKeyIdentifier")
                        bus.policy = json.loads(response.get("Policy", "{}"))
                    except Exception as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_endpoints(self, regional_client):
        logger.info("EventBridge - Listing Endpoints...")
        try:
            next_token = None
            while True:
                params = {"NextToken": next_token} if next_token else {}
                page = regional_client.list_endpoints(**params)
                for endpoint in page["Endpoints"]:
                    endpoint_arn = endpoint["Arn"]
                    if not self.audit_resources or (
                        is_resource_filtered(endpoint_arn, self.audit_resources)
                    ):
                        self.endpoints[endpoint_arn] = Endpoint(
                            name=endpoint.get("Name", ""),
                            arn=endpoint_arn,
                            region=regional_client.region,
                            replication_state=endpoint.get("ReplicationConfig", {}).get(
                                "State", "DISABLED"
                            ),
                        )
                next_token = page.get("NextToken")
                if not next_token:
                    break
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags_for_resource(self):
        logger.info("EventBridge - Listing Tags...")
        try:
            for bus in self.buses.values():
                try:
                    regional_client = self.regional_clients[bus.region]
                    bus.tags = regional_client.list_tags_for_resource(
                        ResourceARN=bus.arn
                    )["Tags"]
                except ClientError as error:
                    if error.response["Error"]["Code"] == "ResourceNotFoundException":
                        logger.warning(
                            f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                    else:
                        logger.error(
                            f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                except Exception as error:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Bus(BaseModel):
    name: str
    arn: str
    region: str
    kms_key_id: Optional[str]
    policy: Optional[str]
    tags: Optional[list]


class Endpoint(BaseModel):
    name: str
    arn: str
    region: str
    replication_state: str
    tags: Optional[list] = []


class Schema(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__("schemas", provider)
        self.registries = {}
        self.__threading_call__(self._list_registries)
        self.__threading_call__(self._get_resource_policy)

    def _list_registries(self, regional_client):
        logger.info("EventBridge - Listing Schema Registries...")
        try:
            list_registries_paginator = regional_client.get_paginator(
                "list_registries",
            )
            for page in list_registries_paginator.paginate():
                for registry in page["Registries"]:
                    registry_arn = registry.get(
                        "RegistryArn",
                        f"arn:{self.audited_partition}:schemas:{regional_client.region}:{self.audited_account}:registry/{registry.get('RegistryName', '')}",
                    )
                    if not self.audit_resources or (
                        is_resource_filtered(registry_arn, self.audit_resources)
                    ):
                        self.registries[registry_arn] = Registry(
                            name=registry.get("RegistryName", ""),
                            arn=registry_arn,
                            region=regional_client.region,
                            tags=[registry["Tags"]],
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_resource_policy(self, regional_client):
        logger.info("EventBridge - Getting Registry Resource Policy...")
        try:
            for registry in self.registries.values():
                # Only get the policy for the registry in the same region and not AWS owned
                if (
                    registry.region == regional_client.region
                    and not registry.name.startswith("aws.")
                ):
                    try:
                        response = regional_client.get_resource_policy(
                            RegistryName=registry.name
                        )
                        registry.policy = json.loads(response.get("Policy", "{}"))
                    except ClientError as error:
                        if error.response["Error"]["Code"] == "NotFoundException":
                            logger.warning(
                                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                            )
                        else:
                            logger.error(
                                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                            )
                    except Exception as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Registry(BaseModel):
    name: str
    arn: str
    region: str
    policy: Optional[dict]
    tags: Optional[list]
