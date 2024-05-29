import json
from typing import Optional

from botocore.exceptions import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################################ EventBridge
class EventBridge(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__("events", provider)
        self.buses = {}
        self.__threading_call__(self.__list_event_buses__)
        self.__threading_call__(self.__describe_event_bus__)
        self.__list_tags_for_resource__()

    def __list_event_buses__(self, regional_client):
        logger.info("EventBridge - Listing Event Buses...")
        try:
            for bus in regional_client.list_event_buses()["EventBuses"]:
                bus_arn = bus["Arn"]
                if not self.audit_resources or (
                    is_resource_filtered(bus_arn, self.audit_resources)
                ):
                    self.buses[bus_arn] = Bus(
                        name=bus.get("Name", ""),
                        arn=bus_arn,
                        region=regional_client.region,
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_event_bus__(self, regional_client):
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

    def __list_tags_for_resource__(self):
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


################################ Schema
class Schema(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__("schemas", provider)
        self.registries = {}
        self.__threading_call__(self.__list_registries__)
        self.__threading_call__(self.__get_resource_policy__)

    def __list_registries__(self, regional_client):
        logger.info("EventBridge - Listing Schema Registries...")
        try:
            for registry in regional_client.list_registries()["Registries"]:
                registry_arn = registry.get(
                    "RegistryArn",
                    f"arn:aws:schemas:{regional_client.region}:{self.audited_account}:registry/{registry.get('RegistryName', '')}",
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

    def __get_resource_policy__(self, regional_client):
        logger.info("EventBridge - Describing Event Buses...")
        try:
            for registry in self.registries.values():
                if registry.region == regional_client.region:
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
