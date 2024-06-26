from json import JSONDecodeError, loads
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################################ OpenSearch
class OpenSearchService(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__("opensearch", provider)
        self.opensearch_domains = []
        self.__threading_call__(self.__list_domain_names__)
        self.__describe_domain_config__(self.regional_clients)
        self.__describe_domain__(self.regional_clients)
        self.__list_tags__()

    def __list_domain_names__(self, regional_client):
        logger.info("OpenSearch - listing domain names...")
        try:
            domains = regional_client.list_domain_names()
            for domain in domains["DomainNames"]:
                arn = f"arn:{self.audited_partition}:opensearch:{regional_client.region}:{self.audited_account}:domain/{domain['DomainName']}"
                if not self.audit_resources or (
                    is_resource_filtered(arn, self.audit_resources)
                ):
                    self.opensearch_domains.append(
                        OpenSearchDomain(
                            arn=arn,
                            name=domain["DomainName"],
                            region=regional_client.region,
                        )
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_domain_config__(self, regional_clients):
        logger.info("OpenSearch - describing domain configurations...")
        try:
            for domain in self.opensearch_domains:
                regional_client = regional_clients[domain.region]
                describe_domain = regional_client.describe_domain_config(
                    DomainName=domain.name
                )
                for logging_key in [
                    "SEARCH_SLOW_LOGS",
                    "INDEX_SLOW_LOGS",
                    "AUDIT_LOGS",
                ]:
                    if (
                        logging_key
                        in describe_domain["DomainConfig"]["LogPublishingOptions"][
                            "Options"
                        ]
                    ):
                        domain.logging.append(
                            PublishingLoggingOption(
                                name=logging_key,
                                enabled=describe_domain["DomainConfig"][
                                    "LogPublishingOptions"
                                ]["Options"][logging_key]["Enabled"],
                            )
                        )
                try:
                    domain.access_policy = loads(
                        describe_domain["DomainConfig"]["AccessPolicies"]["Options"]
                    )
                except JSONDecodeError as error:
                    logger.warning(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                    continue

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_domain__(self, regional_clients):
        logger.info("OpenSearch - describing domain configurations...")
        try:
            for domain in self.opensearch_domains:
                regional_client = regional_clients[domain.region]
                describe_domain = regional_client.describe_domain(
                    DomainName=domain.name
                )
                domain.arn = describe_domain["DomainStatus"]["ARN"]
                domain.endpoint_vpc = None
                if "Endpoints" in describe_domain["DomainStatus"]:
                    if "vpc" in describe_domain["DomainStatus"]["Endpoints"]:
                        domain.endpoint_vpc = describe_domain["DomainStatus"][
                            "Endpoints"
                        ]["vpc"]
                domain.vpc_id = None
                if "VPCOptions" in describe_domain["DomainStatus"]:
                    domain.vpc_id = describe_domain["DomainStatus"]["VPCOptions"][
                        "VPCId"
                    ]
                domain.cognito_options = describe_domain["DomainStatus"][
                    "CognitoOptions"
                ]["Enabled"]
                domain.encryption_at_rest = describe_domain["DomainStatus"][
                    "EncryptionAtRestOptions"
                ]["Enabled"]
                domain.node_to_node_encryption = describe_domain["DomainStatus"][
                    "NodeToNodeEncryptionOptions"
                ]["Enabled"]
                domain.enforce_https = describe_domain["DomainStatus"][
                    "DomainEndpointOptions"
                ]["EnforceHTTPS"]
                domain.internal_user_database = describe_domain["DomainStatus"][
                    "AdvancedSecurityOptions"
                ]["InternalUserDatabaseEnabled"]
                domain.saml_enabled = (
                    describe_domain["DomainStatus"]["AdvancedSecurityOptions"]
                    .get("SAMLOptions", {})
                    .get("Enabled", False)
                )
                domain.update_available = describe_domain["DomainStatus"][
                    "ServiceSoftwareOptions"
                ]["UpdateAvailable"]
                domain.version = describe_domain["DomainStatus"]["EngineVersion"]
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_tags__(self):
        logger.info("OpenSearch - List Tags...")
        for domain in self.opensearch_domains:
            try:
                regional_client = self.regional_clients[domain.region]
                response = regional_client.list_tags(
                    ARN=domain.arn,
                )["TagList"]
                domain.tags = response
            except Exception as error:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class PublishingLoggingOption(BaseModel):
    name: str
    enabled: bool


class OpenSearchDomain(BaseModel):
    name: str
    region: str
    arn: str = None
    logging: list[PublishingLoggingOption] = []
    endpoint_vpc: str = None
    vpc_id: str = None
    access_policy: dict = None
    cognito_options: bool = None
    encryption_at_rest: bool = None
    node_to_node_encryption: bool = None
    enforce_https: bool = None
    internal_user_database: bool = None
    saml_enabled: bool = None
    update_available: bool = None
    version: str = None
    tags: Optional[list] = []
