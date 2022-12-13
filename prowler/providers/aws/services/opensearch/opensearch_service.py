import threading
from json import loads

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################################ OpenSearch
class OpenSearchService:
    def __init__(self, audit_info):
        self.service = "opensearch"
        self.session = audit_info.audit_session
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.opensearch_domains = []
        self.__threading_call__(self.__list_domain_names__)
        self.__describe_domain_config__(self.regional_clients)
        self.__describe_domain__(self.regional_clients)

    def __get_session__(self):
        return self.session

    def __threading_call__(self, call):
        threads = []
        for regional_client in self.regional_clients.values():
            threads.append(threading.Thread(target=call, args=(regional_client,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def __list_domain_names__(self, regional_client):
        logger.info("OpenSearch - listing domain names...")
        try:
            domains = regional_client.list_domain_names()
            for domain in domains["DomainNames"]:
                self.opensearch_domains.append(
                    OpenSearchDomain(
                        name=domain["DomainName"], region=regional_client.region
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
                domain.access_policy = loads(
                    describe_domain["DomainConfig"]["AccessPolicies"]["Options"]
                )
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
                if "vpc" in describe_domain["DomainStatus"]["Endpoints"]:
                    domain.endpoint_vpc = describe_domain["DomainStatus"]["Endpoints"][
                        "vpc"
                    ]
                domain.vpc_id = describe_domain["DomainStatus"]["VPCOptions"]["VPCId"]
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
                domain.update_available = describe_domain["DomainStatus"][
                    "ServiceSoftwareOptions"
                ]["UpdateAvailable"]
                domain.version = describe_domain["DomainStatus"]["EngineVersion"]
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
    update_available: bool = None
    version: str = None
