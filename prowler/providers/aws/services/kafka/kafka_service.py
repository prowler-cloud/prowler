from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class Kafka(AWSService):
    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.account_arn_template = f"arn:{self.audited_partition}:kafka:{self.region}:{self.audited_account}:cluster"
        self.clusters = {}
        self.__threading_call__(self._list_clusters)
        self.kafka_versions = []
        self.__threading_call__(self._list_kafka_versions)

    def _list_clusters(self, regional_client):
        logger.info(f"Kafka - Listing clusters in region {regional_client.region}...")
        try:
            # Use list_clusters_v2 to support both provisioned and serverless clusters
            cluster_paginator = regional_client.get_paginator("list_clusters_v2")
            logger.info(
                f"Kafka - Paginator created for region {regional_client.region}"
            )

            for page in cluster_paginator.paginate():
                logger.info(
                    f"Kafka - Processing page with {len(page.get('ClusterInfoList', []))} clusters in region {regional_client.region}"
                )
                for cluster in page["ClusterInfoList"]:
                    logger.info(
                        f"Kafka - Found cluster: {cluster.get('ClusterName', 'Unknown')} in region {regional_client.region}"
                    )
                    arn = cluster.get(
                        "ClusterArn",
                        f"{self.account_arn_template}/{cluster.get('ClusterName', '')}",
                    )
                    cluster_type = cluster.get("ClusterType", "UNKNOWN")

                    if not self.audit_resources or is_resource_filtered(
                        arn, self.audit_resources
                    ):
                        # Handle provisioned clusters
                        if cluster_type == "PROVISIONED" and "Provisioned" in cluster:
                            provisioned = cluster["Provisioned"]
                            self.clusters[cluster.get("ClusterArn", "")] = Cluster(
                                id=arn.split(":")[-1].split("/")[-1],
                                name=cluster.get("ClusterName", ""),
                                arn=arn,
                                region=regional_client.region,
                                tags=(
                                    list(cluster.get("Tags", {}).values())
                                    if cluster.get("Tags")
                                    else []
                                ),
                                state=cluster.get("State", ""),
                                kafka_version=provisioned.get(
                                    "CurrentBrokerSoftwareInfo", {}
                                ).get("KafkaVersion", ""),
                                data_volume_kms_key_id=provisioned.get(
                                    "EncryptionInfo", {}
                                )
                                .get("EncryptionAtRest", {})
                                .get("DataVolumeKMSKeyId", ""),
                                encryption_in_transit=EncryptionInTransit(
                                    client_broker=provisioned.get("EncryptionInfo", {})
                                    .get("EncryptionInTransit", {})
                                    .get("ClientBroker", "PLAINTEXT"),
                                    in_cluster=provisioned.get("EncryptionInfo", {})
                                    .get("EncryptionInTransit", {})
                                    .get("InCluster", False),
                                ),
                                tls_authentication=provisioned.get(
                                    "ClientAuthentication", {}
                                )
                                .get("Tls", {})
                                .get("Enabled", False),
                                public_access=provisioned.get("BrokerNodeGroupInfo", {})
                                .get("ConnectivityInfo", {})
                                .get("PublicAccess", {})
                                .get("Type", "SERVICE_PROVIDED_EIPS")
                                != "DISABLED",
                                unauthentication_access=provisioned.get(
                                    "ClientAuthentication", {}
                                )
                                .get("Unauthenticated", {})
                                .get("Enabled", False),
                                enhanced_monitoring=provisioned.get(
                                    "EnhancedMonitoring", "DEFAULT"
                                ),
                            )
                            logger.info(
                                f"Kafka - Added provisioned cluster {cluster.get('ClusterName', 'Unknown')} to clusters dict"
                            )

                        # Handle serverless clusters
                        elif cluster_type == "SERVERLESS" and "Serverless" in cluster:
                            # For serverless clusters, encryption is always enabled by default
                            # We'll create a Cluster object with default encryption values
                            self.clusters[cluster.get("ClusterArn", "")] = Cluster(
                                id=arn.split(":")[-1].split("/")[-1],
                                name=cluster.get("ClusterName", ""),
                                arn=arn,
                                region=regional_client.region,
                                tags=(
                                    list(cluster.get("Tags", {}).values())
                                    if cluster.get("Tags")
                                    else []
                                ),
                                state=cluster.get("State", ""),
                                kafka_version="SERVERLESS",  # Serverless doesn't have specific Kafka version
                                data_volume_kms_key_id="AWS_MANAGED",  # Serverless uses AWS managed keys
                                encryption_in_transit=EncryptionInTransit(
                                    client_broker="TLS",  # Serverless always has TLS enabled
                                    in_cluster=True,  # Serverless always has in-cluster encryption
                                ),
                                tls_authentication=True,  # Serverless always has TLS authentication
                                public_access=False,  # Serverless clusters are always private
                                unauthentication_access=False,  # Serverless requires authentication
                                enhanced_monitoring="DEFAULT",
                            )
                            logger.info(
                                f"Kafka - Added serverless cluster {cluster.get('ClusterName', 'Unknown')} to clusters dict"
                            )

                        else:
                            logger.warning(
                                f"Kafka - Unknown cluster type {cluster_type} for cluster {cluster.get('ClusterName', 'Unknown')}"
                            )
                    else:
                        logger.info(
                            f"Kafka - Cluster {cluster.get('ClusterName', 'Unknown')} filtered out by audit_resources"
                        )

            logger.info(
                f"Kafka - Total clusters found in region {regional_client.region}: {len(self.clusters)}"
            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            logger.error(
                f"Kafka - Error details in region {regional_client.region}: {str(error)}"
            )

    def _list_kafka_versions(self, regional_client):
        try:
            kafka_versions_paginator = regional_client.get_paginator(
                "list_kafka_versions"
            )

            for page in kafka_versions_paginator.paginate():
                for version in page["KafkaVersions"]:
                    self.kafka_versions.append(
                        KafkaVersion(
                            version=version.get("Version", "UNKNOWN"),
                            status=version.get("Status", "UNKNOWN"),
                        )
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class EncryptionInTransit(BaseModel):
    client_broker: str
    in_cluster: bool


class Cluster(BaseModel):
    id: str
    name: str
    arn: str
    region: str
    tags: list
    kafka_version: str
    state: str
    data_volume_kms_key_id: str
    encryption_in_transit: EncryptionInTransit
    tls_authentication: bool
    public_access: bool
    unauthentication_access: bool
    enhanced_monitoring: str


class KafkaVersion(BaseModel):
    version: str
    status: str


class KafkaConnect(AWSService):
    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.connectors = {}
        self.__threading_call__(self._list_connectors)

    def _list_connectors(self, regional_client):
        try:
            connector_paginator = regional_client.get_paginator("list_connectors")

            for page in connector_paginator.paginate():
                for connector in page["connectors"]:
                    connector_arn = connector["connectorArn"]

                    if not self.audit_resources or is_resource_filtered(
                        connector_arn, self.audit_resources
                    ):
                        self.connectors[connector_arn] = Connector(
                            arn=connector_arn,
                            name=connector.get("connectorName", ""),
                            region=regional_client.region,
                            encryption_in_transit=connector.get(
                                "kafkaClusterEncryptionInTransit", {}
                            ).get("encryptionType", "PLAINTEXT"),
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Connector(BaseModel):
    name: str
    arn: str
    region: str
    encryption_in_transit: str
