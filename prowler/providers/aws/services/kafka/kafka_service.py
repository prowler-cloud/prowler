from pydantic import BaseModel

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
        try:
            cluster_paginator = regional_client.get_paginator("list_clusters")

            for page in cluster_paginator.paginate():
                for cluster in page["ClusterInfoList"]:
                    arn = cluster.get(
                        "ClusterArn",
                        f"{self.account_arn_template}/{cluster.get('ClusterName', '')}",
                    )

                    if not self.audit_resources or is_resource_filtered(
                        arn, self.audit_resources
                    ):
                        self.clusters[cluster.get("ClusterArn", "")] = Cluster(
                            id=arn.split(":")[-1].split("/")[-1],
                            name=cluster.get("ClusterName", ""),
                            region=regional_client.region,
                            tags=list(cluster.get("Tags", {})),
                            state=cluster.get("State", ""),
                            kafka_version=cluster.get(
                                "CurrentBrokerSoftwareInfo", {}
                            ).get("KafkaVersion", ""),
                            data_volume_kms_key_id=cluster.get("EncryptionInfo", {})
                            .get("EncryptionAtRest", {})
                            .get("DataVolumeKMSKeyId", ""),
                            encryption_in_transit=EncryptionInTransit(
                                client_broker=cluster.get("EncryptionInfo", {})
                                .get("EncryptionInTransit", {})
                                .get("ClientBroker", "PLAINTEXT"),
                                in_cluster=cluster.get("EncryptionInfo", {})
                                .get("EncryptionInTransit", {})
                                .get("InCluster", False),
                            ),
                            tls_authentication=cluster.get("ClientAuthentication", {})
                            .get("Tls", {})
                            .get("Enabled", False),
                            public_access=cluster.get("BrokerNodeGroupInfo", {})
                            .get("ConnectivityInfo", {})
                            .get("PublicAccess", {})
                            .get("Type", "SERVICE_PROVIDED_EIPS")
                            != "DISABLED",
                            unauthentication_access=cluster.get(
                                "ClientAuthentication", {}
                            )
                            .get("Unauthenticated", {})
                            .get("Enabled", False),
                            enhanced_monitoring=cluster.get(
                                "EnhancedMonitoring", "DEFAULT"
                            ),
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
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
