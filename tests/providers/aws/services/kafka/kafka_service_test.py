from unittest.mock import patch

import botocore

from prowler.providers.aws.services.kafka.kafka_service import Kafka, KafkaConnect
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListClusters":
        return {
            "ClusterInfoList": [
                {
                    "BrokerNodeGroupInfo": {
                        "BrokerAZDistribution": "DEFAULT",
                        "ClientSubnets": ["subnet-cbfff283", "subnet-6746046b"],
                        "InstanceType": "kafka.m5.large",
                        "SecurityGroups": ["sg-f839b688"],
                        "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 100}},
                    },
                    "ClusterArn": f"arn:aws:kafka:{AWS_REGION_US_EAST_1}:123456789012:cluster/demo-cluster-1/6357e0b2-0e6a-4b86-a0b4-70df934c2e31-5",
                    "ClusterName": "demo-cluster-1",
                    "CreationTime": "2020-07-09T02:31:36.223000+00:00",
                    "CurrentBrokerSoftwareInfo": {"KafkaVersion": "2.2.1"},
                    "CurrentVersion": "K3AEGXETSR30VB",
                    "EncryptionInfo": {
                        "EncryptionAtRest": {
                            "DataVolumeKMSKeyId": f"arn:aws:kms:{AWS_REGION_US_EAST_1}:123456789012:key/a7ca56d5-0768-4b64-a670-339a9fbef81c"
                        },
                        "EncryptionInTransit": {
                            "ClientBroker": "TLS_PLAINTEXT",
                            "InCluster": True,
                        },
                    },
                    "ClientAuthentication": {
                        "Tls": {"CertificateAuthorityArnList": [], "Enabled": True},
                        "Unauthenticated": {"Enabled": False},
                    },
                    "EnhancedMonitoring": "DEFAULT",
                    "OpenMonitoring": {
                        "Prometheus": {
                            "JmxExporter": {"EnabledInBroker": False},
                            "NodeExporter": {"EnabledInBroker": False},
                        }
                    },
                    "NumberOfBrokerNodes": 2,
                    "State": "ACTIVE",
                    "Tags": {},
                    "ZookeeperConnectString": f"z-2.demo-cluster-1.xuy0sb.c5.kafka.{AWS_REGION_US_EAST_1}.amazonaws.com:2181,z-1.demo-cluster-1.xuy0sb.c5.kafka.{AWS_REGION_US_EAST_1}.amazonaws.com:2181,z-3.demo-cluster-1.xuy0sb.c5.kafka.{AWS_REGION_US_EAST_1}.amazonaws.com:2181",
                }
            ]
        }
    elif operation_name == "ListKafkaVersions":
        return {
            "KafkaVersions": [
                {"Version": "1.0.0", "Status": "DEPRECATED"},
                {"Version": "2.8.0", "Status": "ACTIVE"},
            ]
        }
    elif operation_name == "ListConnectors":
        return {
            "connectors": [
                {
                    "connectorName": "demo-connector",
                    "connectorArn": f"arn:aws:kafkaconnect:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:connector/demo-connector/058406e6-a8f7-4135-8860-d4786220a395-3",
                    "kafkaClusterEncryptionInTransit": {"encryptionType": "PLAINTEXT"},
                },
            ],
        }
    return make_api_call(self, operation_name, kwarg)


class TestKafkaService:
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_service(self):
        kafka = Kafka(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        # General assertions
        assert kafka.service == "kafka"
        assert kafka.__class__.__name__ == "Kafka"
        assert kafka.session.__class__.__name__ == "Session"
        assert kafka.audited_account == AWS_ACCOUNT_NUMBER
        # Clusters assertions
        assert len(kafka.clusters) == 1
        cluster_arn = f"arn:aws:kafka:{AWS_REGION_US_EAST_1}:123456789012:cluster/demo-cluster-1/6357e0b2-0e6a-4b86-a0b4-70df934c2e31-5"
        assert cluster_arn in kafka.clusters
        assert (
            kafka.clusters[cluster_arn].id == "6357e0b2-0e6a-4b86-a0b4-70df934c2e31-5"
        )
        assert kafka.clusters[cluster_arn].name == "demo-cluster-1"
        assert kafka.clusters[cluster_arn].region == AWS_REGION_US_EAST_1
        assert kafka.clusters[cluster_arn].tags == []
        assert kafka.clusters[cluster_arn].state == "ACTIVE"
        assert kafka.clusters[cluster_arn].kafka_version == "2.2.1"
        assert (
            kafka.clusters[cluster_arn].data_volume_kms_key_id
            == f"arn:aws:kms:{AWS_REGION_US_EAST_1}:123456789012:key/a7ca56d5-0768-4b64-a670-339a9fbef81c"
        )
        assert (
            kafka.clusters[cluster_arn].encryption_in_transit.client_broker
            == "TLS_PLAINTEXT"
        )
        assert kafka.clusters[cluster_arn].encryption_in_transit.in_cluster
        assert kafka.clusters[cluster_arn].enhanced_monitoring == "DEFAULT"
        assert kafka.clusters[cluster_arn].tls_authentication
        assert kafka.clusters[cluster_arn].public_access
        assert not kafka.clusters[cluster_arn].unauthentication_access
        # Kafka versions assertions
        assert len(kafka.kafka_versions) == 2
        assert kafka.kafka_versions[0].version == "1.0.0"
        assert kafka.kafka_versions[0].status == "DEPRECATED"
        assert kafka.kafka_versions[1].version == "2.8.0"
        assert kafka.kafka_versions[1].status == "ACTIVE"

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_list_connectors(self):
        kafka = KafkaConnect(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        assert len(kafka.connectors) == 1
        connector_arn = f"arn:aws:kafkaconnect:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:connector/demo-connector/058406e6-a8f7-4135-8860-d4786220a395-3"
        assert connector_arn in kafka.connectors
        assert kafka.connectors[connector_arn].name == "demo-connector"
        assert kafka.connectors[connector_arn].arn == connector_arn
        assert kafka.connectors[connector_arn].region == AWS_REGION_US_EAST_1
        assert kafka.connectors[connector_arn].encryption_in_transit == "PLAINTEXT"
