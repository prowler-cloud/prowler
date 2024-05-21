from unittest.mock import MagicMock, patch

from prowler.providers.aws.services.kafka.kafka_service import (
    Cluster,
    EncryptionInTransit,
    KafkaVersion,
)
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_kafka_cluster_latest_version:
    def test_kafka_no_clusters(self):
        kafka_client = MagicMock
        kafka_client.clusters = {}

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), patch(
            "prowler.providers.aws.services.kafka.kafka_service.Kafka",
            new=kafka_client,
        ):
            from prowler.providers.aws.services.kafka.kafka_cluster_uses_latest_version.kafka_cluster_uses_latest_version import (
                kafka_cluster_uses_latest_version,
            )

            check = kafka_cluster_uses_latest_version()
            result = check.execute()

            assert len(result) == 0

    def test_kafka_cluster_not_using_latest_version(self):
        kafka_client = MagicMock
        kafka_client.clusters = {
            "arn:aws:kafka:us-east-1:123456789012:cluster/demo-cluster-1/6357e0b2-0e6a-4b86-a0b4-70df934c2e31-5": Cluster(
                id="6357e0b2-0e6a-4b86-a0b4-70df934c2e31-5",
                name="demo-cluster-1",
                region=AWS_REGION_US_EAST_1,
                tags=[],
                state="ACTIVE",
                kafka_version="2.2.1",
                data_volume_kms_key_id=f"arn:aws:kms:{AWS_REGION_US_EAST_1}:123456789012:key/a7ca56d5-0768-4b64-a670-339a9fbef81c",
                encryption_in_transit=EncryptionInTransit(
                    client_broker="TLS_PLAINTEXT",
                    in_cluster=True,
                ),
                tls_authentication=True,
                public_access=True,
                unauthentication_access=False,
                enhanced_monitoring="DEFAULT",
            )
        }

        kafka_client.kafka_versions = [
            KafkaVersion(version="1.0.0", status="DEPRECATED"),
            KafkaVersion(version="2.8.0", status="ACTIVE"),
        ]

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), patch(
            "prowler.providers.aws.services.kafka.kafka_service.Kafka",
            new=kafka_client,
        ):
            from prowler.providers.aws.services.kafka.kafka_cluster_uses_latest_version.kafka_cluster_uses_latest_version import (
                kafka_cluster_uses_latest_version,
            )

            check = kafka_cluster_uses_latest_version()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Kafka cluster 'demo-cluster-1' is not using the latest version."
            )
            assert result[0].resource_id == "6357e0b2-0e6a-4b86-a0b4-70df934c2e31-5"
            assert (
                result[0].resource_arn
                == "arn:aws:kafka:us-east-1:123456789012:cluster/demo-cluster-1/6357e0b2-0e6a-4b86-a0b4-70df934c2e31-5"
            )
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1

    def test_kafka_cluster_using_latest_version_pass(self):
        kafka_client = MagicMock
        kafka_client.clusters = {
            "arn:aws:kafka:us-east-1:123456789012:cluster/demo-cluster-1/6357e0b2-0e6a-4b86-a0b4-70df934c2e31-5": Cluster(
                id="6357e0b2-0e6a-4b86-a0b4-70df934c2e31-5",
                name="demo-cluster-1",
                region=AWS_REGION_US_EAST_1,
                tags=[],
                state="ACTIVE",
                kafka_version="2.8.0",
                data_volume_kms_key_id=f"arn:aws:kms:{AWS_REGION_US_EAST_1}:123456789012:key/a7ca56d5-0768-4b64-a670-339a9fbef81c",
                encryption_in_transit=EncryptionInTransit(
                    client_broker="TLS_PLAINTEXT",
                    in_cluster=True,
                ),
                tls_authentication=True,
                public_access=True,
                unauthentication_access=False,
                enhanced_monitoring="DEFAULT",
            )
        }

        kafka_client.kafka_versions = [
            KafkaVersion(version="1.0.0", status="DEPRECATED"),
            KafkaVersion(version="2.8.0", status="ACTIVE"),
        ]

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), patch(
            "prowler.providers.aws.services.kafka.kafka_service.Kafka",
            new=kafka_client,
        ):
            from prowler.providers.aws.services.kafka.kafka_cluster_uses_latest_version.kafka_cluster_uses_latest_version import (
                kafka_cluster_uses_latest_version,
            )

            check = kafka_cluster_uses_latest_version()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Kafka cluster 'demo-cluster-1' is using the latest version."
            )
            assert result[0].resource_id == "6357e0b2-0e6a-4b86-a0b4-70df934c2e31-5"
            assert (
                result[0].resource_arn
                == "arn:aws:kafka:us-east-1:123456789012:cluster/demo-cluster-1/6357e0b2-0e6a-4b86-a0b4-70df934c2e31-5"
            )
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1
