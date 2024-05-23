from unittest.mock import MagicMock, patch

from prowler.providers.aws.services.kafka.kafka_service import (
    Cluster,
    EncryptionInTransit,
)
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_kafka_cluster_is_public:
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
            from prowler.providers.aws.services.kafka.kafka_cluster_is_public.kafka_cluster_is_public import (
                kafka_cluster_is_public,
            )

            check = kafka_cluster_is_public()
            result = check.execute()

            assert len(result) == 0

    def test_kafka_cluster_not_public(self):
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
                    client_broker="PLAINTEXT",
                    in_cluster=True,
                ),
                tls_authentication=True,
                public_access=False,
                unauthentication_access=False,
                enhanced_monitoring="DEFAULT",
            )
        }

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), patch(
            "prowler.providers.aws.services.kafka.kafka_service.Kafka",
            new=kafka_client,
        ):
            from prowler.providers.aws.services.kafka.kafka_cluster_is_public.kafka_cluster_is_public import (
                kafka_cluster_is_public,
            )

            check = kafka_cluster_is_public()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Kafka cluster 'demo-cluster-1' is publicly accessible."
            )
            assert (
                result[0].resource_arn
                == "arn:aws:kafka:us-east-1:123456789012:cluster/demo-cluster-1/6357e0b2-0e6a-4b86-a0b4-70df934c2e31-5"
            )
            assert result[0].resource_id == "6357e0b2-0e6a-4b86-a0b4-70df934c2e31-5"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    def test_kafka_cluster_public(self):
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
                    client_broker="PLAINTEXT",
                    in_cluster=True,
                ),
                tls_authentication=True,
                public_access=True,
                unauthentication_access=False,
                enhanced_monitoring="DEFAULT",
            )
        }

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), patch(
            "prowler.providers.aws.services.kafka.kafka_service.Kafka",
            new=kafka_client,
        ):
            from prowler.providers.aws.services.kafka.kafka_cluster_is_public.kafka_cluster_is_public import (
                kafka_cluster_is_public,
            )

            check = kafka_cluster_is_public()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Kafka cluster 'demo-cluster-1' is not publicly accessible."
            )
            assert (
                result[0].resource_arn
                == "arn:aws:kafka:us-east-1:123456789012:cluster/demo-cluster-1/6357e0b2-0e6a-4b86-a0b4-70df934c2e31-5"
            )
            assert result[0].resource_id == "6357e0b2-0e6a-4b86-a0b4-70df934c2e31-5"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []
