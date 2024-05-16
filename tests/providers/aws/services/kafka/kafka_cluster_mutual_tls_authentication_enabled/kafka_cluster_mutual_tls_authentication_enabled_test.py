from unittest.mock import MagicMock, patch

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_kafka_cluster_mutual_tls_authentication_enabled:
    def test_kafka_no_clusters(self):
        kafka_client = MagicMock
        kafka_client.clusters = {}

        with patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), patch(
            "prowler.providers.aws.services.kafka.kafka_service.Kafka",
            new=kafka_client,
        ):
            from prowler.providers.aws.services.kafka.kafka_cluster_mutual_tls_authentication_enabled.kafka_cluster_mutual_tls_authentication_enabled import (
                kafka_cluster_mutual_tls_authentication_enabled,
            )

            check = kafka_cluster_mutual_tls_authentication_enabled()
            result = check.execute()

            assert len(result) == 0
