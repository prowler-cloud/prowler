from unittest.mock import MagicMock, patch

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_kafka_cluster_encryption_at_rest_uses_cmk:
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
            from prowler.providers.aws.services.kafka.kafka_cluster_encryption_at_rest_uses_cmk.kafka_cluster_encryption_at_rest_uses_cmk import (
                kafka_cluster_encryption_at_rest_uses_cmk,
            )

            check = kafka_cluster_encryption_at_rest_uses_cmk()
            result = check.execute()

            assert len(result) == 0
