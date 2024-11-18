from unittest.mock import patch

import botocore
from boto3 import client

from prowler.providers.aws.services.kafka.kafka_service import KafkaConnect
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

orig = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListConnectors":
        return {
            "connectors": [
                {
                    "connectorName": "connector-plaintext",
                    "connectorArn": f"arn:aws:kafkaconnect:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:connector/connector-plaintext/058406e6-a8f7-4135-8860-d4786220a395-3",
                    "kafkaClusterEncryptionInTransit": {"encryptionType": "PLAINTEXT"},
                },
            ],
        }
    return orig(self, operation_name, kwarg)


def mock_make_api_call_v2(self, operation_name, kwarg):
    if operation_name == "ListConnectors":
        return {
            "connectors": [
                {
                    "connectorName": "connector-tls",
                    "connectorArn": f"arn:aws:kafkaconnect:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:connector/connector-tls/058406e6-a8f7-4135-8860-d4786220a395-3",
                    "kafkaClusterEncryptionInTransit": {"encryptionType": "TLS"},
                },
            ],
        }
    return orig(self, operation_name, kwarg)


class Test_kafka_connector_in_transit_encryption_enabled:
    def test_kafka_no_connector(self):

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), patch(
            "prowler.providers.aws.services.kafka.kafka_connector_in_transit_encryption_enabled.kafka_connector_in_transit_encryption_enabled.kafkaconnect_client",
            new=KafkaConnect(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.kafka.kafka_connector_in_transit_encryption_enabled.kafka_connector_in_transit_encryption_enabled import (
                kafka_connector_in_transit_encryption_enabled,
            )

            check = kafka_connector_in_transit_encryption_enabled()
            result = check.execute()

            assert len(result) == 0

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_kafka_cluster_not_using_in_transit_encryption(self):
        client("kafkaconnect", region_name=AWS_REGION_US_EAST_1)

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), patch(
            "prowler.providers.aws.services.kafka.kafka_connector_in_transit_encryption_enabled.kafka_connector_in_transit_encryption_enabled.kafkaconnect_client",
            new=KafkaConnect(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.kafka.kafka_connector_in_transit_encryption_enabled.kafka_connector_in_transit_encryption_enabled import (
                kafka_connector_in_transit_encryption_enabled,
            )

            check = kafka_connector_in_transit_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Kafka connector connector-plaintext does not have encryption in transit enabled."
            )
            assert result[0].resource_id == "connector-plaintext"
            assert (
                result[0].resource_arn
                == f"arn:aws:kafkaconnect:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:connector/connector-plaintext/058406e6-a8f7-4135-8860-d4786220a395-3"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call_v2)
    def test_kafka_cluster_using_in_transit_encryption(self):

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), patch(
            "prowler.providers.aws.services.kafka.kafka_connector_in_transit_encryption_enabled.kafka_connector_in_transit_encryption_enabled.kafkaconnect_client",
            new=KafkaConnect(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.kafka.kafka_connector_in_transit_encryption_enabled.kafka_connector_in_transit_encryption_enabled import (
                kafka_connector_in_transit_encryption_enabled,
            )

            check = kafka_connector_in_transit_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Kafka connector connector-tls has encryption in transit enabled."
            )
            assert result[0].resource_id == "connector-tls"
            assert (
                result[0].resource_arn
                == f"arn:aws:kafkaconnect:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:connector/connector-tls/058406e6-a8f7-4135-8860-d4786220a395-3"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []
