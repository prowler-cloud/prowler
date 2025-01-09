from prowler.providers.aws.services.kafka.kafka_service import KafkaConnect
from prowler.providers.common.provider import Provider

kafkaconnect_client = KafkaConnect(Provider.get_global_provider())
