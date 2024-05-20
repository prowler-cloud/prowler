from prowler.providers.aws.services.kafka.kafka_service import Kafka
from prowler.providers.common.provider import Provider

kafka_client = Kafka(Provider.get_global_provider())
