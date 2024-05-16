from prowler.providers.aws.services.kafka.kafka_service import Kafka
from prowler.providers.common.common import get_global_provider

kafka_client = Kafka(get_global_provider())
