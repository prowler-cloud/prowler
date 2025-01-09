from prowler.providers.aws.services.mq.mq_service import MQ
from prowler.providers.common.provider import Provider

mq_client = MQ(Provider.get_global_provider())
