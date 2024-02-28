from prowler.providers.aws.services.sqs.sqs_service import SQS
from prowler.providers.common.common import get_global_provider

sqs_client = SQS(get_global_provider())
