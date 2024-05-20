from prowler.providers.aws.services.sqs.sqs_service import SQS
from prowler.providers.common.provider import Provider

sqs_client = SQS(Provider.get_global_provider())
