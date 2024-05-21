from prowler.providers.aws.services.sns.sns_service import SNS
from prowler.providers.common.provider import Provider

sns_client = SNS(Provider.get_global_provider())
