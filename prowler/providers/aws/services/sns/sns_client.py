from prowler.providers.aws.services.sns.sns_service import SNS
from prowler.providers.common.common import get_global_provider

sns_client = SNS(get_global_provider())
