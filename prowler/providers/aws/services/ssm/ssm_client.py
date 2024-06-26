from prowler.providers.aws.services.ssm.ssm_service import SSM
from prowler.providers.common.provider import Provider

ssm_client = SSM(Provider.get_global_provider())
