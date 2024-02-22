from prowler.providers.aws.services.ssm.ssm_service import SSM
from prowler.providers.common.common import get_global_provider

ssm_client = SSM(get_global_provider())
