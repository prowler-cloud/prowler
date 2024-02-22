from prowler.providers.aws.services.efs.efs_service import EFS
from prowler.providers.common.common import get_global_provider

efs_client = EFS(get_global_provider())
