from prowler.providers.aws.services.efs.efs_service import EFS
from prowler.providers.common.provider import Provider

efs_client = EFS(Provider.get_global_provider())
