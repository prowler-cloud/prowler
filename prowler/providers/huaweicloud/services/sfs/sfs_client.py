from prowler.providers.huaweicloud.services.sfs.sfs_service import SFS
from prowler.providers.common.provider import Provider

sfs_client = SFS(Provider.get_global_provider())
