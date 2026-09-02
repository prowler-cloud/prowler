from prowler.providers.common.provider import Provider
from prowler.providers.huaweicloud.services.sfs.sfs_service import SFS

sfs_client = SFS(Provider.get_global_provider())
