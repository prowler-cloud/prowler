from prowler.providers.alibabacloud.services.oss.oss_service import OSS
from prowler.providers.common.provider import Provider

oss_client = OSS(Provider.get_global_provider())
