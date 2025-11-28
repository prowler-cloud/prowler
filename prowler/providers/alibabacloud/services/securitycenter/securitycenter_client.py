from prowler.providers.alibabacloud.services.securitycenter.securitycenter_service import (
    SecurityCenter,
)
from prowler.providers.common.provider import Provider

securitycenter_client = SecurityCenter(Provider.get_global_provider())
