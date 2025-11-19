"""Alibaba Cloud SLS Client Singleton"""

from prowler.providers.alibabacloud.services.sls.sls_service import SLS
from prowler.providers.common.provider import Provider

sls_client = SLS(Provider.get_global_provider())
