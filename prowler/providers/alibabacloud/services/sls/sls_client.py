from prowler.providers.alibabacloud.services.sls.sls_service import Sls
from prowler.providers.common.provider import Provider

sls_client = Sls(Provider.get_global_provider())
