from prowler.providers.alibabacloud.services.cs.cs_service import CS
from prowler.providers.common.provider import Provider

cs_client = CS(Provider.get_global_provider())
