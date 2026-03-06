from prowler.providers.alibabacloud.services.ram.ram_service import RAM
from prowler.providers.common.provider import Provider

ram_client = RAM(Provider.get_global_provider())
