from prowler.providers.cloudflare.services.r2.r2_service import R2
from prowler.providers.common.provider import Provider

r2_client = R2(Provider.get_global_provider())
