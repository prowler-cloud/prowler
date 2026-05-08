from prowler.providers.common.provider import Provider
from prowler.providers.lovable.services.published.published_service import Published

published_client = Published(Provider.get_global_provider())
