from prowler.providers.common.provider import Provider
from prowler.providers.vercel.services.domain.domain_service import Domain

domain_client = Domain(Provider.get_global_provider())
