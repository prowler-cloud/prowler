from prowler.providers.common.provider import Provider
from prowler.providers.vercel.services.security.security_service import Security

security_client = Security(Provider.get_global_provider())
