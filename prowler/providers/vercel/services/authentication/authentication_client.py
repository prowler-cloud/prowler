from prowler.providers.common.provider import Provider
from prowler.providers.vercel.services.authentication.authentication_service import (
    Authentication,
)

authentication_client = Authentication(Provider.get_global_provider())
