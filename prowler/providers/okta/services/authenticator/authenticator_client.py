from prowler.providers.common.provider import Provider
from prowler.providers.okta.services.authenticator.authenticator_service import (
    Authenticator,
)

authenticator_client = Authenticator(Provider.get_global_provider())
