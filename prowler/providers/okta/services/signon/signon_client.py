from prowler.providers.common.provider import Provider
from prowler.providers.okta.services.signon.signon_service import Signon

signon_client = Signon(Provider.get_global_provider())
