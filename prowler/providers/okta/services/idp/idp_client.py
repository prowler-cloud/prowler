from prowler.providers.common.provider import Provider
from prowler.providers.okta.services.idp.idp_service import Idp

idp_client = Idp(Provider.get_global_provider())
