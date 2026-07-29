from prowler.providers.common.provider import Provider
from prowler.providers.okta.services.user.user_service import User

user_client = User(Provider.get_global_provider())
