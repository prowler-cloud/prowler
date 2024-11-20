from prowler.providers.common.provider import Provider
from prowler.providers.microsoft365.services.users.users_service import Users

users_client = Users(Provider.get_global_provider())
