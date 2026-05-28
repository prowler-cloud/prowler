from prowler.providers.common.provider import Provider
from prowler.providers.linode.services.account.account_service import AccountService

account_client = AccountService(Provider.get_global_provider())
