from prowler.providers.aws.services.account.account_service import Account
from prowler.providers.common.provider import Provider

account_client = Account(Provider.get_global_provider())
