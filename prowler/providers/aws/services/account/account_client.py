from prowler.providers.aws.services.account.account_service import Account
from prowler.providers.common.common import get_global_provider

account_client = Account(get_global_provider())
