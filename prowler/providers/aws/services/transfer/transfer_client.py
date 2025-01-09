from prowler.providers.aws.services.transfer.transfer_service import Transfer
from prowler.providers.common.provider import Provider

transfer_client = Transfer(Provider.get_global_provider())
