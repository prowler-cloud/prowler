from prowler.providers.aws.services.kinesis.kinesis_service import Kinesis
from prowler.providers.common.provider import Provider

kinesis_client = Kinesis(Provider.get_global_provider())
