from prowler.providers.aws.services.firehose.firehose_service import Firehose
from prowler.providers.common.provider import Provider

firehose_client = Firehose(Provider.get_global_provider())
