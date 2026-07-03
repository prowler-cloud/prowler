from prowler.providers.aws.services.batch.batch_service import Batch
from prowler.providers.common.provider import Provider

batch_client = Batch(Provider.get_global_provider())
