from prowler.providers.aws.services.datasync.datasync_service import DataSync
from prowler.providers.common.provider import Provider

datasync_client = DataSync(Provider.get_global_provider())
