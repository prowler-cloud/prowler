from prowler.providers.aws.services.directoryservice.directoryservice_service import (
    DirectoryService,
)
from prowler.providers.common.common import get_global_provider

directoryservice_client = DirectoryService(get_global_provider())
