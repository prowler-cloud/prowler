from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.directoryservice.directoryservice_service import (
    DirectoryService,
)

directoryservice_client = DirectoryService(current_audit_info)
